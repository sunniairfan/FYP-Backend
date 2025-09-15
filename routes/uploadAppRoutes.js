const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const mobsf = require("../utils/mobsf");
const { analyzeFileWithVirusTotal } = require("../utils/virusTotal");
const router = express.Router();

// Middleware to require authentication for web routes
const requireWebAuth = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    return next();
  } else {
    return res.redirect("/login");
  }
};

// Helper function to generate dynamic index name based on current date
function getDynamicIndexName() {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, "0");
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const year = today.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
}

// Helper function to generate index name for specific date
function getIndexNameForDate(dateString) {
  const date = new Date(dateString);
  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = date.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
}

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "../Uploads/apks");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for APK file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);  // Save files to uploadsDir
  },
  filename: function (req, file, cb) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const uniqueName = `temp_${timestamp}_${file.originalname}`;
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 500 * 1024 * 1024, // 500MB limit
  },
  // Allow only APK files
  fileFilter: function (req, file, cb) {
    if (
      file.mimetype === "application/vnd.android.package-archive" ||
      file.originalname.toLowerCase().endsWith(".apk")
    ) {
      cb(null, true);
    } else {
      console.error("Invalid file type:", file.mimetype);
      cb(new Error("Only APK files are allowed"), false);
    }
  },
});

// Import controller functions from appController.js
const {
  receiveAppData,
  uploadApp,
  getAppDetails,
  downloadApp,
  deleteApp,
} = require("../controllers/appController");

// Helper function to analyze app with MobSF
async function analyzeApp(sha256, esClient) {
  console.log(`[MobSF Analysis] Starting analysis for SHA256: ${sha256}`);
  
  try {
    const dynamicIndex = getDynamicIndexName();
    console.log(`[MobSF Analysis] Using index: ${dynamicIndex}`);
    
    const searchRes = await esClient.search({
      index: dynamicIndex,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      throw new Error("App not found in database");
    }

    const docId = searchRes.hits.hits[0]._id;
    const appData = searchRes.hits.hits[0]._source;
    const filePath = appData.apkFilePath;

    console.log(`[MobSF Analysis] Found app: ${appData.packageName || "Unknown"}`);
    console.log(`[MobSF Analysis] APK file path: ${filePath}`);

    if (!filePath || !fs.existsSync(filePath)) {
      throw new Error(`APK file not found at path: ${filePath}`);
    }

    const fileStats = fs.statSync(filePath);
    console.log(`[MobSF Analysis] File size: ${(fileStats.size / 1024 / 1024).toFixed(2)} MB`);

    const isConnected = await mobsf.checkConnection();
    if (!isConnected) {
      throw new Error("Cannot connect to MobSF service");
    }

    console.log(`[MobSF Analysis] Uploading to MobSF...`);
    const uploadRes = await mobsf.uploadToMobSF(filePath);
    const md5Hash = uploadRes.hash;
    
    console.log(`[MobSF Analysis] Upload successful, MD5 hash: ${md5Hash}`);

    console.log(`[MobSF Analysis] Starting scan...`);
    await mobsf.scanWithMobSF(md5Hash);
    
    console.log(`[MobSF Analysis] Scan completed, fetching report...`);
    let report;
    let retryCount = 0;
    const maxRetries = 3;
    
    while (retryCount < maxRetries) {
      try {
        report = await mobsf.getJsonReport(md5Hash);
        break;
      } catch (reportError) {
        retryCount++;
        console.log(`[MobSF Analysis] Report fetch attempt ${retryCount} failed, retrying...`);
        if (retryCount >= maxRetries) {
          throw new Error(`Failed to get report after ${maxRetries} attempts: ${reportError.message}`);
        }
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
    console.log(`[MobSF Analysis] Report fetched successfully`);

    const dangerousPermissions = [];
    if (report.permissions && typeof report.permissions === "object") {
      for (const [permName, permData] of Object.entries(report.permissions)) {
        if (permData && permData.status === "dangerous") {
          dangerousPermissions.push(permName);
        }
      }
    }

    let highRiskFindings = 0;
    if (report.code_analysis && typeof report.code_analysis === "object") {
      highRiskFindings = Object.entries(report.code_analysis).filter(
        ([_, finding]) => finding && finding.metadata && finding.metadata.severity === "high"
      ).length;
    }

    const securityScore = report.security_score || 0;

    const mobsfAnalysis = {
      security_score: securityScore,
      dangerous_permissions: dangerousPermissions,
      high_risk_findings: highRiskFindings,
      scan_type: uploadRes.scan_type || "unknown",
      file_name: uploadRes.file_name || path.basename(filePath),
    };

    let status = "unknown";
    if (securityScore >= 70) {
      status = "safe";
    } else if (securityScore < 40) {
      status = "malicious";
    } else {
      status = "suspicious";
    }

    console.log(`[MobSF Analysis] Analysis complete:`, {
      security_score: securityScore,
      status: status,
      dangerous_permissions: dangerousPermissions.length,
      high_risk_findings: highRiskFindings,
    });

    await esClient.update({
      index: dynamicIndex,
      id: docId,
      body: {
        doc: {
          mobsfAnalysis,
          lastMobsfAnalysis: new Date().toISOString(),
          mobsfHash: md5Hash,
          status,
          mobsfScanType: uploadRes.scan_type,
        },
      },
    });

    console.log(`[MobSF Analysis] Database updated successfully for ${appData.packageName}`);

    return {
      success: true,
      analysis: mobsfAnalysis,
      app: { ...appData, status },
      mobsfHash: md5Hash,
    };
  } catch (error) {
    console.error(`[MobSF Analysis] Error analyzing ${sha256}:`, {
      message: error.message,
      stack: error.stack,
      response: error.response?.data,
    });

    try {
      const dynamicIndex = getDynamicIndexName();
      const searchRes = await esClient.search({
        index: dynamicIndex,
        size: 1,
        query: { term: { sha256: { value: sha256 } } },
      });

      if (searchRes.hits.hits.length > 0) {
        const docId = searchRes.hits.hits[0]._id;
        await esClient.update({
          index: dynamicIndex,
          id: docId,
          body: {
            doc: {
              status: "analysis_failed",
              lastMobsfAnalysis: new Date().toISOString(),
              mobsfError: error.message,
            },
          },
        });
      }
    } catch (updateError) {
      console.error(`[MobSF Analysis] Failed to update error status:`, updateError.message);
    }
    
    throw error;
  }
}

// Helper function to analyze app with VirusTotal
async function analyzeAppWithVirusTotal(sha256, esClient) {
  console.log(`[VirusTotal Analysis] Starting analysis for SHA256: ${sha256}`);
  
  try {
    const dynamicIndex = getDynamicIndexName();
    const searchRes = await esClient.search({
      index: dynamicIndex,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      throw new Error("App not found in database");
    }

    const docId = searchRes.hits.hits[0]._id;
    const appData = searchRes.hits.hits[0]._source;
    const filePath = appData.apkFilePath;

    if (!filePath || !fs.existsSync(filePath)) {
      throw new Error(`APK file not found at path: ${filePath}`);
    }

    const fileStats = fs.statSync(filePath);
    console.log(`[VirusTotal Analysis] File size: ${(fileStats.size / 1024 / 1024).toFixed(2)} MB`);

    const vtResult = await analyzeFileWithVirusTotal(filePath);
    
    console.log(`[VirusTotal Analysis] Analysis complete:`, {
      status: vtResult.status,
      detectionRatio: vtResult.detectionRatio,
      maliciousCount: vtResult.maliciousCount,
      suspiciousCount: vtResult.suspiciousCount,
    });

    await esClient.update({
      index: dynamicIndex,
      id: docId,
      body: {
        doc: {
          virusTotalAnalysis: {
            status: vtResult.status,
            detectionRatio: vtResult.detectionRatio,
            totalEngines: vtResult.totalEngines,
            detectedEngines: vtResult.detectedEngines,
            maliciousCount: vtResult.maliciousCount,
            suspiciousCount: vtResult.suspiciousCount,
            scanTime: vtResult.scanTime,
            analysisId: vtResult.analysisId,
          },
          lastVirusTotalAnalysis: new Date().toISOString(),
        },
      },
    });

    console.log(`[VirusTotal Analysis] Database updated successfully for ${appData.packageName}`);

    return {
      success: true,
      analysis: vtResult,
      app: { ...appData, status: vtResult.status },
    };
  } catch (error) {
    console.error(`[VirusTotal Analysis] Error analyzing ${sha256}:`, error.message);
    
    try {
      const dynamicIndex = getDynamicIndexName();
      const searchRes = await esClient.search({
        index: dynamicIndex,
        size: 1,
        query: { term: { sha256: { value: sha256 } } },
      });

      if (searchRes.hits.hits.length > 0) {
        const docId = searchRes.hits.hits[0]._id;
        await esClient.update({
          index: dynamicIndex,
          id: docId,
          body: {
            doc: {
              virusTotalError: error.message,
              lastVirusTotalAnalysis: new Date().toISOString(),
            },
          },
        });
      }
    } catch (updateError) {
      console.error(`[VirusTotal Analysis] Failed to update error status:`, updateError.message);
    }
    
    throw error;
  }
}

// Route: POST /upload (Mobile app upload, no auth required)
router.post(
  "/upload",
  (req, res, next) => {
    console.log(">>> Files received:", req.files);
    console.log(">>> Body:", req.body);
    upload.fields([
      { name: "apk", maxCount: 1 },
      { name: "metadata", maxCount: 1 },
    ])(req, res, (err) => {
      if (err) {
        console.error("Multer error:", err.message);
        return res.status(400).json({ error: "File upload failed", details: err.message });
      }
      next();
    });
  },
  uploadApp
);

// Routes for APK upload and management
router.post(
  "/api/app/upload",
  upload.fields([
    { name: "apk", maxCount: 1 },
    { name: "metadata", maxCount: 1 },
  ]),
  uploadApp
);

// Route: POST /analyze/:sha256 (Trigger MobSF analysis, no auth required)
router.post("/analyze/:sha256", async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;
  try {
    const result = await analyzeApp(sha256, esClient);
    res.json(result);
  } catch (err) {
    console.error("MobSF Analysis Error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Route: POST /analyze-vt/:sha256 (Trigger VirusTotal analysis, no auth required)
router.post("/analyze-vt/:sha256", async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;
  try {
    const result = await analyzeAppWithVirusTotal(sha256, esClient);
    res.json(result);
  } catch (err) {
    console.error("VirusTotal Analysis Error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /report/:sha256 - Get MobSF PDF report - NO AUTH REQUIRED
router.get("/report/:sha256", async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;
  
  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);
    
    console.log(`[PDF Report] Looking for app ${sha256} in index: ${indexName}`);
    
    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      console.error(`[PDF Report] App not found: ${sha256}`);
      return res.status(404).send("App not found");
    }

    const appData = searchRes.hits.hits[0]._source;
    const md5Hash = appData.mobsfHash;

    if (!md5Hash) {
      console.error(`[PDF Report] No MobSF hash available for app: ${sha256}`);
      return res.status(400).send("No MobSF analysis available for this app");
    }

    console.log(`[PDF Report] Fetching PDF for MD5: ${md5Hash}`);
    
    const pdfStream = await mobsf.getPdfReport(md5Hash);
    
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="mobsf_report_${sha256}.pdf"`);
    
    pdfStream.pipe(res);
    
    pdfStream.on("error", (error) => {
      console.error(`[PDF Report] Stream error:`, error);
      if (!res.headersSent) {
        res.status(500).send("Error generating PDF report");
      }
    });
  } catch (err) {
    console.error("[PDF Report] Failed to get MobSF report:", err.message);
    if (!res.headersSent) {
      res.status(500).send("Failed to get MobSF report");
    }
  }
});

// GET /mobsf/status - Check MobSF connection status - NO AUTH REQUIRED
router.get("/mobsf/status", async (req, res) => {
  const connected = await mobsf.checkConnection();
  res.json({ mobsf_connected: connected });
});

// GET /apps - View uploaded apps (HTML page with calendar) - REQUIRES WEB AUTH
router.get("/apps", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);
    const isToday = selectedDate === new Date().toISOString().split("T")[0];
    
    console.log(`[Apps Route] Using index: ${indexName} for date: ${selectedDate}`);
    
    let apps = [];
    try {
      const result = await esClient.search({
        index: indexName,
        size: 100,
        query: { term: { uploadedByUser: true } },
        sort: [{ timestamp: { order: "desc" } }],
      });
      
      apps = result.hits.hits.map((hit) => ({
        ...hit._source,
        id: hit._id,
      }));
    } catch (indexError) {
      console.log(`[Apps Route] Index ${indexName} not found or no data`);
    }

    let html = `
      <html>
      <head>
        <title>Uploaded Apps - Android Malware Detector</title>
        <style>
          body {
            background-color: #0d1b2a;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          h1 {
            font-size: 2.5rem;
            color: #ffffff;
            margin-bottom: 10px;
          }
          .subtitle {
            color: #778da9;
            font-size: 1.1rem;
          }
          .date-selector {
            background: linear-gradient(135deg, #1b263b, #415a77);
            padding: 15px 25px;
            border-radius: 10px;
            margin: 15px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
          }
          .date-selector label {
            color: #90e0ef;
            font-weight: bold;
          }
          .date-selector input[type="date"] {
            background: #0d1b2a;
            border: 2px solid #415a77;
            border-radius: 6px;
            padding: 8px 12px;
            color: white;
            font-size: 1rem;
          }
          .date-selector button {
            background: linear-gradient(135deg, #0077b6, #0096c7);
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            color: white;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
          }
          .date-selector button:hover {
            background: linear-gradient(135deg, #005577, #007bb6);
            transform: translateY(-1px);
          }
          .search-section {
            background: linear-gradient(135deg, #1b263b, #415a77);
            padding: 15px 25px;
            border-radius: 10px;
            margin: 15px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
          }
          .search-section label {
            color: #90e0ef;
            font-weight: bold;
          }
          .search-section input[type="text"] {
            background: #0d1b2a;
            border: 2px solid #415a77;
            border-radius: 6px;
            padding: 8px 12px;
            color: white;
            font-size: 1rem;
            width: 300px;
          }
          .search-section select {
            background: #0d1b2a;
            border: 2px solid #415a77;
            border-radius: 6px;
            padding: 8px 12px;
            color: white;
            font-size: 1rem;
          }
          .search-section button {
            background: linear-gradient(135deg, #0077b6, #0096c7);
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            color: white;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
          }
          .search-section button:hover {
            background: linear-gradient(135deg, #005577, #007bb6);
            transform: translateY(-1px);
          }
          .current-index {
            background: linear-gradient(135deg, #1b263b, #415a77);
            padding: 10px 20px;
            border-radius: 8px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            color: #90e0ef;
          }
          .stats {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin: 20px 0;
          }
          .stat-card {
            background: linear-gradient(135deg, #1b263b, #415a77);
            padding: 15px 25px;
            border-radius: 10px;
            text-align: center;
          }
          .stat-number {
            font-size: 1.8rem;
            font-weight: bold;
            color: #90e0ef;
          }
          .stat-label {
            font-size: 0.9rem;
            color: #cad2c5;
          }
          table {
            width: 100%;
            border-spacing: 0;
            border-collapse: separate;
            border-radius: 12px;
            overflow: hidden;
            background-color: #1b263b;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
          }
          thead {
            background: linear-gradient(135deg, #415a77, #778da9);
          }
          th {
            padding: 18px 15px;
            text-align: left;
            font-size: 1rem;
            font-weight: bold;
            color: white;
          }
          th:nth-child(1) { width: 20%; }
          th:nth-child(2) { width: 20%; }
          th:nth-child(3) { width: 20%; }
          th:nth-child(4) { width: 20%; }
          th:nth-child(5) { width: 20%; }
          td {
            padding: 15px;
            border-bottom: 1px solid #415a77;
            vertical-align: middle;
          }
          tr:hover {
            background-color: #273b54;
            transition: background-color 0.3s ease;
          }
          tr:last-child td {
            border-bottom: none;
          }
          .status {
            font-weight: bold;
            padding: 8px 12px;
            border-radius: 6px;
            display: inline-block;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }
          .status.unknown {
            background-color: #ffb703;
            color: #1b263b;
          }
          .status.safe {
            background-color: #52b788;
            color: white;
          }
          .status.malicious {
            background-color: #e63946;
            color: white;
          }
          .status.suspicious {
            background-color: #f77f00;
            color: white;
          }
          .status.sandbox_submitted {
            background-color: #f77f00;
            color: white;
          }
          .actions {
            min-width: 200px;
          }
          button {
            padding: 8px 14px;
            border: none;
            border-radius: 6px;
            color: white;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            margin: 2px;
            font-size: 0.85rem;
          }
          .btn-mobsf {
            background: linear-gradient(135deg, #6f42c1, #8e3af5);
          }
          .btn-mobsf:hover {
            background: linear-gradient(135deg, #5a2a9f, #6f42c1);
            transform: translateY(-1px);
          }
          .btn-vt {
            background: linear-gradient(135deg, #00b4d8, #48cae4);
          }
          .btn-vt:hover {
            background: linear-gradient(135deg, #0096c7, #00b4d8);
            transform: translateY(-1px);
          }
          .btn-report {
            background: linear-gradient(135deg, #dc3545, #e74c3c);
          }
          .btn-report:hover {
            background: linear-gradient(135deg, #c82333, #dc3545);
            transform: translateY(-1px);
          }
          .btn-sandbox {
            background: linear-gradient(135deg, #0077b6, #0096c7);
          }
          .btn-sandbox:hover {
            background: linear-gradient(135deg, #005577, #007bb6);
            transform: translateY(-1px);
          }
          .btn-download {
            background: linear-gradient(135deg, #52b788, #74c69d);
          }
          .btn-download:hover {
            background: linear-gradient(135deg, #40916c, #52b788);
            transform: translateY(-1px);
          }
          .btn-delete {
            background: linear-gradient(135deg, #e63946, #f77f00);
          }
          .btn-delete:hover {
            background: linear-gradient(135deg, #d00000, #e63946);
            transform: translateY(-1px);
          }
          .btn-disabled {
            background: #6c757d !important;
            cursor: not-allowed !important;
            opacity: 0.6;
          }
          .btn-disabled:hover {
            transform: none !important;
          }
          form {
            margin: 0;
            display: inline-block;
          }
          .file-info {
            font-size: 0.85rem;
            color: #cad2c5;
            line-height: 1.4;
          }
          .app-name {
            font-weight: 600;
            color: #90e0ef;
          }
          .package-name {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            color: #778da9;
          }
          .no-apps {
            text-align: center;
            padding: 50px;
            color: #778da9;
            font-size: 1.2rem;
          }
          .permissions {
            font-size: 0.8rem;
            color: #ffb703;
          }
          .mobsf-info, .vt-info {
            font-size: 0.8rem;
            color: #90e0ef;
            margin-top: 5px;
          }
          .security-score {
            font-weight: bold;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
          }
          .score-high {
            background-color: #52b788;
            color: white;
          }
          .score-medium {
            background-color: #ffb703;
            color: #1b263b;
          }
          .score-low {
            background-color: #e63946;
            color: white;
          }
          .mobsf-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: bold;
          }
          .mobsf-connected {
            background-color: #52b788;
            color: white;
          }
          .mobsf-disconnected {
            background-color: #e63946;
            color: white;
          }
        </style>
      </head>
      <body>
        <div id="mobsf-status" class="mobsf-status">Checking MobSF...</div>
        
        <div class="header">
          <h1>📱 Uploaded Apps</h1>
          <div class="subtitle">Android Malware Detection System with MobSF & VirusTotal Integration</div>
          
          <div class="date-selector">
            <label for="date-picker">Select Date:</label>
            <input type="date" id="date-picker" value="${selectedDate}" />
            <button onclick="loadAppsForDate()">Load Apps</button>
            ${!isToday ? `<button onclick="loadToday()">Today</button>` : ""}
          </div>
          
          <div class="search-section">
            <label for="search-input">Search Apps:</label>
            <input type="text" id="search-input" placeholder="e.g., rg cipher vpn" onkeyup="performSearch()">
            <button onclick="performSearch()">Search</button>
          </div>
          
          <div class="current-index">Using Index: ${indexName}</div>
        </div>
        
        <div class="stats">
          <div class="stat-card">
            <div class="stat-number">${apps.length}</div>
            <div class="stat-label">Total Apps</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${apps.filter((app) => app.status === "malicious").length}</div>
            <div class="stat-label">Malicious</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${apps.filter((app) => app.status === "safe").length}</div>
            <div class="stat-label">Safe</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${apps.filter((app) => app.status === "suspicious").length}</div>
            <div class="stat-label">Suspicious</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${apps.filter((app) => app.status === "unknown").length}</div>
            <div class="stat-label">Unknown</div>
          </div>
        </div>
    `;

    if (apps.length === 0) {
      html += `
        <div class="no-apps">
          <p>No apps found for ${selectedDate}.</p>
          <p>${isToday ? "Upload apps using the Android application to see them here." : "Try selecting a different date or check today's uploads."}</p>
        </div>
      `;
    } else {
      html += `
        <table>
          <thead>
            <tr>
              <th>App Details</th>
              <th>Package Info</th>
              <th>File Information</th>
              <th>Status & Analysis</th>
              <th class="actions">Actions</th>
            </tr>
          </thead>
          <tbody>
      `;

      apps.forEach((app) => {
        const fileInfo = app.apkFileName ? `${app.apkFileName}` : "No file uploaded";
        const uploadDate = new Date(app.timestamp).toLocaleDateString();
        const permissionCount = app.permissions ? app.permissions.length : 0;
        const hasMobsfAnalysis = app.mobsfAnalysis && app.mobsfAnalysis.security_score !== undefined;
        const hasVirusTotalAnalysis = app.virusTotalAnalysis && app.virusTotalAnalysis.detectionRatio;
        const hasApkFile = app.apkFilePath && app.apkFileName;

        let scoreClass = "score-medium";
        if (hasMobsfAnalysis) {
          if (app.mobsfAnalysis.security_score >= 70) scoreClass = "score-high";
          else if (app.mobsfAnalysis.security_score < 40) scoreClass = "score-low";
        }
        
        html += `
          <tr>
            <td>
              <div class="app-name">${app.appName || "Unknown App"}</div>
              <div class="file-info">Uploaded: ${uploadDate}</div>
              ${app.source ? `<div class="file-info">Source: ${app.source}</div>` : ""}
              ${app.lastMobsfAnalysis ? `<div class="file-info">MobSF: ${new Date(app.lastMobsfAnalysis).toLocaleDateString()}</div>` : ""}
              ${app.lastVirusTotalAnalysis ? `<div class="file-info">VirusTotal: ${new Date(app.lastVirusTotalAnalysis).toLocaleDateString()}</div>` : ""}
            </td>
            <td>
              <div class="package-name">${app.packageName}</div>
              ${permissionCount > 0 ? `<div class="permissions">${permissionCount} permissions</div>` : ""}
              ${hasMobsfAnalysis && app.mobsfAnalysis.dangerous_permissions ? 
                `<div class="permissions">⚠️ ${app.mobsfAnalysis.dangerous_permissions.length} dangerous perms</div>` : ""}
            </td>
            <td>
              <div class="file-info">${fileInfo}</div>
              <div class="file-info">Size: ${app.sizeMB?.toFixed(2) || 0} MB</div>
              ${app.sha256 ? `<div class="file-info" title="${app.sha256}">SHA-256: ${app.sha256.substring(0, 16)}...</div>` : ""}
            </td>
            <td>
              <span class="status ${app.status || "unknown"}">
                ${app.status || "unknown"}
              </span>
              ${hasMobsfAnalysis ? `
                <div class="mobsf-info">
                  <span class="security-score ${scoreClass}">MobSF Score: ${app.mobsfAnalysis.security_score}/100</span>
                </div>
                <div class="mobsf-info">
                  Risk: ${app.mobsfAnalysis.malware_probability || "unknown"}
                  ${app.mobsfAnalysis.high_risk_findings > 0 ? `| 🔴 ${app.mobsfAnalysis.high_risk_findings} high risks` : ""}
                </div>
              ` : ""}
              ${hasVirusTotalAnalysis ? `
                <div class="vt-info">
                  <span class="security-score ${app.virusTotalAnalysis.status === 'safe' ? 'score-high' : app.virusTotalAnalysis.status === 'malicious' ? 'score-low' : 'score-medium'}">
                    VT Detection: ${app.virusTotalAnalysis.detectionRatio}
                  </span>
                </div>
                <div class="vt-info">
                  Malicious: ${app.virusTotalAnalysis.maliciousCount} | Suspicious: ${app.virusTotalAnalysis.suspiciousCount}
                </div>
              ` : ""}
            </td>
            <td class="actions">
              <div class="btn-group">
                <button class="btn-mobsf" onclick="runMobsfAnalysis('${app.sha256}', '${app.packageName}')" title="Run MobSF Static Analysis">
                  ${hasMobsfAnalysis ? "Re-analyze" : "Analyze"} MobSF
                </button>
                ${hasMobsfAnalysis ? `
                  <button class="btn-report" onclick="downloadMobsfReport('${app.sha256}')" title="Download MobSF PDF Report">
                    PDF Report
                  </button>
                ` : ""}
                <button class="btn-sandbox" onclick="uploadToSandbox('${app.sha256}', '${app.packageName}')">
                  Upload to Sandbox
                </button>
                <button class="btn-vt" onclick="runVirusTotalAnalysis('${app.sha256}', '${app.packageName}')" title="Run VirusTotal Analysis">
                  ${hasVirusTotalAnalysis ? "Re-analyze" : "Analyze"} VirusTotal
                </button>
                ${app.apkFileName ? `
                  <button class="btn-download" onclick="downloadFile('${app.apkFileName}')">
                    Download APK
                  </button>
                ` : ""}
                <button class="btn-delete" onclick="deleteApp('${app.sha256}', '${app.packageName}')">
                  Delete
                </button>
              </div>
            </td>
          </tr>
        `;
      });

      html += `
            </tbody>
          </table>
      `;
    }

    html += `
        <script>
          fetch(window.location.pathname.replace('/apps', '/mobsf/status'))
            .then(response => response.json())
            .then(data => {
              const statusDiv = document.getElementById('mobsf-status');
              if (data.mobsf_connected) {
                statusDiv.textContent = 'MobSF: Connected ✓';
                statusDiv.className = 'mobsf-status mobsf-connected';
              } else {
                statusDiv.textContent = 'MobSF: Disconnected ✗';
                statusDiv.className = 'mobsf-status mobsf-disconnected';
              }
            })
            .catch(error => {
              const statusDiv = document.getElementById('mobsf-status');
              statusDiv.textContent = 'MobSF: Error';
              statusDiv.className = 'mobsf-status mobsf-disconnected';
            });

          function getBasePath() {
            return window.location.pathname.replace('/apps', '');
          }

          function loadAppsForDate() {
            const selectedDate = document.getElementById('date-picker').value;
            if (selectedDate) {
              window.location.href = window.location.pathname + '?date=' + selectedDate;
            }
          }

          function loadToday() {
            window.location.href = window.location.pathname;
          }

          function downloadFile(fileName) {
            window.location.href = getBasePath() + '/download/' + encodeURIComponent(fileName);
          }
          
          function performSearch() {
            const query = document.getElementById('search-input').value.toLowerCase();
            const rows = document.querySelectorAll('table tbody tr');
            rows.forEach(row => {
              const appName = row.querySelector('.app-name').textContent.toLowerCase();
              const packageName = row.querySelector('.package-name').textContent.toLowerCase();
              const fileName = row.querySelector('td:nth-child(3) .file-info').textContent.toLowerCase();
              if (appName.includes(query) || packageName.includes(query) || fileName.includes(query)) {
                row.style.display = '';
              } else {
                row.style.display = 'none';
              }
            });
          }
          
          function runMobsfAnalysis(sha256, packageName) {
            if (confirm('Run MobSF static analysis for "' + packageName + '"? This may take several minutes.')) {
              event.target.textContent = 'Analyzing...';
              event.target.disabled = true;
              event.target.className = 'btn-mobsf btn-disabled';
              
              fetch(getBasePath() + '/analyze/' + sha256, { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                  if (data.error) {
                    alert('MobSF Analysis Error: ' + data.error);
                  } else {
                    alert('MobSF analysis completed successfully!\\nSecurity Score: ' + 
                          (data.analysis ? data.analysis.security_score + '/100' : 'N/A') + 
                          '\\nStatus: ' + data.app.status);
                    location.reload();
                  }
                })
                .catch(error => {
                  alert('Error: ' + error.message);
                })
                .finally(() => {
                  event.target.textContent = 'Analyze MobSF';
                  event.target.disabled = false;
                  event.target.className = 'btn-mobsf';
                });
            }
          }
          
          function runVirusTotalAnalysis(sha256, packageName) {
            if (confirm('Run VirusTotal analysis for "' + packageName + '"? This may take a few minutes.')) {
              event.target.textContent = 'Analyzing...';
              event.target.disabled = true;
              event.target.className = 'btn-vt btn-disabled';
              
              fetch(getBasePath() + '/analyze-vt/' + sha256, { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                  if (data.error) {
                    alert('VirusTotal Analysis Error: ' + data.error);
                  } else {
                    alert('VirusTotal analysis completed successfully!\\nDetection Ratio: ' + 
                          (data.analysis ? data.analysis.detectionRatio : 'N/A') + 
                          '\\nStatus: ' + data.app.status);
                    location.reload();
                  }
                })
                .catch(error => {
                  alert('Error: ' + error.message);
                })
                .finally(() => {
                  event.target.textContent = 'Analyze VirusTotal';
                  event.target.disabled = false;
                  event.target.className = 'btn-vt';
                });
            }
          }
          
          function downloadMobsfReport(sha256) {
            const selectedDate = document.getElementById('date-picker').value;
            const url = getBasePath() + '/report/' + sha256 + (selectedDate ? '?date=' + selectedDate : '');
            window.location.href = url;
          }
          
          function uploadToSandbox(sha256, packageName) {
            if (confirm('Upload "' + packageName + '" to sandbox for dynamic analysis?')) {
              fetch(getBasePath() + '/apps/' + sha256 + '/upload-sandbox', { method: 'POST' })
                .then(response => {
                  if (response.ok) {
                    alert('App uploaded to sandbox successfully!');
                    location.reload();
                  } else {
                    alert('Error uploading to sandbox');
                  }
                })
                .catch(error => {
                  alert('Error: ' + error.message);
                });
            }
          }
          
          function deleteApp(sha256, packageName) {
            if (confirm('Are you sure you want to delete "' + packageName + '"? This will also delete the APK file and analysis results.')) {
              fetch(getBasePath() + '/delete/' + sha256, { method: 'DELETE' })
                .then(response => response.json())
                .then(data => {
                  if (data.error) {
                    alert('Error: ' + data.error);
                  } else {
                    alert('App deleted successfully');
                    location.reload();
                  }
                })
                .catch(error => {
                  alert('Error: ' + error.message);
                });
            }
          }
        </script>
      </body>
      </html>
    `;

    res.send(html);
  } catch (err) {
    console.error("Failed to fetch apps for upload app page:", err.message);
    res.status(500).send(`
      <html>
      <body style="background: #0d1b2a; color: white; font-family: Arial; text-align: center; padding: 50px;">
        <h1>Error Loading Apps</h1>
        <p>${err.message}</p>
      </body>
      </html>
    `);
  }
});

// POST /apps/:sha256/upload-sandbox - Upload to sandbox - REQUIRES WEB AUTH
router.post("/apps/:sha256/upload-sandbox", requireWebAuth, async (req, res) => {
  const sha256 = req.params.sha256;
  const esClient = req.app.get("esClient");

  try {
    const dynamicIndex = getDynamicIndexName();
    const searchRes = await esClient.search({
      index: dynamicIndex,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      console.error(`App not found for SHA256: ${sha256}`);
      return res.status(404).send("App not found");
    }

    const docId = searchRes.hits.hits[0]._id;
    const appData = searchRes.hits.hits[0]._source;

    console.log(`📤 Uploading to sandbox: ${appData.apkFilePath}`);

    await esClient.update({
      index: dynamicIndex,
      id: docId,
      body: {
        doc: {
          status: "sandbox_submitted",
          uploadedByUser: true,
          timestamp: new Date(),
        },
      },
    });

    console.log(`✅ Marked app ${sha256} as sandbox_submitted`);
    res.redirect(req.originalUrl.replace(`/apps/${sha256}/upload-sandbox`, "/apps"));
  } catch (err) {
    console.error(`Failed to submit app ${sha256} to sandbox:`, err.message);
    res.status(500).send("Failed to submit to sandbox");
  }
});

// Route: GET /list (Get apps as JSON, no auth required)
router.get("/list", async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const dynamicIndex = getDynamicIndexName();
    const result = await esClient.search({
      index: dynamicIndex,
      size: 100,
      query: { term: { uploadedByUser: true } },
      sort: [{ timestamp: { order: "desc" } }],
    });

    const apps = result.hits.hits.map((hit) => ({
      id: hit._id,
      ...hit._source,
    }));

    res.status(200).json({
      total: apps.length,
      apps: apps,
    });
  } catch (err) {
    console.error("Failed to fetch apps:", err.message);
    res.status(500).json({ error: "Failed to fetch apps" });
  }
});

// GET /details/:identifier - Get app details - NO AUTH REQUIRED
router.get("/details/:identifier", getAppDetails);

// GET /download/:fileName - Download APK file - REQUIRES WEB AUTH
router.get("/download/:fileName", requireWebAuth, downloadApp);

// DELETE /delete/:sha256 - Delete app and APK file - REQUIRES WEB AUTH
router.delete("/delete/:sha256", requireWebAuth, deleteApp);

// POST /scan - Original scan endpoint (backward compatibility) - NO AUTH REQUIRED
router.post("/scan", receiveAppData);

module.exports = router;