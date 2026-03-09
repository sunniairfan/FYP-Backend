const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const mobsf = require("../utils/mobsf");
const { analyzeFileWithVirusTotal, checkVirusTotal } = require("../utils/virusTotal");
const { calculateWeightedRiskScore } = require("../utils/riskAlgorithm");
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
const uploadsDir = path.join(__dirname, "../uploads/apks");
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

    // MobSF provides security score in appsec.security_score field
    const securityScore = report.appsec?.security_score || report.security_score || 0;

    const mobsfAnalysis = {
      security_score: securityScore,
      dangerous_permissions: dangerousPermissions,
      high_risk_findings: highRiskFindings,
      scan_type: uploadRes.scan_type || "unknown",
      file_name: uploadRes.file_name || path.basename(filePath),
    };

    console.log(`[MobSF Analysis] Analysis complete:`, {
      security_score: securityScore,
      dangerous_permissions: dangerousPermissions.length,
      high_risk_findings: highRiskFindings,
    });

    // Determine MobSF status based on security score
    let mobsfStatus = "unknown";
    if (securityScore >= 70) mobsfStatus = "safe";
    else if (securityScore < 40) mobsfStatus = "malicious";
    else mobsfStatus = "suspicious";

    await esClient.update({
      index: dynamicIndex,
      id: docId,
      body: {
        doc: {
          mobsfAnalysis,
          lastMobsfAnalysis: new Date().toISOString(),
          mobsfHash: md5Hash,
          mobsfStatus: mobsfStatus,
          mobsfScanType: uploadRes.scan_type,
        },
      },
    });

    console.log(`[MobSF Analysis] Database updated successfully for ${appData.packageName}`);

    return {
      success: true,
      analysis: mobsfAnalysis,
      app: appData,
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
              mobsfStatus: "analysis_failed",
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
            undetectedCount: vtResult.undetectedCount || 0,
            results: vtResult.results || {},
            scanTime: vtResult.scanTime,
            analysisId: vtResult.analysisId,
            analysisDate: new Date().toISOString(),
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

// GET /virustotal-results/:sha256 - View VirusTotal analysis results - REQUIRES WEB AUTH
router.get("/virustotal-results/:sha256", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;
  
  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);
    
    console.log(`[VT Results] Looking for app ${sha256} in index: ${indexName}`);
    
    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).send(`
        <html>
          <head>
            <title>App Not Found</title>
            <style>
              body { background: #0a192f; color: white; font-family: Arial; text-align: center; padding: 50px; }
              .error { background: #e63946; padding: 20px; border-radius: 10px; display: inline-block; }
              a { color: #90e0ef; text-decoration: none; }
            </style>
          </head>
          <body>
            <div class="error">
              <h1>❌ App Not Found</h1>
              <p>The requested app was not found in the database.</p>
              <a href="/uploadapp/apps">← Back to Apps</a>
            </div>
          </body>
        </html>
      `);
    }

    const appData = searchRes.hits.hits[0]._source;
    const vtAnalysis = appData.virusTotalAnalysis;

    if (!vtAnalysis) {
      return res.status(400).send(`
        <html>
          <head>
            <title>No VirusTotal Analysis</title>
            <style>
              body { background: #0a192f; color: white; font-family: Arial; text-align: center; padding: 50px; }
              .warning { background: #ffb703; color: #1b263b; padding: 20px; border-radius: 10px; display: inline-block; }
              a { color: #0077b6; text-decoration: none; font-weight: bold; }
            </style>
          </head>
          <body>
            <div class="warning">
              <h1>⚠️ No VirusTotal Analysis Available</h1>
              <p>This app has not been analyzed with VirusTotal yet.</p>
              <a href="/uploadapp/apps">← Back to Apps</a>
            </div>
          </body>
        </html>
      `);
    }

    // Generate HTML page with VirusTotal results
    const html = `
      <html>
      <head>
        <title>VirusTotal Results - ${appData.packageName}</title>
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }

          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: #0a192f;
            color: #cbd5e1;
            min-height: 100vh;
            padding: 20px;
          }

          .container {
            max-width: 1000px;
            margin: 0 auto;
          }

          .back-btn {
            display: inline-block;
            margin-bottom: 20px;
            padding: 8px 16px;
            background: #2563eb;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s;
          }

          .back-btn:hover {
            background: #1d4ed8;
          }

          .header {
            text-align: center;
            margin-bottom: 25px;
          }

          h1 {
            color: #e2e8f0;
            font-size: 24px;
            margin: 0 0 8px 0;
            font-weight: 600;
          }

          .app-info {
            color: #94a3b8;
            font-size: 13px;
          }
          .back-btn {
            display: inline-block;
            margin: 20px 0;
            padding: 8px 16px;
            background: #2563eb;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s;
          }
          .back-btn:hover {
            background: #1d4ed8;
          }
          .summary-card {
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
          }
          .summary-title {
            font-size: 15px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #e2e8f0;
          }
          .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
          }
          .stat-box {
            background: #112240;
            border: 1px solid #2a2a2a;
            padding: 15px;
            border-radius: 6px;
            text-align: center;
          }
          .stat-label {
            color: #94a3b8;
            font-size: 11px;
            margin-bottom: 8px;
            text-transform: uppercase;
            font-weight: 500;
          }
          .stat-value {
            font-size: 22px;
            font-weight: bold;
            color: #60a5fa;
          }
          .stat-value.malicious {
            color: #ef4444;
          }
          .stat-value.suspicious {
            color: #ef4444;
          }
          .stat-value.safe {
            color: #10b981;
          }
          .status-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 700;
            margin: 15px 0;
            text-transform: uppercase;
          }
          .status-badge.safe {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid #10b981;
          }
          .status-badge.malicious {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid #ef4444;
          }
          .status-badge.suspicious {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
            border: 1px solid #ef4444;
          }
          .detections-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            border-radius: 12px;
            overflow: hidden;
            margin-top: 20px;
          }
          .detections-table th {
            background: #1d3557;
            padding: 15px;
            text-align: left;
            font-weight: bold;
          }
          .detections-table td {
            background: #1b263b;
            padding: 12px 15px;
            border-bottom: 1px solid #415a77;
          }
          .detections-table tr:last-child td {
            border-bottom: none;
          }
          .detections-table tr:hover td {
            background: #273b54;
          }
          .engine-name {
            font-weight: 600;
            color: #90e0ef;
          }
          .result-detected {
            color: #e63946;
            font-weight: bold;
          }
          .result-clean {
            color: #52b788;
          }
          .info-row {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #1d3557;
            gap: 15px;
          }
          .info-row:last-child {
            border-bottom: none;
          }
          .info-label {
            color: #94a3b8;
            font-weight: 500;
            font-size: 12px;
            min-width: 120px;
          }
          .info-value {
            color: #cbd5e1;
            font-family: 'Courier New', monospace;
            word-break: break-all;
            font-size: 11px;
            text-align: right;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <a href="/uploadapp/apps" class="back-btn">← Back to Apps</a>
          
          <div class="header">
            <h1>VirusTotal Analysis Results</h1>
            <div class="app-info">
              <strong>${appData.appName || 'Unknown App'}</strong><br>
              ${appData.packageName}
            </div>
          </div>

          <div class="summary-card">
            <div class="summary-title">Detection Summary</div>
            
            <div style="text-align: center;">
              <div class="status-badge ${vtAnalysis.status}">
                ${vtAnalysis.status === 'malicious' ? 'MALICIOUS' : 
                  vtAnalysis.status === 'suspicious' ? 'SUSPICIOUS' : 
                  'SAFE'}
              </div>
            </div>

            <div class="stats-grid">
              <div class="stat-box">
                <div class="stat-label">Detection Ratio</div>
                <div class="stat-value">${vtAnalysis.detectionRatio || 'N/A'}</div>
              </div>
              <div class="stat-box">
                <div class="stat-label">Malicious</div>
                <div class="stat-value malicious">${vtAnalysis.maliciousCount || 0}</div>
              </div>
              <div class="stat-box">
                <div class="stat-label">Suspicious</div>
                <div class="stat-value suspicious">${vtAnalysis.suspiciousCount || 0}</div>
              </div>
              <div class="stat-box">
                <div class="stat-label">Undetected</div>
                <div class="stat-value safe">${vtAnalysis.undetectedCount || 0}</div>
              </div>
            </div>
          </div>

          <div class="summary-card">
            <div class="summary-title">File Information</div>
            <div class="info-row">
              <span class="info-label">SHA-256:</span>
              <span class="info-value">${appData.sha256 || 'N/A'}</span>
            </div>
            <div class="info-row">
              <span class="info-label">File Size:</span>
              <span class="info-value">${appData.sizeMB?.toFixed(2) || 0} MB</span>
            </div>
          </div>

          ${vtAnalysis.results && Object.keys(vtAnalysis.results).length > 0 ? `
            <div class="summary-card">
              <div class="summary-title">Detection Details (${Object.keys(vtAnalysis.results).length} Engines)</div>
              <table class="detections-table">
                <thead>
                  <tr>
                    <th>Antivirus Engine</th>
                    <th>Category</th>
                    <th>Result</th>
                  </tr>
                </thead>
                <tbody>
                  ${Object.entries(vtAnalysis.results)
                    .sort((a, b) => {
                      // Sort: detected first, then by engine name
                      if (a[1].category === 'malicious' && b[1].category !== 'malicious') return -1;
                      if (b[1].category === 'malicious' && a[1].category !== 'malicious') return 1;
                      if (a[1].category === 'suspicious' && b[1].category !== 'suspicious') return -1;
                      if (b[1].category === 'suspicious' && a[1].category !== 'suspicious') return 1;
                      return a[0].localeCompare(b[0]);
                    })
                    .map(([engine, result]) => `
                      <tr>
                        <td class="engine-name">${engine}</td>
                        <td>${result.category || 'undetected'}</td>
                        <td class="${result.category === 'undetected' ? 'result-clean' : 'result-detected'}">
                          ${result.result || 'Clean'}
                        </td>
                      </tr>
                    `).join('')}
                </tbody>
              </table>
            </div>
          ` : ''}
        </div>
      </body>
      </html>
    `;

    res.send(html);
  } catch (err) {
    console.error("[VT Results] Error:", err.message);
    res.status(500).send(`
      <html>
        <head>
          <title>Error</title>
          <style>
            body { background: #0a192f; color: white; font-family: Arial; text-align: center; padding: 50px; }
            .error { background: #e63946; padding: 20px; border-radius: 10px; display: inline-block; }
            a { color: #90e0ef; text-decoration: none; }
          </style>
        </head>
        <body>
          <div class="error">
            <h1>❌ Error</h1>
            <p>Failed to load VirusTotal results: ${err.message}</p>
            <a href="/uploadapp/apps">← Back to Apps</a>
          </div>
        </body>
      </html>
    `);
  }
});

// GET /results/:sha256 - Comprehensive analysis results page - REQUIRES WEB AUTH
router.get("/results/:sha256", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;
  
  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);
    
    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).send(`
        <html>
        <head>
          <title>App Not Found</title>
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
          body { background: #0a192f; color: white; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
            .error-box { background: #112240; border: 1px solid #2a2a2a; border-radius: 10px; padding: 40px; max-width: 500px; text-align: center; }
            h1 { color: #ef4444; margin-bottom: 10px; }
            p { color: #94a3b8; margin-bottom: 20px; }
            a { color: #2563eb; text-decoration: none; font-weight: 500; }
            a:hover { text-decoration: underline; }
          </style>
        </head>
        <body>
          <div class="error-box">
            <h1>❌ App Not Found</h1>
            <p>The requested app was not found in the database.</p>
            <a href="/uploadapp/apps">← Back to Apps</a>
          </div>
        </body>
        </html>
      `);
    }

    const app = searchRes.hits.hits[0]._source;

    // Fetch VT hash check if not already in database
    if (!app.virusTotalHashCheck && app.sha256) {
      console.log(`[Results:${sha256}] Fetching VT hash check...`);
      try {
        const vtResult = await checkVirusTotal(app.sha256);
        if (vtResult) {
          app.virusTotalHashCheck = {
            detectionRatio: vtResult.detectionRatio,
            totalEngines: vtResult.totalEngines,
            detectedEngines: vtResult.detectedEngines,
            scanTime: vtResult.scanTime
          };
          
          // Update database with VT hash check
          try {
            await esClient.update({
              index: indexName,
              id: searchRes.hits.hits[0]._id,
              body: {
                doc: {
                  virusTotalHashCheck: app.virusTotalHashCheck,
                  status: vtResult.status,
                  source: "VirusTotal"
                }
              }
            });
            console.log(`✅ Updated VT hash check for: ${app.packageName}`);
          } catch (updateErr) {
            console.log(`⚠️ Could not update VT hash in database: ${updateErr.message}`);
          }
        }
      } catch (vtErr) {
        console.log(`ℹ️ Could not fetch VT hash: ${vtErr.message}`);
      }
    }

    const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Analysis Results - ${app.appName || 'App'}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0a192f 0%, #1b3a52 100%); color: #cbd5e1; min-height: 100vh; padding: 30px 20px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    .back-btn { 
      display: inline-block; 
      margin-bottom: 25px;
      padding: 10px 20px;
      background: #1e293b;
      color: #90e0ef;
      text-decoration: none;
      border-radius: 6px;
      border: 1px solid #334155;
      transition: all 0.3s;
    }
    .back-btn:hover { background: #334155; border-color: #90e0ef; }
    
    .header {
      background: rgba(30, 41, 59, 0.8);
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 30px;
      margin-bottom: 30px;
      backdrop-filter: blur(10px);
    }
    .app-name { font-size: 32px; font-weight: 700; margin-bottom: 10px; color: #f1f5f9; }
    .app-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-top: 20px; }
    .meta-item { }
    .meta-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
    .meta-value { color: #e2e8f0; font-weight: 500; word-break: break-all; }
    
    .analysis-section {
      background: rgba(30, 41, 59, 0.6);
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 25px;
      margin-bottom: 20px;
      backdrop-filter: blur(10px);
    }
    .section-title {
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .section-title .icon { font-size: 20px; }
    
    .analysis-section.ml { border-left: 4px solid #6366f1; }
    .analysis-section.ml .section-title { color: #6366f1; }
    
    .analysis-section.mobsf { border-left: 4px solid #22c55e; }
    .analysis-section.mobsf .section-title { color: #22c55e; }
    
    .analysis-section.vt-hash { border-left: 4px solid #3b82f6; }
    .analysis-section.vt-hash .section-title { color: #3b82f6; }
    
    .analysis-section.vt-multi { border-left: 4px solid #a855f7; }
    .analysis-section.vt-multi .section-title { color: #a855f7; }
    
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 15px;
      margin-bottom: 15px;
    }
    .metric {
      background: rgba(10, 25, 47, 0.8);
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 15px;
    }
    .metric-label {
      font-size: 11px;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 8px;
    }
    .metric-value {
      font-size: 22px;
      font-weight: 700;
      color: #e2e8f0;
    }
    .no-data {
      background: rgba(15, 23, 42, 0.5);
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
      color: #64748b;
      font-style: italic;
    }
    .permission-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }
    .permission-tag {
      background: rgba(239, 68, 68, 0.2);
      color: #fca5a5;
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 11px;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .status-safe { color: #10b981; }
    .status-risky { color: #f59e0b; }
    .status-malware { color: #ef4444; }
  </style>
</head>
<body>
  <div class="container">
    <div style="display: flex; gap: 10px; margin-bottom: 25px;">
      <a href="/" class="back-btn" style="background: #1e293b; border: 1px solid #334155; color: #90e0ef;">🏠 Home</a>
      <a href="/uploadapp/apps" class="back-btn" style="background: #1e293b; border: 1px solid #334155; color: #90e0ef;">← Back to Apps</a>
    </div>
    
    <div class="header">
      <div class="app-name">${app.appName || 'Unknown App'}</div>
      <div class="app-meta">
        <div class="meta-item">
          <div class="meta-label">Package Name</div>
          <div class="meta-value">${app.packageName || 'N/A'}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Overall Status</div>
          <div class="meta-value" style="color: ${app.status === 'safe' ? '#10b981' : app.status === 'suspicious' ? '#f59e0b' : '#ef4444'};">
            ${(app.status || 'unknown').toUpperCase()}
          </div>
        </div>
        <div class="meta-item">
          <div class="meta-label">File Size</div>
          <div class="meta-value">${app.sizeMB?.toFixed(2) || 0} MB</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Source</div>
          <div class="meta-value">${app.source || 'N/A'}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Uploaded</div>
          <div class="meta-value">${app.timestamp ? new Date(app.timestamp).toLocaleDateString() : 'N/A'}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">SHA256</div>
          <div class="meta-value" style="font-size: 11px; font-family: monospace;">${app.sha256?.substring(0, 20)}...</div>
        </div>
      </div>
    </div>

    <!-- RUN ALGORITHM SECTION -->
    <div class="analysis-section" style="background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%); border-left: 4px solid #6366f1;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <div class="section-title" style="margin: 0;"><span class="icon">⚙️</span> Weighted Risk Algorithm</div>
        <button id="runAlgorithmBtn" onclick="runAlgorithm('${sha256}')" style="padding: 10px 20px; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; transition: all 0.3s;">
          ▶️ Run Algorithm
        </button>
      </div>
      <div id="algorithmResults" style="display: none;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px;">
          <div class="metric">
            <div class="metric-label">Final Score</div>
            <div class="metric-value" id="finalScore" style="color: #6366f1;">--</div>
          </div>
          <div class="metric">
            <div class="metric-label">Final Status</div>
            <div class="metric-value" id="finalStatus" style="color: #6366f1;">--</div>
          </div>
          <div class="metric">
            <div class="metric-label">Confidence</div>
            <div class="metric-value" id="confidence" style="color: #6366f1;">--</div>
          </div>
          <div class="metric">
            <div class="metric-label">Data Sources</div>
            <div class="metric-value" id="dataSources" style="color: #6366f1;">--</div>
          </div>
        </div>

        <div style="background: rgba(10, 25, 47, 0.5); border: 1px solid #1e293b; border-radius: 8px; padding: 15px; margin-bottom: 15px;">
          <div style="font-weight: 600; color: #e2e8f0; margin-bottom: 12px;">Score Breakdown:</div>
          <div id="breakdownTable" style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px;">
            <!-- Breakdown will be populated here -->
          </div>
        </div>

        <div style="background: rgba(10, 25, 47, 0.5); border: 1px solid #1e293b; border-radius: 8px; padding: 15px;">
          <div style="font-weight: 600; color: #e2e8f0; margin-bottom: 12px;">Weights Used:</div>
          <div id="weightsTable" style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px;">
            <!-- Weights will be populated here -->
          </div>
        </div>
      </div>
      <div id="algorithmLoading" style="display: none; text-align: center; padding: 20px;">
        <div style="font-size: 24px; margin-bottom: 10px;">⏳</div>
        <div style="color: #94a3b8;">Calculating weighted risk score...</div>
      </div>
    </div>

    <!-- 1. ML MODEL PREDICTION -->
    <div class="analysis-section ml">
      <div class="section-title"><span class="icon">🤖</span> ML Model Prediction</div>
      <div class="section-content">
        ${app.mlPredictionScore !== undefined ? `
          <div class="metrics-grid">
            <div class="metric">
              <div class="metric-label">Prediction</div>
              <div class="metric-value status-${app.mlPredictionLabel === 'safe' ? 'safe' : app.mlPredictionLabel === 'risky' ? 'risky' : 'malware'}">
                ${(app.mlPredictionLabel || 'unknown').toUpperCase()}
              </div>
            </div>
            <div class="metric">
              <div class="metric-label">Confidence Score</div>
              <div class="metric-value status-${app.mlPredictionLabel === 'safe' ? 'safe' : app.mlPredictionLabel === 'risky' ? 'risky' : 'malware'}">
                ${(app.mlPredictionScore ?? 0).toFixed(3)}
              </div>
            </div>
            ${app.mlAnalysisTimestamp ? `
              <div class="metric">
                <div class="metric-label">Analysis Date</div>
                <div class="metric-value">${new Date(app.mlAnalysisTimestamp).toLocaleDateString()}</div>
              </div>
            ` : ''}
          </div>
        ` : `
          <div class="no-data">No ML analysis available yet. Contact administrator.</div>
        `}
      </div>
    </div>

    <!-- 2. STATIC ANALYSIS (MobSF) -->
    <div class="analysis-section mobsf">
      <div class="section-title"><span class="icon">🔍</span> Static Analysis (MobSF)</div>
      <div class="section-content">
        ${app.mobsfAnalysis ? `
          <div class="metrics-grid">
            <div class="metric">
              <div class="metric-label">Security Score</div>
              <div class="metric-value" style="color: ${app.mobsfAnalysis.security_score >= 70 ? '#10b981' : app.mobsfAnalysis.security_score >= 40 ? '#f59e0b' : '#ef4444'};">
                ${app.mobsfAnalysis.security_score}/100
              </div>
            </div>
            <div class="metric">
              <div class="metric-label">Dangerous Permissions</div>
              <div class="metric-value" style="color: #f59e0b;">${app.mobsfAnalysis.dangerous_permissions?.length || 0}</div>
            </div>
            <div class="metric">
              <div class="metric-label">High Risk Findings</div>
              <div class="metric-value" style="color: #ef4444;">${app.mobsfAnalysis.high_risk_findings || 0}</div>
            </div>
            ${app.mobsfAnalysis.scan_type ? `
              <div class="metric">
                <div class="metric-label">Scan Type</div>
                <div class="metric-value">${app.mobsfAnalysis.scan_type}</div>
              </div>
            ` : ''}
          </div>
          ${app.mobsfAnalysis.dangerous_permissions && app.mobsfAnalysis.dangerous_permissions.length > 0 ? `
            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #1e293b;">
              <div class="metric-label">Dangerous Permissions</div>
              <div class="permission-list">
                ${app.mobsfAnalysis.dangerous_permissions.map(p => `
                  <span class="permission-tag">${p.replace('android.permission.', '')}</span>
                `).join('')}
              </div>
            </div>
          ` : ''}
        ` : `
          <div class="no-data">No static analysis available yet</div>
        `}
      </div>
    </div>

    <!-- 4. VirusTotal Multi-Engine Analysis -->
    <div class="analysis-section vt-multi">
      <div class="section-title"><span class="icon">⚙️</span> VirusTotal Multi-Engine Analysis</div>
      <div class="section-content">
        ${app.virusTotalAnalysis ? `
          <div class="metrics-grid">
            <div class="metric">
              <div class="metric-label">VT Status</div>
              <div class="metric-value" style="color: ${app.virusTotalAnalysis.status === 'malicious' ? '#ef4444' : app.virusTotalAnalysis.status === 'suspicious' ? '#f59e0b' : '#10b981'};">
                ${(app.virusTotalAnalysis.status || 'unknown').toUpperCase()}
              </div>
            </div>
            <div class="metric">
              <div class="metric-label">Detection Ratio</div>
              <div class="metric-value">${app.virusTotalAnalysis.detectionRatio || 'N/A'}</div>
            </div>
            <div class="metric">
              <div class="metric-label">Malicious</div>
              <div class="metric-value" style="color: #ef4444;">${app.virusTotalAnalysis.maliciousCount || 0}</div>
            </div>
            <div class="metric">
              <div class="metric-label">Suspicious</div>
              <div class="metric-value" style="color: #f59e0b;">${app.virusTotalAnalysis.suspiciousCount || 0}</div>
            </div>
            <div class="metric">
              <div class="metric-label">Undetected</div>
              <div class="metric-value" style="color: #10b981;">${app.virusTotalAnalysis.undetectedCount || 0}</div>
            </div>
            <div class="metric">
              <div class="metric-label">Scan Date</div>
              <div class="metric-value">${new Date(app.virusTotalAnalysis.scanTime || app.virusTotalAnalysis.analysisDate).toLocaleDateString()}</div>
            </div>
          </div>
        ` : `
          <div class="no-data">No multi-engine analysis available. Click "Analyze VirusTotal" to run analysis.</div>
        `}
      </div>
    </div>
  </div>
</body>
</html>
    `;

    res.send(html);
  } catch (err) {
    console.error("Failed to load results:", err.message);
    res.status(500).send(`<html><body style="background:#0a192f;color:white;text-align:center;padding:50px"><h1>❌ Error</h1><p>\${err.message}</p><a href="/uploadapp/apps" style="color:#90e0ef">← Back</a></body></html>`);
  }
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
        appType: hit._source.appType || 'system'
      }));
    } catch (indexError) {
      console.log(`[Apps Route] Index ${indexName} not found or no data`);
    }
    
    // Separate apps by type
    const userApps = apps.filter(app => app.appType === 'user');
    const systemApps = apps.filter(app => app.appType === 'system');

    let html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Uploaded Apps - Android Malware Detector</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
          * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
          }

          html {
            position: relative;
            overflow-x: hidden;
          }
          
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: #0a192f;
            color: #94a3b8;
            min-height: 100vh;
            display: flex;
            position: relative;
            overflow-x: hidden;
          }

          /* Sidebar styles */
          .sidebar {
            width: 200px;
            background: #112240;
            height: 100vh;
            padding: 20px 0;
            display: flex;
            flex-direction: column;
            position: fixed;
            left: -200px;
            top: 0;
            z-index: 1000;
            box-shadow: 2px 0 10px rgba(0, 0, 0, 0.3);
            transition: left 0.3s ease;
          }

          .sidebar.open {
            left: 0;
          }

          .logo {
            padding: 0 18px 25px;
            display: flex;
            align-items: center;
            gap: 12px;
            color: white;
            font-weight: 600;
            font-size: 17px;
            border-bottom: 1px solid #1d3557;
            margin-bottom: 20px;
          }

          .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%); border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            color: white;
          }

          .nav-item {
            padding: 12px 18px;
            color: #94a3b8;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: all 0.2s;
            font-size: 14px;
            cursor: pointer;
          }

          .nav-item:hover {
            background: #1d3557;
            color: white;
          }

          .nav-item.active {
            background: #000000;
            color: white;
            border-left: 3px solid #2563eb;
          }

          .nav-icon {
            width: 20px;
            text-align: center;
            font-size: 16px;
          }

          .logout-nav {
            margin-top: auto;
            padding: 12px 18px;
            color: #ef4444;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 12px;
            transition: all 0.2s;
            font-size: 14px;
            border-top: 1px solid #1d3557;
          }

          .logout-nav:hover {
            background: #7f1d1d;
            color: white;
          }

          /* Main content */
          .main-content {
            margin-left: 0;
            flex: 1;
            padding: 0;
            width: 100%;
            transition: margin-left 0.3s ease;
            transform: none;
          }

          .main-content.shifted {
            margin-left: 200px;
          }

          .menu-btn {
            background: transparent;
            border: none;
            color: #94a3b8;
            font-size: 18px;
            cursor: pointer;
            padding: 4px 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: color 0.3s;
          }

          .menu-btn:hover {
            color: white;
          }

          .overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 999;
          }

          .overlay.active {
            display: block;
          }

          .top-bar {
            background: #112240;
            padding: 8px 15px 8px 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1d3557;
          }

          .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #e2e8f0;
            font-size: 14px;
            font-weight: 500;
          }

          .user-avatar {
            width: 32px;
            height: 32px;
            background: #3a3a3a;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 600;
            font-size: 14px;
          }

          .container {
            padding: 30px;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
          }

          .header {
            text-align: center;
            margin-bottom: 30px;
          }

          h1 {
            color: white;
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
          }

          .subtitle {
            color: #64748b;
            font-size: 14px;
          }

          .controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            gap: 15px;
          }

          .date-selector {
            display: flex;
            gap: 12px;
            padding: 12px 20px;
            background: rgba(17, 34, 64, 0.6);
            border: 1px solid #1d3557;
            border-radius: 8px;
            align-items: center;
          }

          .date-selector label {
            display: none;
          }
          
          .date-selector input[type="date"] {
            background: transparent;
            border: none;
            color: #94a3b8;
            padding: 5px 8px;
            font-size: 14px;
            cursor: pointer;
          }
          
          .date-selector input:focus {
            outline: none;
          }
          
          .date-selector input[type="date"]::-webkit-calendar-picker-indicator {
            filter: invert(0.6);
            cursor: pointer;
          }
          
          .date-selector button, .search-section button {
            background: #2563eb;
            border: none;
            padding: 7px 15px;
            border-radius: 6px;
            color: white;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
          }
          
          .date-selector button:hover, .search-section button:hover {
            background: #1d4ed8;
          }
          
          .search-section {
            display: flex;
            gap: 12px;
            padding: 12px 20px;
            background: rgba(17, 34, 64, 0.6);
            border: 1px solid #1d3557;
            border-radius: 8px;
            align-items: center;
            min-width: 350px;
          }
          
          .search-section label {
            display: none;
          }
          
          .search-section input[type="text"] {
            background: transparent;
            border: none;
            color: #94a3b8;
            padding: 5px;
            font-size: 14px;
            width: 100%;
            flex: 1;
          }
          
          .search-section input:focus {
            outline: none;
          }
          
          .search-section input::placeholder {
            color: #64748b;
          }
          
          .search-section button {
            display: none;
          }

          .clear-btn {
            background: rgba(220, 38, 38, 0.15);
            border: 1px solid rgba(220, 38, 38, 0.4);
            color: #ef4444;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 8px;
            white-space: nowrap;
            min-width: fit-content;
          }

          .clear-btn:hover {
            background: rgba(220, 38, 38, 0.25);
            border-color: #dc2626;
          }
          
          .clear-btn i {
            font-size: 15px;
          }

          .current-index {
            background: #112240;
            padding: 10px 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            color: #60a5fa;
            font-size: 13px;
            text-align: center;
            border: 1px solid #1d3557;
          }

          .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
          }

          .stat-card {
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
          }

          .stat-label {
            color: #94a3b8;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
          }

          .stat-value {
            font-size: 32px;
            font-weight: bold;
          }

          .stat-card.total .stat-value { color: #3b82f6; }
          .stat-card.malicious .stat-value { color: #ef4444; }
          .stat-card.safe .stat-value { color: #10b981; }
          .stat-card.suspicious .stat-value { color: #ef4444; }
          .stat-card.unknown .stat-value { color: #6b7280; }

          table {
            width: 100%;
            border-collapse: collapse;
            background: #112240;
            border-radius: 8px;
            overflow: hidden;
          }

          thead {
            background: #1d3557;
          }

          th {
            padding: 8px 6px;
            text-align: left;
            color: #94a3b8;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #1d3557;
          }

          th:nth-child(1) { width: 10%; }
          th:nth-child(2) { width: 9%; }
          th:nth-child(3) { width: 8%; }
          th:nth-child(4) { width: 21%; }
          th:nth-child(5) { width: 52%; }

          td {
            padding: 10px 8px;
            border-bottom: 1px solid #1d3557;
            color: #cbd5e1;
            font-size: 13px;
          }

          td:nth-child(1) { width: 10%; }
          td:nth-child(2) { width: 9%; }
          td:nth-child(3) { width: 8%; }
          td:nth-child(4) { width: 21%; }
          td:nth-child(5) { width: 52%; }

          tr:last-child td {
            border-bottom: none;
          }

          tr:hover {
            background: #1d3557;
          }

          .file-info {
            font-size: 10px;
            color: #94a3b8;
            margin-top: 2px;
          }

          td:nth-child(1), td:nth-child(2), td:nth-child(3) {
            padding: 10px 6px;
            font-size: 12px;
          }

          .app-name {
            font-weight: 600;
            color: white;
            font-size: 12px;
          }

          .package-name {
            font-family: 'Courier New', monospace;
            font-size: 10px;
            color: #94a3b8;
          }

          .permissions {
            font-size: 11px;
            color: #cbd5e1;
            margin-top: 2px;
          }

          .status {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            display: inline-block;
          }

          .status.safe {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
          }

          .status.malicious {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
          }

          .status.suspicious {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
          }

          .status.unknown {
            background: rgba(107, 114, 128, 0.2);
            color: #6b7280;
          }

          .status.uploaded {
            background: rgba(148, 163, 184, 0.2);
            color: #94a3b4;
          }

          .actions {
            padding: 10px 6px;
            position: relative;
          }

          .analysis-columns {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 8px;
            margin-bottom: 10px;
          }

          .analysis-col {
            background: rgba(255, 255, 255, 0.05);
            padding: 8px;
            border-radius: 4px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            display: flex;
            flex-direction: column;
            gap: 6px;
            align-items: center;
            text-align: center;
          }

          .col-title {
            font-size: 9px;
            font-weight: 700;
            color: #cbd5e1;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            margin-bottom: 2px;
          }

          .bottom-actions {
            display: flex;
            justify-content: center;
            gap: 6px;
            flex-wrap: wrap;
          }

          button {
            padding: 7px 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 10px;
            font-weight: 500;
            transition: all 0.2s;
            margin: 0;
            white-space: nowrap;
          }

          .analysis-col button {
            width: 100%;
            font-size: 9px;
            padding: 6px 8px;
          }

          .bottom-actions button {
            flex: 0 0 auto;
            font-size: 10px;
            padding: 7px 10px;
          }

          .btn-mobsf, .btn-report, .btn-view, .btn-vt, .btn-download, .btn-analysis, .btn-dynamic {
            background: #2563eb;
            color: white;
          }

          .btn-delete-action {
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
            color: white;
            border: none;
            padding: 7px 14px;
          }

          .btn-delete-action:hover {
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.4);
          }

          .btn-remarks {
            background: #059669;
            color: white;
          }

          .btn-remarks:hover {
            background: #047857;
          }

          .btn-mobsf:hover, .btn-report:hover, .btn-view:hover, .btn-vt:hover, .btn-download:hover, .btn-analysis:hover, .btn-dynamic:hover {
            background: #1d4ed8;
          }

          tr {
            position: relative;
          }

          .btn-group {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            align-items: center;
          }

          .btn-group-left {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            flex: 1;
          }

          .app-name {
            font-weight: 600;
            color: white;
          }

          .package-name {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #94a3b8;
          }

          .no-apps {
            text-align: center;
            padding: 50px;
            color: #94a3b8;
            font-size: 14px;
          }

          .permissions {
            font-size: 11px;
            color: #60a5fa;
            margin-top: 2px;
          }

          .mobsf-info, .vt-info {
            font-size: 10px;
            color: #60a5fa;
            margin-top: 2px;
          }

          .security-score {
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            display: inline-block;
            margin-top: 1px;
          }

          .score-high {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
          }

          .score-medium {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
          }

          .score-low {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
          }

          .mobsf-status {
            padding: 6px 12px;
            font-size: 12px;
            font-weight: 500;
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 6px;
            margin-right: 12px;
          }

          .mobsf-connected {
            color: #10b981;
          }

          .mobsf-disconnected {
            color: #ef4444;
          }


          }

          .btn-cancel {
            background: #374151;
            color: #e2e8f0;
          }

          .btn-cancel:hover {
            background: #1f2937;
          }
        </style>
      </head>
      <body>
        <!-- Sidebar -->
        <div class="sidebar" id="sidebar">
          <div class="logo">
            <div class="logo-icon">
              <i class="fas fa-shield-alt"></i>
            </div>
            <span>CYBER WOLF</span>
          </div>
          
          <a href="/" class="nav-item">
            <i class="fas fa-home nav-icon"></i>
            <span>Home</span>
          </a>
          
          <a href="/dashboard" class="nav-item">
            <i class="fas fa-chart-line nav-icon"></i>
            <span>Dashboard</span>
          </a>
          
          <a href="/uploadapp/apps" class="nav-item active">
            <i class="fas fa-mobile-alt nav-icon"></i>
            <span>App Manager</span>
          </a>
          
          <a href="#" class="nav-item">
            <i class="fas fa-cog nav-icon"></i>
            <span>Settings</span>
          </a>
          
          <a href="/logout" class="logout-nav">
            <i class="fas fa-sign-out-alt nav-icon"></i>
            <span>Logout</span>
          </a>
        </div>

        <!-- Overlay -->
        <div class="overlay" id="overlay" onclick="toggleSidebar()"></div>

        <!-- Main Content -->
        <div class="main-content" id="mainContent">
          <!-- Top Bar -->
          <div class="top-bar">
            <button class="menu-btn" onclick="toggleSidebar()">
              <i class="fas fa-bars"></i>
            </button>
            
            <div class="user-info">
              <div id="mobsf-status" class="mobsf-status">Checking MobSF...</div>
              <span>${req.session.username || 'User'}</span>
              <div class="user-avatar">${(req.session.username || 'U')[0].toUpperCase()}</div>
            </div>
          </div>
          
          <div class="container">
            <div class="header">
              <h1>Uploaded Apps</h1>
              <div class="subtitle">Android Malware Detection System</div>
            </div>
            
            <div class="controls">
              <div class="date-selector">
                <i class="fas fa-calendar-alt" style="color: #64748b;"></i>
                <input type="date" id="date-picker" value="${selectedDate}" onchange="loadAppsForDate()" />
              </div>
              
              <div class="search-section">
                <i class="fas fa-search" style="color: #64748b;"></i>
                <input type="text" id="search-input" placeholder="Search by app name..." onkeyup="performSearch()">
              </div>

              <button class="clear-btn" onclick="clearTodayData()">
                <i class="fas fa-trash-alt"></i>
                Clear Today's Data
              </button>
            </div>
            
            <!-- Filter Dropdown -->
            <div style="margin-bottom: 20px;">
              <label for="appTypeFilter" style="color: #94a3b8; font-weight: 500; margin-right: 10px;">Filter by App Type:</label>
              <select id="appTypeFilter" onchange="filterAppsByType()" style="padding: 8px 12px; background: #1e293b; color: white; border: 1px solid #334155; border-radius: 6px; font-size: 14px; cursor: pointer;">
                <option value="all">All Apps</option>
                <option value="user">User Apps Only</option>
                <option value="system">System Apps Only</option>
              </select>
            </div>
            
            <!-- Total Apps Stats -->
            <div class="stats-grid">
              <div class="stat-card total">
                <div class="stat-label">Total Apps</div>
                <div class="stat-value">${apps.length}</div>
              </div>
              <div class="stat-card malicious">
                <div class="stat-label">Malicious</div>
                <div class="stat-value">${apps.filter((app) => app.status === "malicious").length}</div>
              </div>
              <div class="stat-card safe">
                <div class="stat-label">Safe</div>
                <div class="stat-value">${apps.filter((app) => app.status === "safe").length}</div>
              </div>
              <div class="stat-card suspicious">
                <div class="stat-label">Suspicious</div>
                <div class="stat-value">${apps.filter((app) => app.status === "suspicious").length}</div>
              </div>
              <div class="stat-card unknown">
                <div class="stat-label">Unknown</div>
                <div class="stat-value">${apps.filter((app) => app.status === "unknown").length}</div>
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
        const hasDynamicAnalysis = app.dynamicAnalysis && app.dynamicAnalysis.status === 'completed';
        const hasApkFile = app.apkFilePath && app.apkFileName;
        const appType = app.appType || 'system';

        let scoreClass = "score-medium";
        if (hasMobsfAnalysis) {
          if (app.mobsfAnalysis.security_score >= 70) scoreClass = "score-high";
          else if (app.mobsfAnalysis.security_score < 40) scoreClass = "score-low";
        }
        
        html += `
          <tr data-app-type="${appType}">
            <td>
              <div class="app-name">${app.appName || "Unknown App"}</div>
              <div class="file-info">Uploaded: ${uploadDate}</div>
            </td>
            <td>
              <div class="package-name">${app.packageName}</div>
              ${permissionCount > 0 ? `<div class="permissions">${permissionCount} perms</div>` : ""}
            </td>
            <td>
              <div class="file-info">${fileInfo}</div>
              <div class="file-info">${app.sizeMB?.toFixed(1) || 0}MB</div>
            </td>
            <td>
              <span class="status ${app.status || "unknown"}">
                ${app.status || "unknown"}
              </span>
              ${hasMobsfAnalysis ? `
                <div class="mobsf-info" style="margin-top: 4px;">
                  <span class="security-score" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8;">Score: ${app.mobsfAnalysis.security_score}/100</span>
                </div>
                <div class="mobsf-info" style="font-size: 10px;">
                  ${app.mobsfAnalysis.dangerous_permissions?.length > 0 ? `${app.mobsfAnalysis.dangerous_permissions.length} dangerous perms` : ""}
                  ${app.mobsfAnalysis.high_risk_findings > 0 ? `| ${app.mobsfAnalysis.high_risk_findings} risks` : ""}
                </div>
              ` : ""}
              ${hasVirusTotalAnalysis ? `
                <div class="vt-info" style="margin-top: 4px;">
                  <span class="security-score" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8;">VT: ${app.virusTotalAnalysis.detectionRatio}</span>
                </div>
                <div class="vt-info" style="font-size: 10px;">
                  M:${app.virusTotalAnalysis.maliciousCount} | S:${app.virusTotalAnalysis.suspiciousCount}
                </div>
              ` : ""}
              ${app.mlPredictionScore !== undefined && app.mlPredictionScore !== null && app.status !== 'safe' ? `
                <div class="ml-info" style="margin-top: 4px; padding: 3px; background: rgba(99, 102, 241, 0.1); border-radius: 2px; border-left: 2px solid #6366f1;">
                  <span class="security-score" style="background: rgba(99, 102, 241, 0.2); color: #6366f1; margin: 0; font-size: 9px;">ML S:${(app.mlPredictionScore ?? 0).toFixed(2)}</span>
                </div>
              ` : ""}
            </td>
            <td class="actions">
              <div class="analysis-columns">
                <!-- Static Analysis Column -->
                <div class="analysis-col">
                  <div class="col-title">Static Analysis</div>
                  <button class="btn-mobsf" onclick="runMobsfAnalysis('${app.sha256}', '${app.packageName}')" title="Run MobSF Static Analysis">
                    ${hasMobsfAnalysis ? "Re-analyze" : "Do Static"} Analysis
                  </button>
                  ${hasMobsfAnalysis ? `
                    <button class="btn-report" onclick="downloadMobsfReport('${app.sha256}')" title="Download MobSF PDF Report">
                      📄 Download PDF
                    </button>
                  ` : ""}
                </div>

                <!-- Dynamic Analysis Column -->
                <div class="analysis-col">
                  <div class="col-title">Dynamic Analysis</div>
                  <button class="btn-dynamic" onclick="runDynamicAnalysis('${app.sha256}', '${app.packageName}', this)" title="Do Dynamic Analysis">
                    ${hasDynamicAnalysis ? 'Re-run Dynamic Analysis' : 'Do Dynamic Analysis'}
                  </button>
                  ${hasDynamicAnalysis ? `
                    <button class="btn-report" onclick="downloadDynamicReport('${app.sha256}')" title="Download Dynamic Analysis PDF">
                      📄 Download PDF
                    </button>
                    <button class="btn-view" onclick="viewDynamicResults('${app.sha256}')" title="View Dynamic Analysis Results">
                      👁️ View Results
                    </button>
                  ` : ''}
                </div>

                <!-- Multi-Engine Analysis Column -->
                <div class="analysis-col">
                  <div class="col-title">Multi-Engine Analysis</div>
                  <button class="btn-vt" onclick="runVirusTotalAnalysis('${app.sha256}', '${app.packageName}')" title="Run VirusTotal Analysis">
                    Multi-Engine Analysis
                  </button>
                  ${hasVirusTotalAnalysis ? `
                    <button class="btn-view" onclick="viewVirusTotalResults('${app.sha256}', '${app.packageName}')" title="View VirusTotal Results">
                      👁️ View Results
                    </button>
                  ` : ""}
                </div>
              </div>

              <!-- Bottom Action Buttons -->
              <div class="bottom-actions">
                <button class="btn-analysis" onclick="window.location.href = getBasePath() + '/results/${app.sha256}'" title="View All Analysis Results">
                  📊 Results
                </button>
                ${app.apkFileName ? `
                  <button class="btn-download" onclick="downloadFile('${app.apkFileName}')">
                    📥 Download APK
                  </button>
                ` : ""}
                <button class="btn-delete-action" onclick="deleteApp('${app.sha256}', '${app.packageName}')" title="Delete App">
                  🗑️ Delete
                </button>
              </div>
            </td>
          </tr>
        `;
      });

      html += `
            </tbody>
          </table>
          </div>
        </div>


      `;
    }

    html += `
        <script>
          // Sidebar toggle
          function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const overlay = document.getElementById('overlay');
            const mainContent = document.getElementById('mainContent');
            
            sidebar.classList.toggle('open');
            overlay.classList.toggle('active');
            mainContent.classList.toggle('shifted');
          }

          // MobSF Status Check
          fetch(window.location.pathname.replace('/apps', '/mobsf/status'))
            .then(response => response.json())
            .then(data => {
              const statusDiv = document.getElementById('mobsf-status');
              if (data.mobsf_connected) {
                statusDiv.textContent = 'MobSF Connected';
                statusDiv.className = 'mobsf-status mobsf-connected';
              } else {
                statusDiv.textContent = 'MobSF Disconnected';
                statusDiv.className = 'mobsf-status mobsf-disconnected';
              }
            })
            .catch(error => {
              const statusDiv = document.getElementById('mobsf-status');
              statusDiv.textContent = 'MobSF Error';
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
          
          function filterAppsByType() {
            const selectedType = document.getElementById('appTypeFilter').value;
            const rows = document.querySelectorAll('table tbody tr');
            
            rows.forEach(row => {
              const appType = row.getAttribute('data-app-type');
              if (selectedType === 'all' || appType === selectedType) {
                row.style.display = '';
              } else {
                row.style.display = 'none';
              }
            });
          }

          function clearTodayData() {
            if (confirm('Are you sure you want to delete all data from today\\'s index? This action cannot be undone.')) {
              fetch(getBasePath() + '/clear-today', { method: 'DELETE' })
                .then(response => response.json())
                .then(data => {
                  if (data.error) {
                    alert('Error: ' + data.error);
                  } else {
                    alert(data.message);
                    location.reload();
                  }
                })
                .catch(error => {
                  alert('Error: ' + error.message);
                });
            }
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
                    alert('MobSF Static Analysis completed successfully!\\nSecurity Score: ' + 
                          (data.analysis ? data.analysis.security_score + '/100' : 'N/A'));
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

          function downloadDynamicReport(sha256) {
            const selectedDate = document.getElementById('date-picker').value;
            const url = getBasePath() + '/dynamic-report/' + sha256 + (selectedDate ? '?date=' + selectedDate : '');
            window.location.href = url;
          }

          function viewDynamicResults(sha256) {
            const selectedDate = document.getElementById('date-picker').value;
            window.location.href = getBasePath() + '/dynamic-results/' + sha256 + (selectedDate ? '?date=' + selectedDate : '');
          }

          function runDynamicAnalysis(sha256, packageName, btnEl) {
            const selectedDate = document.getElementById('date-picker').value;
            const dateParam = selectedDate ? '?date=' + selectedDate : '';
            const waitSec = 60; // default capture window in seconds

            // Build an overlay/modal to show progress steps
            const overlay = document.createElement('div');
            overlay.id = 'dynOverlay_' + sha256;
            overlay.style.cssText = [
              'position:fixed;top:0;left:0;width:100%;height:100%;',
              'background:rgba(0,0,0,0.75);z-index:9999;',
              'display:flex;align-items:center;justify-content:center;'
            ].join('');

            overlay.innerHTML = \`
              <div style="background:#112240;border:1px solid #1d4ed8;border-radius:12px;padding:28px 36px;max-width:520px;width:92%;text-align:center;max-height:90vh;overflow-y:auto;">
                <h2 style="color:#60a5fa;margin:0 0 6px 0;font-size:18px;">⚙️ Dynamic Analysis</h2>
                <p style="color:#94a3b8;font-size:12px;margin:0 0 16px 0;">\${packageName}</p>

                <div id="dynSteps_\${sha256}" style="text-align:left;margin-bottom:16px;font-size:12px;">
                  <div id="dynStep1_\${sha256}"  style="color:#94a3b8;padding:3px 0;">⏳ Getting device identifier from MobSF…</div>
                  <div id="dynStep2_\${sha256}"  style="color:#64748b;padding:3px 0;">⬜ MobSFying the Android emulator…</div>
                  <div id="dynStep3_\${sha256}"  style="color:#64748b;padding:3px 0;">⬜ Installing Root CA (enables HTTPS capture)…</div>
                  <div id="dynStep4_\${sha256}"  style="color:#64748b;padding:3px 0;">⬜ Setting global HTTPS proxy…</div>
                  <div id="dynStep5_\${sha256}"  style="color:#64748b;padding:3px 0;">⬜ Installing &amp; launching app on emulator…</div>
                  <div id="dynStep6_\${sha256}"  style="color:#64748b;padding:3px 0;">⬜ Waiting for app to boot…</div>
                  <div id="dynStep7_\${sha256}"  style="color:#64748b;padding:3px 0;">⬜ Applying Frida hooks (SSL bypass, root bypass, API monitor)…</div>
                  <div id="dynStep8_\${sha256}"  style="color:#64748b;padding:3px 0;">⬜ Running exported activity tester…</div>
                  <div id="dynStep9_\${sha256}"  style="color:#64748b;padding:3px 0;">⬜ Running activity tester…</div>
                  <div id="dynStep10_\${sha256}" style="color:#64748b;padding:3px 0;">⬜ Capturing network traffic &amp; API calls…</div>
                  <div id="dynStep11_\${sha256}" style="color:#64748b;padding:3px 0;">⬜ Collecting Frida API monitor data…</div>
                  <div id="dynStep12_\${sha256}" style="color:#64748b;padding:3px 0;">⬜ Running TLS/SSL security tests…</div>
                  <div id="dynStep13_\${sha256}" style="color:#64748b;padding:3px 0;">⬜ Stopping analysis &amp; finalising capture…</div>
                  <div id="dynStep14_\${sha256}" style="color:#64748b;padding:3px 0;">⬜ Collecting Frida logs…</div>
                  <div id="dynStep15_\${sha256}" style="color:#64748b;padding:3px 0;">⬜ Generating dynamic report…</div>
                  <div id="dynStep16_\${sha256}" style="color:#64748b;padding:3px 0;">⬜ Cleaning up proxy…</div>
                  <div id="dynStep17_\${sha256}" style="color:#64748b;padding:3px 0;">⬜ Saving results to database…</div>
                </div>

                <div id="dynResult_\${sha256}" style="display:none;"></div>

                <div id="dynProgress_\${sha256}" style="width:100%;height:4px;background:#1e293b;border-radius:2px;overflow:hidden;margin-bottom:10px;">
                  <div id="dynBar_\${sha256}" style="height:100%;width:0%;background:#3b82f6;transition:width 0.5s;"></div>
                </div>

                <p style="color:#64748b;font-size:11px;margin:0 0 14px 0;" id="dynTimer_\${sha256}">Elapsed: 0s</p>
                <button id="dynCancelBtn_\${sha256}" onclick="document.getElementById('dynOverlay_\${sha256}').remove();"
                  style="background:#ef4444;color:white;border:none;border-radius:6px;padding:8px 20px;cursor:pointer;font-size:12px;">
                  Close
                </button>
              </div>
            \`;

            document.body.appendChild(overlay);

            // Animate timer
            const timerEl = document.getElementById('dynTimer_' + sha256);
            const barEl = document.getElementById('dynBar_' + sha256);
            const startTs = Date.now();
            // Total expected ~175s for default 60s wait pipeline
            const totalExpected = waitSec + 115;
            const timerInterval = setInterval(() => {
              const elapsed = Math.round((Date.now() - startTs) / 1000);
              if (timerEl) timerEl.textContent = 'Elapsed: ' + elapsed + 's';
              if (barEl) barEl.style.width = Math.min(95, Math.round((elapsed / totalExpected) * 100)) + '%';
            }, 1000);

            function markStep(n, status) {
              const el = document.getElementById('dynStep' + n + '_' + sha256);
              if (!el) return;
              if (status === 'done')   { el.style.color = '#10b981'; el.textContent = el.textContent.replace('⬜','✅').replace('⏳','✅'); }
              else if (status === 'active') { el.style.color = '#f59e0b'; el.textContent = el.textContent.replace('⬜','⏳'); }
              else if (status === 'error')  { el.style.color = '#ef4444'; el.textContent = el.textContent.replace('⬜','❌').replace('⏳','❌'); }
            }

            // Approximate step timing (cumulative seconds)
            const stepTimings = [0,2,8,12,15,30,42,48,65,80, 80+waitSec, 88+waitSec, 95+waitSec, 102+waitSec, 107+waitSec, 113+waitSec, 116+waitSec];
            stepTimings.forEach((t, i) => {
              if (i === 0) { markStep(1, 'active'); return; }
              setTimeout(() => { markStep(i, 'done'); markStep(i + 1, 'active'); }, t * 1000);
            });

            if (btnEl) { btnEl.disabled = true; btnEl.textContent = '⏳ Running…'; }

            fetch(getBasePath() + '/dynamic-analysis/' + sha256 + dateParam, { method: 'POST' })
              .then(response => {
                return response.text().then(text => {
                  try {
                    return { ok: response.ok, status: response.status, data: JSON.parse(text) };
                  } catch (_) {
                    return { ok: false, status: response.status, data: { error: 'Server returned non-JSON response (status ' + response.status + '). Make sure the server is running and try again.' } };
                  }
                });
              })
              .then(({ ok, status, data }) => {
                clearInterval(timerInterval);
                if (barEl) barEl.style.width = '100%';
                // Mark all steps done
                for (let i = 1; i <= 17; i++) markStep(i, data.error ? 'error' : 'done');

                const resultEl = document.getElementById('dynResult_' + sha256);
                if (resultEl) resultEl.style.display = 'block';

                if (data.error) {
                  if (resultEl) resultEl.innerHTML = \`
                    <div style="background:#7f1d1d;border-radius:6px;padding:12px;color:#fca5a5;font-size:12px;margin-bottom:12px;">
                      ❌ Dynamic analysis failed:<br><strong>\${data.error}</strong>
                    </div>\`;
                } else {
                  const da = data.dynamicAnalysis || {};
                  const tls = da.tls_tests || {};
                  if (resultEl) resultEl.innerHTML = \`
                    <div style="background:#052e16;border:1px solid #16a34a;border-radius:6px;padding:12px;color:#4ade80;font-size:12px;margin-bottom:12px;">
                      ✅ Dynamic analysis completed!
                      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px;text-align:left;">
                        <span style="color:#94a3b8;">📱 MobSFy:</span><span style="color:#e2e8f0;">\${da.mobsfy_applied ? '✅' : '⚠️ Skipped'}</span>
                        <span style="color:#94a3b8;">🔐 Root CA:</span><span style="color:#e2e8f0;">\${da.root_ca_installed ? '✅ Installed' : '⚠️ Skipped'}</span>
                        <span style="color:#94a3b8;">🌐 Proxy:</span><span style="color:#e2e8f0;">\${da.proxy_set ? '✅ Set' : '⚠️ Skipped'}</span>
                        <span style="color:#94a3b8;">🪝 Frida:</span><span style="color:#e2e8f0;">\${da.frida_applied ? '✅ Applied' : '⚠️ N/A'}</span>
                        <span style="color:#94a3b8;">🏃 Activities:</span><span style="color:#e2e8f0;">\${da.exported_activities || 0} exported</span>
                        <span style="color:#94a3b8;">🌍 Domains:</span><span style="color:#e2e8f0;">\${da.domains_count || 0}</span>
                        <span style="color:#94a3b8;">📡 URLs:</span><span style="color:#e2e8f0;">\${da.urls_found || 0}</span>
                        <span style="color:#94a3b8;">🕵️ Trackers:</span><span style="color:#e2e8f0;">\${da.trackers || 0}</span>
                        <span style="color:#94a3b8;">⚠️ Net issues:</span><span style="color:#e2e8f0;">\${da.network_security_issues || 0}</span>
                        \${tls.tls_misconfigured !== undefined ? \`<span style="color:#94a3b8;">🔒 TLS:</span><span style="color:\${tls.tls_misconfigured ? '#ef4444' : '#10b981'}">\${tls.tls_misconfigured ? '⚠️ Misconfigured' : '✅ OK'}</span>\` : ''}
                      </div>
                    </div>
                    <button onclick="downloadDynamicReport('\${sha256}')"
                      style="background:#2563eb;color:white;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-size:12px;margin-bottom:8px;width:100%;">
                      📄 Download Dynamic Analysis PDF
                    </button>\`;
                }

                if (btnEl) {
                  btnEl.disabled = false;
                  btnEl.textContent = 'Re-run Dynamic Analysis';
                }

                const cancelBtn = document.getElementById('dynCancelBtn_' + sha256);
                if (cancelBtn) {
                  cancelBtn.textContent = 'Close & Refresh';
                  cancelBtn.onclick = () => {
                    document.getElementById('dynOverlay_' + sha256)?.remove();
                    location.reload();
                  };
                }
              })
              .catch(err => {
                clearInterval(timerInterval);
                const resultEl = document.getElementById('dynResult_' + sha256);
                if (resultEl) {
                  resultEl.style.display = 'block';
                  resultEl.innerHTML = \`
                    <div style="background:#7f1d1d;border-radius:6px;padding:12px;color:#fca5a5;font-size:12px;margin-bottom:12px;">
                      ❌ Network error: \${err.message}
                    </div>\`;
                }
                if (btnEl) { btnEl.disabled = false; btnEl.textContent = 'Do Dynamic Analysis'; }
                for (let i = 13; i <= 17; i++) markStep(i, 'error');
              });
          }
          
          function viewVirusTotalResults(sha256, packageName) {
            const selectedDate = document.getElementById('date-picker').value;
            window.location.href = getBasePath() + '/virustotal-results/' + sha256 + (selectedDate ? '?date=' + selectedDate : '');
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

          // Run Weighted Algorithm
          function runAlgorithm(sha256) {
            const loading = document.getElementById('algorithmLoading');
            const results = document.getElementById('algorithmResults');
            const btn = document.getElementById('runAlgorithmBtn');

            loading.style.display = 'block';
            results.style.display = 'none';
            btn.disabled = true;
            btn.style.opacity = '0.5';

            fetch('/uploadapp/run-algorithm/' + sha256, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' }
            })
            .then(response => response.json())
            .then(data => {
              if (data.success) {
                const algo = data.algorithmResult;
                
                // Update summary metrics
                document.getElementById('finalScore').textContent = algo.finalScore.toFixed(2);
                document.getElementById('finalScore').style.color = 
                  algo.finalScore < 35 ? '#10b981' : algo.finalScore < 60 ? '#f59e0b' : '#ef4444';
                
                document.getElementById('finalStatus').textContent = algo.finalStatus;
                document.getElementById('finalStatus').style.color = 
                  algo.finalStatus === 'SAFE' ? '#10b981' : algo.finalStatus === 'SUSPICIOUS' ? '#f59e0b' : '#ef4444';
                
                document.getElementById('confidence').textContent = algo.confidence + '%';
                document.getElementById('dataSources').textContent = algo.dataSourcesCount + '/4';

                // Build breakdown table
                const breakdownTable = document.getElementById('breakdownTable');
                breakdownTable.innerHTML = '';
                const sources = algo.breakdown.sources;
                for (const [key, value] of Object.entries(sources)) {
                  if (value !== null) {
                    const scoreItem = document.createElement('div');
                    scoreItem.style.cssText = 'background: rgba(10, 25, 47, 0.8); border: 1px solid #1e293b; border-radius: 6px; padding: 10px; text-align: center;';
                    scoreItem.innerHTML = \`<div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-bottom: 5px;">\${key.replace('_', ' ')}</div><div style="font-size: 18px; font-weight: 700; color: #60a5fa;">\${value.toFixed(2)}</div>\`;
                    breakdownTable.appendChild(scoreItem);
                  }
                }

                // Build weights table
                const weightsTable = document.getElementById('weightsTable');
                weightsTable.innerHTML = '';
                const weights = algo.breakdown.weights;
                for (const [key, value] of Object.entries(weights)) {
                  if (value > 0) {
                    const weightItem = document.createElement('div');
                    weightItem.style.cssText = 'background: rgba(10, 25, 47, 0.8); border: 1px solid #1e293b; border-radius: 6px; padding: 10px; text-align: center;';
                    weightItem.innerHTML = \`<div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; margin-bottom: 5px;">\${key.replace('_', ' ')}</div><div style="font-size: 18px; font-weight: 700; color: #8b5cf6;">\${(value * 100).toFixed(0)}%</div>\`;
                    weightsTable.appendChild(weightItem);
                  }
                }

                loading.style.display = 'none';
                results.style.display = 'block';
              } else {
                alert('Error: ' + (data.error || 'Unknown error'));
                loading.style.display = 'none';
              }
              btn.disabled = false;
              btn.style.opacity = '1';
            })
            .catch(error => {
              alert('Error: ' + error.message);
              loading.style.display = 'none';
              btn.disabled = false;
              btn.style.opacity = '1';
            });
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
      <body style="background: #0a192f; color: white; font-family: Arial; text-align: center; padding: 50px;">
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
          sandboxStatus: "sandbox_submitted",
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

// POST /update-remarks/:sha256 - Update SOC Analyst remarks - REQUIRES WEB AUTH
router.post("/update-remarks/:sha256", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { sha256 } = req.params;
  const { socRemarks, status, remarksTimestamp } = req.body;

  try {
    const dynamicIndex = getDynamicIndexName();
    const searchRes = await esClient.search({
      index: dynamicIndex,
      body: {
        query: { term: { sha256: sha256 } },
      },
    });

    if (!searchRes.hits.hits.length) {
      return res.status(404).json({ error: "App not found" });
    }

    const docId = searchRes.hits.hits[0]._id;

    const updateBody = {
      socRemarks: socRemarks,
      remarksTimestamp: remarksTimestamp,
      remarksBy: req.session.username || 'Unknown Analyst'
    };

    if (status) {
      updateBody.status = status;
    }

    await esClient.update({
      index: dynamicIndex,
      id: docId,
      body: {
        doc: updateBody,
      },
    });

    console.log(`✅ SOC remarks added for ${sha256} by ${req.session.username}`);
    res.json({ success: true, message: "Remarks updated successfully" });
  } catch (err) {
    console.error(`Failed to update remarks for ${sha256}:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// NEW ENDPOINT: POST /update-final-decision/:sha256 - SOC Analyst Final Decision
router.post("/update-final-decision/:sha256", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { sha256 } = req.params;
  const { finalStatus, socRemarks, decisionTimestamp } = req.body;

  try {
    // Validate inputs
    if (!finalStatus || !['safe', 'suspicious', 'malicious'].includes(finalStatus)) {
      return res.status(400).json({ error: "Invalid final status" });
    }

    if (!socRemarks || socRemarks.trim().length === 0) {
      return res.status(400).json({ error: "Remarks are required" });
    }

    const dynamicIndex = getDynamicIndexName();
    const searchRes = await esClient.search({
      index: dynamicIndex,
      body: {
        query: { term: { sha256: sha256 } },
      },
    });

    if (!searchRes.hits.hits.length) {
      return res.status(404).json({ error: "App not found" });
    }

    const docId = searchRes.hits.hits[0]._id;
    const analyst = req.session.username || 'Unknown Analyst';

    // Update database with final decision
    const updateBody = {
      finalDecision: {
        status: finalStatus,
        remarks: socRemarks,
        decidedBy: analyst,
        decidedAt: decisionTimestamp || new Date().toISOString()
      },
      status: finalStatus, // Also update main status field for sorting/filtering
      lastUpdatedBy: analyst,
      lastUpdated: new Date().toISOString()
    };

    await esClient.update({
      index: dynamicIndex,
      id: docId,
      body: {
        doc: updateBody,
      },
    });

    console.log(`✅ Final decision saved for ${sha256} by ${analyst} - Status: ${finalStatus}`);
    res.json({ 
      success: true, 
      message: `Final decision saved successfully. App marked as ${finalStatus.toUpperCase()}.`
    });
  } catch (err) {
    console.error(`Failed to save final decision for ${sha256}:`, err.message);
    res.status(500).json({ error: err.message });
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

// DELETE /clear-today - Clear all data from today's index - REQUIRES WEB AUTH
router.delete("/clear-today", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  
  try {
    const dynamicIndex = getDynamicIndexName();
    console.log(`🗑️ Clearing all data from index: ${dynamicIndex}`);
    
    // Delete all documents from today's index
    const deleteResult = await esClient.deleteByQuery({
      index: dynamicIndex,
      body: {
        query: {
          match_all: {}
        }
      },
      refresh: true
    });
    
    console.log(`✅ Deleted ${deleteResult.deleted} documents from ${dynamicIndex}`);
    res.json({ 
      success: true, 
      message: `Successfully deleted ${deleteResult.deleted} apps from today's index`,
      deleted: deleteResult.deleted
    });
  } catch (err) {
    console.error("Failed to clear today's data:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /run-algorithm/:sha256 - Run weighted risk algorithm - REQUIRES WEB AUTH
router.post("/run-algorithm/:sha256", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { sha256 } = req.params;
  
  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);
    
    // Fetch app data from database
    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).json({ error: "App not found" });
    }

    const app = searchRes.hits.hits[0]._source;
    const docId = searchRes.hits.hits[0]._id;

    // Calculate weighted risk score
    const algorithmResult = calculateWeightedRiskScore(app);

    // Save result to database
    try {
      await esClient.update({
        index: indexName,
        id: docId,
        body: {
          doc: {
            algorithmResult: algorithmResult,
            algorithmRunAt: new Date().toISOString()
          }
        }
      });
      console.log(`✅ Algorithm result saved for ${app.packageName}`);
    } catch (updateErr) {
      console.log(`⚠️ Could not save algorithm result: ${updateErr.message}`);
    }

    res.json({
      success: true,
      algorithmResult: algorithmResult,
      appName: app.appName,
      packageName: app.packageName
    });
  } catch (err) {
    console.error(`Failed to run algorithm for ${sha256}:`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Dynamic Analysis Routes ──────────────────────────────────────────────────

// POST /dynamic-analysis/:sha256
// Full automated dynamic analysis pipeline:
//   start_analysis → frida hooks → tls_tests → wait → stop_analysis → report_json → save to ES
router.post("/dynamic-analysis/:sha256", async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;
  const waitSeconds = parseInt(req.query.wait || req.body?.wait || "45", 10);

  console.log(`[Dynamic Analysis] Starting pipeline for SHA256: ${sha256}`);

  try {
    // 1. Find app in ES to get the mobsfHash (MD5) from the static scan
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);

    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).json({ error: "App not found in database" });
    }

    const docId = searchRes.hits.hits[0]._id;
    const appData = searchRes.hits.hits[0]._source;
    const md5Hash = appData.mobsfHash;

    if (!md5Hash) {
      return res.status(400).json({
        error: "Static analysis must be completed first before running dynamic analysis. Please click 'Do Static Analysis' or 'Re-analyze Analysis' first.",
      });
    }

    console.log(`[Dynamic Analysis] Using MD5 hash: ${md5Hash} for app: ${appData.packageName}`);

    // 2. Mark as running in ES
    await esClient.update({
      index: indexName,
      id: docId,
      body: { doc: { dynamicAnalysisStatus: "running", dynamicAnalysisStarted: new Date().toISOString() } },
    });

    // 3. Run full pipeline
    const pipelineResult = await mobsf.runFullDynamicAnalysis(md5Hash, waitSeconds);

    const dynReport = pipelineResult.dynamicReport || {};

    // 4. Extract key findings from dynamic report
    const networkFindings = dynReport.network_security || dynReport.exported_activities || [];
    const browsableActivities = dynReport.browsable_activities || [];
    const trackers = dynReport.trackers || {};
    const domains = dynReport.domains || {};
    const emails = dynReport.emails || [];
    const urls = dynReport.urls || [];
    // TLS: prefer dedicated call result, fallback to dynamic report JSON fields
    // MobSF may store TLS data under several different keys depending on version
    const tlsRaw = pipelineResult.tlsResult;
    const hasTlsDirect = tlsRaw && typeof tlsRaw === 'object' && Object.keys(tlsRaw).length > 0;
    const tlsFromReport = dynReport.tls_tests || dynReport.ssl_tests || dynReport.tls ||
      dynReport.tls_data || dynReport.network_security?.tls || null;
    const tlsFinal = hasTlsDirect ? tlsRaw : (tlsFromReport || null);
    console.log('[Dynamic] tlsResult from dedicated call:', JSON.stringify(tlsRaw));
    console.log('[Dynamic] tls from dynReport:', JSON.stringify(tlsFromReport));
    console.log('[Dynamic] tlsFinal saved:', JSON.stringify(tlsFinal));

    // Extract network/security findings
    const networkSecurityIssues = dynReport.network_security || [];
    const openRedirects = dynReport.open_redirect || [];
    const exportedActivities = dynReport.activities || [];

    // Extract API monitor data
    const apiMonitorData = pipelineResult.apiMonitorData || null;
    const fridaLogs = pipelineResult.fridaLogs || null;

    const dynamicAnalysis = {
      status: "completed",
      completedAt: new Date().toISOString(),
      wait_seconds: waitSeconds,
      device_identifier: pipelineResult.deviceIdentifier || null,
      // MobSFy & environment setup
      mobsfy_applied: !!pipelineResult.mobsfyResult,
      root_ca_installed: !!pipelineResult.rootCAResult,
      proxy_set: !!pipelineResult.proxyResult,
      // Runtime analysis results
      frida_applied: !!pipelineResult.fridaResult,
      activity_tester_exported: !!pipelineResult.activityExportedResult,
      activity_tester_run: !!pipelineResult.activityResult,
      tls_tests: tlsFinal,
      // Traffic & behaviour
      network_security_issues: Array.isArray(networkSecurityIssues) ? networkSecurityIssues.length : 0,
      browsable_activities: Array.isArray(browsableActivities) ? browsableActivities.length : 0,
      trackers: typeof trackers === "object" ? Object.keys(trackers).length : 0,
      domains_count: typeof domains === "object" ? Object.keys(domains).length : 0,
      emails_found: Array.isArray(emails) ? emails.length : 0,
      urls_found: Array.isArray(urls) ? urls.length : 0,
      open_redirects: Array.isArray(openRedirects) ? openRedirects.length : 0,
      exported_activities: Array.isArray(exportedActivities) ? exportedActivities.length : 0,
      // Raw data
      api_monitor: apiMonitorData,
      frida_logs: fridaLogs,
      raw_report: dynReport,
    };

    // 5. Persist results in ES
    await esClient.update({
      index: indexName,
      id: docId,
      body: {
        doc: {
          dynamicAnalysis,
          dynamicAnalysisStatus: "completed",
          lastDynamicAnalysis: new Date().toISOString(),
        },
      },
    });

    console.log(`[Dynamic Analysis] Pipeline complete for ${appData.packageName}`);
    res.json({ success: true, dynamicAnalysis, mobsfHash: md5Hash });
  } catch (err) {
    console.error(`[Dynamic Analysis] Pipeline failed for ${sha256}:`, err.message);

    // Try to mark failure in ES
    try {
      const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
      const indexName = getIndexNameForDate(selectedDate);
      const searchRes = await esClient.search({
        index: indexName,
        size: 1,
        query: { term: { sha256: { value: sha256 } } },
      });
      if (searchRes.hits.hits.length > 0) {
        const docId = searchRes.hits.hits[0]._id;
        await esClient.update({
          index: indexName,
          id: docId,
          body: {
            doc: {
              dynamicAnalysisStatus: "failed",
              dynamicAnalysisError: err.message,
              lastDynamicAnalysis: new Date().toISOString(),
            },
          },
        });
      }
    } catch (_) {}

    res.status(500).json({ error: err.message });
  }
});

// GET /dynamic-report/:sha256 - Download dynamic analysis PDF (uses same MobSF PDF endpoint after dynamic run)
router.get("/dynamic-report/:sha256", async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;

  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);

    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).send("App not found");
    }

    const appData = searchRes.hits.hits[0]._source;
    const md5Hash = appData.mobsfHash;

    if (!md5Hash) {
      return res.status(400).send("No MobSF analysis available for this app");
    }

    if (!appData.dynamicAnalysis || appData.dynamicAnalysis.status !== "completed") {
      return res.status(400).send("Dynamic analysis has not been completed for this app yet");
    }

    console.log(`[Dynamic PDF] Fetching PDF for MD5: ${md5Hash}`);
    const pdfStream = await mobsf.getPdfReport(md5Hash);

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="dynamic_report_${sha256.substring(0, 8)}.pdf"`);

    pdfStream.pipe(res);
    pdfStream.on("error", (error) => {
      console.error(`[Dynamic PDF] Stream error:`, error);
      if (!res.headersSent) res.status(500).send("Error generating dynamic PDF report");
    });
  } catch (err) {
    console.error("[Dynamic PDF] Failed:", err.message);
    if (!res.headersSent) res.status(500).send("Failed to get dynamic PDF report: " + err.message);
  }
});

// GET /dynamic-results/:sha256 - View dynamic analysis results as HTML page
router.get("/dynamic-results/:sha256", async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;

  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);

    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).send('<html><body style="background:#0a192f;color:white;font-family:Arial;text-align:center;padding:50px"><h1>App not found</h1><a href="/uploadapp/apps" style="color:#60a5fa">← Back</a></body></html>');
    }

    const appData = searchRes.hits.hits[0]._source;
    const da = appData.dynamicAnalysis;

    if (!da || da.status !== 'completed') {
      return res.status(400).send('<html><body style="background:#0a192f;color:white;font-family:Arial;text-align:center;padding:50px"><h1>⚠️ Dynamic analysis not completed yet</h1><a href="/uploadapp/apps" style="color:#60a5fa">← Back</a></body></html>');
    }

    const raw = da.raw_report || {};
    // TLS: check all possible locations MobSF might store it
    const tlsRaw = da.tls_tests || raw.tls_tests || raw.tls || raw.tls_data ||
      (raw.network_security?.tls) || null;

    // Normalise into a consistent {_tests:[]} or flat object
    // MobSF formats seen:
    //  A) Array directly: [{name, result}, ...]
    //  B) {status, tls_tests:[{name,result},...]}  ← wrapper with nested array
    //  C) {tests:[{name,result},...]}
    //  D) Flat: {has_cleartext, tls_misconfigured, no_tls_pin_or_transparency, pin_or_transparency_bypassed}
    let tls = {};
    const mapTests = (arr) => {
      const out = { _tests: arr };
      for (const t of arr) {
        const name = (t.name || t.test || '').toLowerCase();
        if (name.includes('cleartext'))                                   out.has_cleartext = !t.result;
        if (name.includes('misconfigur'))                                 out.tls_misconfigured = !t.result;
        if (name.includes('bypass'))                                      out.pin_or_transparency_bypassed = !t.result;
        if (name.includes('pinning') && !name.includes('bypass'))        out.no_tls_pin_or_transparency = !t.result;
        if (name.includes('transparency') && !name.includes('bypass'))   out.no_tls_pin_or_transparency = !t.result;
      }
      return out;
    };
    if (Array.isArray(tlsRaw)) {
      // Format A: direct array
      tls = mapTests(tlsRaw);
    } else if (tlsRaw && typeof tlsRaw === 'object') {
      if (Array.isArray(tlsRaw.tls_tests)) {
        // Format B: {status, tls_tests:[...]}
        tls = mapTests(tlsRaw.tls_tests);
      } else if (tlsRaw.tls_tests && typeof tlsRaw.tls_tests === 'object') {
        // Format E: {status, tls_tests:{has_cleartext,...}} — flat nested
        tls = tlsRaw.tls_tests;
      } else if (Array.isArray(tlsRaw.tests)) {
        // Format C: {tests:[...]}
        tls = mapTests(tlsRaw.tests);
      } else if ('has_cleartext' in tlsRaw || 'tls_misconfigured' in tlsRaw) {
        // Format D: flat top-level
        tls = tlsRaw;
      }
    }

    // Build network activity table from raw report
    const networkData = raw.network_data || raw.network || [];
    const activityData = raw.activities_tested || raw.activities || [];
    const apiCalls = da.api_monitor ? (Array.isArray(da.api_monitor) ? da.api_monitor : [da.api_monitor]) : [];
    const fridaLogs = da.frida_logs || null;
    const domains = raw.domains || {};
    const urls = raw.urls || [];
    const trackers = raw.trackers || {};
    const openRedirects = raw.open_redirect || [];
    const exportedExploitable = raw.exported_activities_exploitable || [];

    const domainList = typeof domains === 'object' ? Object.entries(domains) : [];
    const trackerList = typeof trackers === 'object' ? Object.keys(trackers) : [];

    const statusColor = (v) => v ? '#ef4444' : '#10b981';
    const boolBadge = (v, trueLabel = 'YES', falseLabel = 'NO') =>
      `<span style="background:${v ? '#7f1d1d' : '#052e16'};color:${v ? '#fca5a5' : '#4ade80'};padding:2px 8px;border-radius:4px;font-size:11px;">${v ? trueLabel : falseLabel}</span>`;

    const html = `<!DOCTYPE html>
<html>
<head>
  <title>Dynamic Analysis Results – ${appData.packageName || sha256}</title>
  <meta charset="utf-8">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0a192f;color:#cbd5e1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:20px;min-height:100vh}
    .container{max-width:1100px;margin:0 auto}
    .back{display:inline-block;margin-bottom:16px;padding:7px 14px;background:#1d4ed8;color:white;text-decoration:none;border-radius:6px;font-size:13px}
    .back:hover{background:#1e40af}
    h1{color:#e2e8f0;font-size:22px;margin-bottom:4px}
    .subtitle{color:#64748b;font-size:13px;margin-bottom:20px}
    .section{background:#112240;border:1px solid #1e3a5f;border-radius:8px;padding:16px;margin-bottom:16px}
    .section h2{color:#60a5fa;font-size:14px;font-weight:600;margin-bottom:12px;text-transform:uppercase;letter-spacing:.05em}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}
    .card{background:#0a192f;border:1px solid #1e293b;border-radius:6px;padding:12px;text-align:center}
    .card-label{font-size:11px;color:#64748b;text-transform:uppercase;margin-bottom:6px}
    .card-val{font-size:22px;font-weight:700;color:#60a5fa}
    .card-val.red{color:#ef4444}
    .card-val.green{color:#10b981}
    .card-val.yellow{color:#f59e0b}
    table{width:100%;border-collapse:collapse;font-size:12px}
    th{background:#0d2137;color:#94a3b8;padding:8px;text-align:left;font-weight:600;border-bottom:1px solid #1e293b}
    td{padding:7px 8px;border-bottom:1px solid #0d2137;vertical-align:top;word-break:break-all}
    tr:hover td{background:rgba(30,58,95,0.3)}
    .badge{padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600}
    .badge-red{background:#7f1d1d;color:#fca5a5}
    .badge-green{background:#052e16;color:#4ade80}
    .badge-yellow{background:#451a03;color:#fcd34d}
    .badge-blue{background:#1e3a8a;color:#93c5fd}
    .empty{color:#475569;font-size:12px;padding:8px 0}
    .dl-btn{display:inline-block;margin-top:12px;padding:8px 18px;background:#2563eb;color:white;text-decoration:none;border-radius:6px;font-size:13px;border:none;cursor:pointer}
    .dl-btn:hover{background:#1d4ed8}
    pre{background:#0d2137;padding:10px;border-radius:4px;font-size:11px;overflow-x:auto;max-height:200px;overflow-y:auto;color:#94a3b8}
  </style>
</head>
<body>
<div class="container">
  <a class="back" href="/uploadapp/apps?date=${selectedDate}">← Back to Apps</a>
  <h1>🔍 Dynamic Analysis Results</h1>
  <p class="subtitle">${appData.appName || 'Unknown'} &nbsp;·&nbsp; ${appData.packageName || sha256} &nbsp;·&nbsp; Completed: ${new Date(da.completedAt).toLocaleString()}</p>

  <!-- Environment Setup -->
  <div class="section">
    <h2>⚙️ Environment Setup</h2>
    <div class="grid">
      <div class="card"><div class="card-label">MobSFy Applied</div><div class="card-val ${da.mobsfy_applied ? 'green' : 'yellow'}">${da.mobsfy_applied ? '✅' : '⚠️'}</div></div>
      <div class="card"><div class="card-label">Root CA Installed</div><div class="card-val ${da.root_ca_installed ? 'green' : 'yellow'}">${da.root_ca_installed ? '✅' : '⚠️'}</div></div>
      <div class="card"><div class="card-label">HTTPS Proxy</div><div class="card-val ${da.proxy_set ? 'green' : 'yellow'}">${da.proxy_set ? '✅ Set' : '⚠️'}</div></div>
      <div class="card"><div class="card-label">Frida Hooks</div><div class="card-val ${da.frida_applied ? 'green' : 'yellow'}">${da.frida_applied ? '✅' : '⚠️'}</div></div>
      <div class="card"><div class="card-label">Activity Tester</div><div class="card-val ${da.activity_tester_run ? 'green' : 'yellow'}">${da.activity_tester_run ? '✅' : '⚠️'}</div></div>
      <div class="card"><div class="card-label">Device</div><div class="card-val" style="font-size:12px;color:#94a3b8">${da.device_identifier || 'N/A'}</div></div>
    </div>
  </div>

  <!-- TLS/SSL Tests -->
  <div class="section">
    <h2>🔒 TLS / SSL Security Tests</h2>
    ${
      Object.keys(tls).filter(k => k !== '_tests').length === 0
      ? '<p class="empty">TLS test data not available. Re-run dynamic analysis to capture TLS results.</p>'
      : (() => {
          // If we have the raw tests array, render as table
          if (tls._tests && tls._tests.length > 0) {
            return `<table>
              <tr><th>Test</th><th>Result</th></tr>
              ${tls._tests.map(t => `<tr><td>${t.name || t.test || JSON.stringify(t)}</td><td><span class="badge ${t.result ? 'badge-green' : 'badge-red'}">${t.result ? '✅ PASS' : '❌ FAIL'}</span></td></tr>`).join('')}
            </table>`;
          }
          // Otherwise render as cards
          return `<div class="grid">
            <div class="card"><div class="card-label">TLS Misconfigured</div><div class="card-val ${tls.tls_misconfigured ? 'red' : 'green'}">${boolBadge(tls.tls_misconfigured, 'YES ⚠️', 'NO ✅')}</div></div>
            <div class="card"><div class="card-label">No TLS Pinning</div><div class="card-val">${boolBadge(tls.no_tls_pin_or_transparency, 'Yes ⚠️', 'No ✅')}</div></div>
            <div class="card"><div class="card-label">Pinning Bypassed</div><div class="card-val">${boolBadge(tls.pin_or_transparency_bypassed, 'Yes ⚠️', 'No ✅')}</div></div>
            <div class="card"><div class="card-label">Cleartext Traffic</div><div class="card-val ${tls.has_cleartext ? 'red' : 'green'}">${boolBadge(tls.has_cleartext, 'YES ⚠️', 'NO ✅')}</div></div>
          </div>`;
        })()
    }
  </div>

  <!-- Traffic Summary -->
  <div class="section">
    <h2>📊 Traffic & Behaviour Summary</h2>
    <div class="grid">
      <div class="card"><div class="card-label">Domains Contacted</div><div class="card-val ${da.domains_count > 0 ? 'yellow' : 'green'}">${da.domains_count || 0}</div></div>
      <div class="card"><div class="card-label">URLs Found</div><div class="card-val">${da.urls_found || 0}</div></div>
      <div class="card"><div class="card-label">Trackers</div><div class="card-val ${da.trackers > 0 ? 'red' : 'green'}">${da.trackers || 0}</div></div>
      <div class="card"><div class="card-label">Network Issues</div><div class="card-val ${da.network_security_issues > 0 ? 'red' : 'green'}">${da.network_security_issues || 0}</div></div>
      <div class="card"><div class="card-label">Open Redirects</div><div class="card-val ${da.open_redirects > 0 ? 'red' : 'green'}">${da.open_redirects || 0}</div></div>
      <div class="card"><div class="card-label">Exported Activities</div><div class="card-val">${da.exported_activities || 0}</div></div>
    </div>
  </div>

  <!-- Domains -->
  ${domainList.length > 0 ? `
  <div class="section">
    <h2>🌍 Domains Contacted (${domainList.length})</h2>
    <table>
      <tr><th>Domain</th><th>Status</th><th>Geolocation</th><th>Flag</th></tr>
      ${domainList.slice(0, 100).map(([domain, info]) => {
        const flagged = info?.bad === true;
        const country = info?.geolocation?.country_long || info?.country || '';
        const status = info?.status || '';
        return `<tr>
          <td>${domain}</td>
          <td><span class="badge ${flagged ? 'badge-red' : 'badge-green'}">${flagged ? '⚠️ Flagged' : '✅ Clean'}</span></td>
          <td>${country}</td>
          <td>${status}</td>
        </tr>`;
      }).join('')}
    </table>
  </div>` : ''}

  <!-- Trackers -->
  ${trackerList.length > 0 ? `
  <div class="section">
    <h2>🕵️ Trackers Detected (${trackerList.length})</h2>
    <div style="display:flex;flex-wrap:wrap;gap:8px">
      ${trackerList.map(t => `<span class="badge badge-red">${t}</span>`).join('')}
    </div>
  </div>` : ''}

  <!-- Network Activity -->
  ${networkData.length > 0 ? `
  <div class="section">
    <h2>📡 Network Activity (${networkData.length})</h2>
    <table>
      <tr><th>Issue / Finding</th><th>Description</th></tr>
      ${networkData.slice(0, 50).map(n => {
        const title = n.title || n.issue || JSON.stringify(n).substring(0,80);
        const desc = n.description || n.details || '';
        return `<tr><td>${title}</td><td>${desc}</td></tr>`;
      }).join('')}
    </table>
  </div>` : ''}

  <!-- Exported Exploitable Activities -->
  ${exportedExploitable.length > 0 ? `
  <div class="section">
    <h2>⚠️ Exported / Exploitable Activities (${exportedExploitable.length})</h2>
    <table>
      <tr><th>Activity</th><th>Details</th></tr>
      ${exportedExploitable.slice(0, 50).map(a => {
        const name = typeof a === 'string' ? a : (a.activity || a.name || JSON.stringify(a).substring(0,60));
        const det = typeof a === 'object' ? (a.details || '') : '';
        return `<tr><td>${name}</td><td>${det}</td></tr>`;
      }).join('')}
    </table>
  </div>` : ''}

  <!-- Frida API Monitor -->
  ${apiCalls.length > 0 ? `
  <div class="section">
    <h2>🪝 Frida API Monitor Calls</h2>
    <pre>${JSON.stringify(apiCalls, null, 2).substring(0, 3000)}</pre>
  </div>` : ''}

  <!-- Frida Logs -->
  ${fridaLogs ? `
  <div class="section">
    <h2>📝 Frida Logs</h2>
    <pre>${typeof fridaLogs === 'string' ? fridaLogs.substring(0,3000) : JSON.stringify(fridaLogs, null, 2).substring(0,3000)}</pre>
  </div>` : ''}

  <!-- Download Button -->
  <div style="text-align:center;margin:20px 0">
    <a class="dl-btn" href="/uploadapp/dynamic-report/${sha256}?date=${selectedDate}">📄 Download Full Dynamic Analysis PDF</a>
  </div>
</div>
</body>
</html>`;

    res.send(html);
  } catch (err) {
    console.error("[Dynamic Results] Error:", err.message);
    res.status(500).send(`<html><body style="background:#0a192f;color:white;font-family:Arial;padding:40px"><h1>Error</h1><p>${err.message}</p></body></html>`);
  }
});

// GET /dynamic-status/:sha256 - Get dynamic analysis status (for frontend polling)
router.get("/dynamic-status/:sha256", async (req, res) => {
  const esClient = req.app.get("esClient");
  const sha256 = req.params.sha256;

  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);

    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).json({ error: "App not found" });
    }

    const appData = searchRes.hits.hits[0]._source;
    res.json({
      dynamicAnalysisStatus: appData.dynamicAnalysisStatus || "not_started",
      dynamicAnalysis: appData.dynamicAnalysis || null,
      lastDynamicAnalysis: appData.lastDynamicAnalysis || null,
      hasDynamicAnalysis: !!(appData.dynamicAnalysis && appData.dynamicAnalysis.status === "completed"),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /scan - Original scan endpoint (backward compatibility) - NO AUTH REQUIRED
router.post("/scan", receiveAppData);

module.exports = router;


