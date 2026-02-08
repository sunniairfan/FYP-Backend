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
              body { background: #0d1b2a; color: white; font-family: Arial; text-align: center; padding: 50px; }
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
              body { background: #0d1b2a; color: white; font-family: Arial; text-align: center; padding: 50px; }
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
            background: #0a192f;
            border: 1px solid #1d3557;
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
            background: linear-gradient(135deg, #415a77, #778da9);
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
            body { background: #0d1b2a; color: white; font-family: Arial; text-align: center; padding: 50px; }
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
            background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
            border-radius: 8px;
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
            background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
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
            padding: 12px 15px;
            text-align: left;
            color: #94a3b8;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #1d3557;
          }

          td {
            padding: 15px;
            border-bottom: 1px solid #1d3557;
            color: #cbd5e1;
            font-size: 13px;
          }

          tr:last-child td {
            border-bottom: none;
          }

          tr:hover {
            background: #1d3557;
          }

          .file-info {
            font-size: 12px;
            color: #94a3b8;
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
            min-width: 200px;
          }

          button {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 11px;
            font-weight: 500;
            transition: all 0.2s;
            margin: 2px;
            width: 130px;
            white-space: nowrap;
          }

          .btn-mobsf, .btn-report, .btn-view, .btn-sandbox, .btn-vt, .btn-download {
            background: #2563eb;
            color: white;
            flex: 0 0 auto;
          }

          .btn-remarks {
            background: #059669;
            color: white;
            flex: 0 0 auto;
          }

          .btn-remarks:hover {
            background: #047857;
          }

          .btn-mobsf:hover, .btn-report:hover, .btn-view:hover, .btn-sandbox:hover, .btn-vt:hover, .btn-download:hover {
            background: #1d4ed8;
          }

          .btn-delete {
            width: 28px;
            height: 28px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #7f1d1d;
            color: #ef4444;
            padding: 0;
            border-radius: 5px;
            position: absolute;
            right: 10px;
            bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
          }

          .btn-delete:hover {
            background: #7f1d1d;
            color: white;
          }

          .btn-delete i {
            font-size: 12px;
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
            font-size: 11px;
            color: #60a5fa;
            margin-top: 4px;
          }

          .security-score {
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            display: inline-block;
            margin-top: 2px;
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

          /* SOC Remarks Modal */
          .modal {
            display: none;
            position: fixed;
            z-index: 10000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            align-items: center;
            justify-content: center;
          }

          .modal.active {
            display: flex;
          }

          .modal-content {
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 8px;
            padding: 30px;
            width: 90%;
            max-width: 600px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
          }

          .modal-header {
            color: #e2e8f0;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 20px;
          }

          .modal-body {
            margin-bottom: 20px;
          }

          .form-group {
            margin-bottom: 15px;
          }

          .form-group label {
            display: block;
            color: #94a3b8;
            font-size: 13px;
            margin-bottom: 8px;
            font-weight: 500;
          }

          .form-group textarea {
            width: 100%;
            background: #0a192f;
            border: 1px solid #1d3557;
            border-radius: 6px;
            padding: 12px;
            color: #e2e8f0;
            font-size: 13px;
            font-family: inherit;
            resize: vertical;
            min-height: 120px;
          }

          .form-group textarea:focus {
            outline: none;
            border-color: #2563eb;
          }

          .form-group select {
            width: 100%;
            background: #0a192f;
            border: 1px solid #1d3557;
            border-radius: 6px;
            padding: 10px;
            color: #e2e8f0;
            font-size: 13px;
          }

          .form-group select:focus {
            outline: none;
            border-color: #2563eb;
          }

          .modal-footer {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
          }

          .btn-modal {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.2s;
          }

          .btn-submit {
            background: #2563eb;
            color: white;
          }

          .btn-submit:hover {
            background: #1d4ed8;
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
              ${app.source ? `<div class="file-info">Source: ${app.source}</div>` : ""}
              ${app.lastMobsfAnalysis ? `<div class="file-info">MobSF: ${new Date(app.lastMobsfAnalysis).toLocaleDateString()}</div>` : ""}
              ${app.lastVirusTotalAnalysis ? `<div class="file-info">VirusTotal: ${new Date(app.lastVirusTotalAnalysis).toLocaleDateString()}</div>` : ""}
            </td>
            <td>
              <div class="package-name">${app.packageName}</div>
              ${permissionCount > 0 ? `<div class="permissions">${permissionCount} permissions</div>` : ""}
              ${hasMobsfAnalysis && app.mobsfAnalysis.dangerous_permissions ? 
                `<div class="permissions">${app.mobsfAnalysis.dangerous_permissions.length} dangerous perms</div>` : ""}
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
                  <span class="security-score" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8;">Static Analysis Score: ${app.mobsfAnalysis.security_score}/100</span>
                </div>
                <div class="mobsf-info">
                  ${app.mobsfAnalysis.dangerous_permissions?.length > 0 ? `${app.mobsfAnalysis.dangerous_permissions.length} dangerous permissions` : "No dangerous permissions"}
                  ${app.mobsfAnalysis.high_risk_findings > 0 ? ` | ${app.mobsfAnalysis.high_risk_findings} high risk findings` : ""}
                </div>
              ` : ""}
              ${hasVirusTotalAnalysis ? `
                <div class="vt-info">
                  <span class="security-score" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8;">
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
                <div class="btn-group-left">
                  <button class="btn-sandbox" onclick="uploadToSandbox('${app.sha256}', '${app.packageName}')">
                    Upload to Sandbox
                  </button>
                  <button class="btn-mobsf" onclick="runMobsfAnalysis('${app.sha256}', '${app.packageName}')" title="Run MobSF Static Analysis">
                    ${hasMobsfAnalysis ? "Re-analyze" : "Analyze"} MobSF
                  </button>
                  ${hasMobsfAnalysis ? `
                    <button class="btn-report" onclick="downloadMobsfReport('${app.sha256}')" title="Download MobSF PDF Report">
                      Download PDF
                    </button>
                  ` : ""}
                  ${app.apkFileName ? `
                    <button class="btn-download" onclick="downloadFile('${app.apkFileName}')">
                      Download APK
                    </button>
                  ` : ""}
                  <button class="btn-vt" onclick="runVirusTotalAnalysis('${app.sha256}', '${app.packageName}')" title="Run VirusTotal Analysis">
                    ${hasVirusTotalAnalysis ? "Re-analyze" : "Analyze"} VirusTotal
                  </button>
                  ${hasVirusTotalAnalysis ? `
                    <button class="btn-view" onclick="viewVirusTotalResults('${app.sha256}', '${app.packageName}')" title="View VirusTotal Results">
                      View Results
                    </button>
                  ` : ""}
                  <button class="btn-remarks" onclick="openRemarksModal('${app.sha256}', '${app.packageName}', '${app.appName || "Unknown App"}')" title="Add SOC Analyst Remarks">
                    SOC Remarks
                  </button>
                </div>
              </div>
              <button class="btn-delete" onclick="deleteApp('${app.sha256}', '${app.packageName}')" title="Delete App">
                <i class="fas fa-trash"></i>
              </button>
            </td>
          </tr>
        `;
      });

      html += `
            </tbody>
          </table>
          </div>
        </div>

        <!-- SOC Analyst Remarks Modal -->
        <div id="remarksModal" class="modal">
          <div class="modal-content">
            <div class="modal-header">SOC Analyst Remarks</div>
            <div class="modal-body">
              <div class="form-group">
                <label>Application</label>
                <input type="text" id="modal-app-name" readonly style="width: 100%; background: #0a192f; border: 1px solid #1d3557; border-radius: 6px; padding: 10px; color: #94a3b8; font-size: 13px;">
              </div>
              <div class="form-group">
                <label>Update Status</label>
                <select id="modal-status">
                  <option value="">-- Keep Current Status --</option>
                  <option value="safe">Safe</option>
                  <option value="malicious">Malicious</option>
                  <option value="suspicious">Suspicious</option>
                  <option value="unknown">Unknown</option>
                </select>
              </div>
              <div class="form-group">
                <label>SOC Analyst Remarks</label>
                <textarea id="modal-remarks" placeholder="Enter your analysis remarks here..."></textarea>
              </div>
            </div>
            <div class="modal-footer">
              <button class="btn-modal btn-cancel" onclick="closeRemarksModal()">Cancel</button>
              <button class="btn-modal btn-submit" onclick="submitRemarks()">Submit</button>
            </div>
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

          // SOC Analyst Remarks Modal Functions
          let currentAppSha256 = '';
          let currentAppPackage = '';

          function openRemarksModal(sha256, packageName, appName) {
            currentAppSha256 = sha256;
            currentAppPackage = packageName;
            document.getElementById('modal-app-name').value = appName + ' (' + packageName + ')';
            document.getElementById('modal-status').value = '';
            document.getElementById('modal-remarks').value = '';
            document.getElementById('remarksModal').classList.add('active');
          }

          function closeRemarksModal() {
            document.getElementById('remarksModal').classList.remove('active');
            currentAppSha256 = '';
            currentAppPackage = '';
          }

          function submitRemarks() {
            const status = document.getElementById('modal-status').value;
            const remarks = document.getElementById('modal-remarks').value.trim();

            if (!remarks) {
              alert('Please enter remarks before submitting.');
              return;
            }

            const payload = {
              socRemarks: remarks,
              remarksTimestamp: new Date().toISOString()
            };

            if (status) {
              payload.status = status;
            }

            fetch(getBasePath() + '/update-remarks/' + currentAppSha256, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload)
            })
            .then(response => response.json())
            .then(data => {
              if (data.error) {
                alert('Error: ' + data.error);
              } else {
                alert('SOC Analyst remarks submitted successfully!' + 
                      (status ? '\\nStatus updated to: ' + status : ''));
                closeRemarksModal();
                location.reload();
              }
            })
            .catch(error => {
              alert('Error: ' + error.message);
            });
          }

          // Close modal when clicking outside
          document.getElementById('remarksModal').addEventListener('click', function(e) {
            if (e.target === this) {
              closeRemarksModal();
            }
          });
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

// POST /scan - Original scan endpoint (backward compatibility) - NO AUTH REQUIRED
router.post("/scan", receiveAppData);

module.exports = router;