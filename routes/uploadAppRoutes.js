const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const mobsf = require("../utils/mobsf");
const { analyzeFileWithVirusTotal, checkVirusTotal } = require("../utils/virusTotal");
const { createHighMalwareNotification } = require("../utils/notifications");
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
            harmlessCount: vtResult.harmlessCount || 0,
            undetectedCount: vtResult.undetectedCount || 0,
            timeoutCount: vtResult.timeoutCount || 0,
            engineResultsJson: vtResult.results ? JSON.stringify(vtResult.results) : null,
            scanTime: vtResult.scanTime,
            analysisId: vtResult.analysisId,
            analysisDate: new Date().toISOString(),
            fileType: vtResult.fileType || null,
            fileMagic: vtResult.fileMagic || null,
            tags: vtResult.tags || [],
            names: vtResult.names || [],
            md5: vtResult.md5 || null,
            sha1: vtResult.sha1 || null,
            ssdeep: vtResult.ssdeep || null,
            reputation: vtResult.reputation ?? null,
            totalVotes: vtResult.totalVotes || null,
            firstSubmitted: vtResult.firstSubmitted || null,
            lastSubmitted: vtResult.lastSubmitted || null,
            timesSubmitted: vtResult.timesSubmitted || null,
            popularThreat: vtResult.popularThreat || null,
          },
          lastVirusTotalAnalysis: new Date().toISOString(),
        },
      },
    });

    createHighMalwareNotification(esClient, {
      appName: appData.appName,
      packageName: appData.packageName,
      sha256: appData.sha256,
      detectionRatio: vtResult.detectionRatio,
      totalEngines: vtResult.totalEngines,
      detectedEngines: vtResult.detectedEngines,
    }).catch((err) => console.error("Notification error:", err.message));

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

// Route: POST /analyze/:sha256 (Trigger MobSF analysis - requires web auth)
router.post("/analyze/:sha256", requireWebAuth, async (req, res) => {
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

// Route: POST /analyze-vt/:sha256 (Trigger VirusTotal analysis - requires web auth)
router.post("/analyze-vt/:sha256", requireWebAuth, async (req, res) => {
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

// GET /report/:sha256 - Get MobSF PDF report (requires web auth)
router.get("/report/:sha256", requireWebAuth, async (req, res) => {
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

// GET /mobsf/status - Check MobSF connection status (requires web auth)
router.get("/mobsf/status", requireWebAuth, async (req, res) => {
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

    const searchRes = await esClient.search({
      index: indexName,
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).send('<html><body style="background:#05090f;color:white;font-family:Arial;text-align:center;padding:50px"><h1>App not found</h1><a href="/uploadapp/apps" style="color:#60a5fa">← Back</a></body></html>');
    }

    const appData = searchRes.hits.hits[0]._source;
    const vt = appData.virusTotalAnalysis;

    if (!vt) {
      return res.status(400).send('<html><body style="background:#05090f;color:white;font-family:Arial;text-align:center;padding:50px"><h1>⚠️ No VirusTotal analysis available</h1><p style="color:#94a3b8">Run VirusTotal analysis from the app details page first.</p><a href="/uploadapp/apps" style="color:#60a5fa">← Back</a></body></html>');
    }

    // ── Data extraction ──────────────────────────────────────────────────────
    const esc = (s) => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

    let engineResults = {};
    const _rawEngineData = vt.engineResultsJson || vt.results;
    if (_rawEngineData) {
      try { engineResults = typeof _rawEngineData === 'string' ? JSON.parse(_rawEngineData) : _rawEngineData; } catch(e) { engineResults = {}; }
    }
    const allEngines    = Object.entries(engineResults);

    // Separate by verdict
    const maliciousEngines  = allEngines.filter(([,r]) => r.category === 'malicious');
    const suspiciousEngines = allEngines.filter(([,r]) => r.category === 'suspicious');
    const harmlessEngines   = allEngines.filter(([,r]) => r.category === 'harmless' || r.category === 'clean');
    const undetectedEngines = allEngines.filter(([,r]) => r.category === 'undetected');
    const timeoutEngines    = allEngines.filter(([,r]) => r.category === 'timeout' || r.category === 'type-unsupported' || r.category === 'failure');

    const totalEngines   = vt.totalEngines || allEngines.length || 0;
    const malCount       = vt.maliciousCount  || maliciousEngines.length  || 0;
    const suspCount      = vt.suspiciousCount || suspiciousEngines.length || 0;
    const harmCount      = vt.harmlessCount   || harmlessEngines.length   || 0;
    const undetCount     = vt.undetectedCount || undetectedEngines.length || 0;
    const detectedCount  = malCount + suspCount;

    // Overall verdict
    const verdict = vt.status || (malCount > 0 ? 'malicious' : suspCount > 0 ? 'suspicious' : 'safe');
    const verdictColor  = verdict === 'malicious' ? '#ef4444' : verdict === 'suspicious' ? '#f59e0b' : '#22c55e';
    const verdictBg     = verdict === 'malicious' ? '#450a0a' : verdict === 'suspicious' ? '#451a03' : '#052e16';
    const verdictBorder = verdict === 'malicious' ? '#7f1d1d' : verdict === 'suspicious' ? '#92400e' : '#166534';
    const verdictLabel  = verdict === 'malicious' ? '🔴 MALICIOUS' : verdict === 'suspicious' ? '🟡 SUSPICIOUS' : '🟢 CLEAN';
    const verdictDesc   = verdict === 'malicious'
      ? `${malCount} out of ${totalEngines} security engines flagged this file as malicious. It likely contains harmful code.`
      : verdict === 'suspicious'
      ? `${suspCount} out of ${totalEngines} engines rated this file as suspicious. It may exhibit unwanted behavior.`
      : `No security engines flagged this file. It appears to be safe based on ${totalEngines} engine scans.`;

    // Threat classification from VT
    const popThreat = vt.popularThreat || null;
    const suggestedLabel = popThreat?.suggested_threat_label || null;

    // Detection percentage for gauge
    const detectionPct = totalEngines > 0 ? Math.round((detectedCount / totalEngines) * 100) : 0;
    const gaugeColor = detectionPct === 0 ? '#22c55e' : detectionPct < 10 ? '#f59e0b' : '#ef4444';

    // Collect unique threat names from detected engines
    const threatNames = [...new Set(
      [...maliciousEngines, ...suspiciousEngines]
        .map(([,r]) => r.result)
        .filter(Boolean)
    )];

    const scanDate = vt.scanTime ? new Date(vt.scanTime).toLocaleString() : 'N/A';
    const vtLink = `https://www.virustotal.com/gui/file/${sha256}`;

    // Helper to build engine row HTML
    const engineRow = ([engine, r], idx) => {
      const cat = r.category || 'undetected';
      const threat = r.result || '';
      const ver = r.engine_version || '';
      const update = r.engine_update || '';
      const isDetected = cat === 'malicious' || cat === 'suspicious';
      const catColor = cat === 'malicious' ? '#fca5a5' : cat === 'suspicious' ? '#fcd34d' : cat === 'harmless' || cat === 'clean' ? '#4ade80' : '#64748b';
      const catBg    = cat === 'malicious' ? '#450a0a' : cat === 'suspicious' ? '#451a03' : cat === 'harmless' || cat === 'clean' ? '#052e16' : '#1e293b';
      const rowBg    = isDetected ? 'rgba(239,68,68,0.05)' : '';
      return `<tr style="background:${rowBg}">
        <td style="font-weight:${isDetected?'600':'400'};color:${isDetected?'#f1f5f9':'#94a3b8'}">${esc(engine)}</td>
        <td><span style="background:${catBg};color:${catColor};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600">${cat.toUpperCase()}</span></td>
        <td style="color:${isDetected?'#fca5a5':'#475569'};font-size:11px">${esc(threat) || (cat==='undetected'?'—':'Clean')}</td>
        <td style="color:#475569;font-size:10px;font-family:monospace">${esc(ver)}</td>
        <td style="color:#334155;font-size:10px">${esc(update)}</td>
      </tr>`;
    };

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>VirusTotal — ${esc(appData.appName || appData.packageName)}</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:#05090f;color:#cbd5e1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;min-height:100vh;padding:20px 16px}
    a{color:#3b82f6;text-decoration:none}a:hover{text-decoration:underline}
    .wrap{max-width:1100px;margin:0 auto}
    .topbar{display:flex;align-items:center;gap:12px;margin-bottom:22px;flex-wrap:wrap}
    .back-btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;background:#1e293b;border:1px solid #334155;color:#94a3b8;border-radius:8px;font-size:13px;font-weight:500;transition:background .2s}
    .back-btn:hover{background:#263248;color:#e2e8f0;text-decoration:none}
    .page-title{font-size:20px;font-weight:700;color:#f1f5f9}
    .page-sub{font-size:12px;color:#64748b;margin-top:3px}
    /* Cards */
    .card{background:#0b1120;border:1px solid #1a2332;border-radius:12px;padding:18px 20px;margin-bottom:14px;overflow:hidden}
    .card-hdr{display:flex;align-items:center;gap:10px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid #1a2332}
    .card-icon{font-size:18px;width:32px;height:32px;background:#0f2040;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
    .card-title{font-size:13px;font-weight:600;color:#e2e8f0;text-transform:uppercase;letter-spacing:.05em}
    .card-sub{margin-left:auto;font-size:11px;color:#64748b}
    /* Verdict banner */
    .verdict-banner{border-radius:12px;padding:22px 24px;margin-bottom:14px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
    .verdict-label{font-size:28px;font-weight:800;letter-spacing:.05em}
    .verdict-desc{font-size:13px;line-height:1.6;flex:1}
    /* Stats grid */
    .stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px}
    .stat-card{background:#05090f;border:1px solid #1a2332;border-radius:10px;padding:14px;text-align:center}
    .stat-label{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
    .stat-val{font-size:26px;font-weight:700;line-height:1}
    .sv-red{color:#ef4444}.sv-yellow{color:#f59e0b}.sv-green{color:#22c55e}.sv-blue{color:#3b82f6}.sv-gray{color:#94a3b8}
    /* Detection gauge */
    .gauge-wrap{display:flex;align-items:center;gap:16px;margin-bottom:12px}
    .gauge-bar-bg{flex:1;height:12px;background:#1e293b;border-radius:99px;overflow:hidden}
    .gauge-bar-fill{height:100%;border-radius:99px;transition:width .4s}
    .gauge-pct{font-size:22px;font-weight:700;min-width:56px;text-align:right}
    /* Tables */
    .tbl-wrap{overflow-x:auto}
    table{width:100%;border-collapse:collapse;font-size:12px}
    th{background:#070d1a;color:#94a3b8;padding:9px 10px;text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #1e293b}
    td{padding:8px 10px;border-bottom:1px solid #0d1a2e;vertical-align:top}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:rgba(30,58,100,.2)}
    /* Info rows */
    .info-row{display:flex;justify-content:space-between;align-items:flex-start;padding:8px 0;border-bottom:1px solid #0d1a2e;gap:12px}
    .info-row:last-child{border-bottom:none}
    .info-lbl{font-size:11px;color:#64748b;font-weight:500;min-width:140px;flex-shrink:0}
    .info-val{font-size:11px;color:#cbd5e1;word-break:break-all;text-align:right;font-family:monospace}
    /* Threat chips */
    .chip-list{display:flex;flex-wrap:wrap;gap:6px}
    .chip{padding:4px 10px;border-radius:6px;font-size:11px;font-weight:600}
    .chip-red{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d}
    .chip-yellow{background:#451a03;color:#fcd34d;border:1px solid #92400e}
    .chip-gray{background:#1e293b;color:#94a3b8;border:1px solid #334155}
    /* Sections for detected/all toggle */
    .tab-bar{display:flex;gap:8px;margin-bottom:12px}
    .tab{padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid #334155;background:#1e293b;color:#94a3b8;transition:.15s}
    .tab.active{background:#1d4ed8;color:#fff;border-color:#1d4ed8}
    .engine-section{display:none}.engine-section.active{display:block}
    /* Collapsible */
    details summary{cursor:pointer;font-size:12px;color:#64748b;user-select:none;padding:4px 0}
    details summary:hover{color:#94a3b8}
    details[open] summary{margin-bottom:8px}
    .vt-ext-link{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;background:linear-gradient(135deg,#1a56db,#1d4ed8);color:#fff;border-radius:8px;font-size:13px;font-weight:600}
    .vt-ext-link:hover{opacity:.88;text-decoration:none}
    @media(max-width:600px){.stats-grid{grid-template-columns:repeat(2,1fr)}.verdict-banner{flex-direction:column}}
  </style>
</head>
<body>
<div class="wrap">

  <div class="topbar">
    <a class="back-btn" href="/uploadapp/apps?date=${selectedDate}">← Back to Apps</a>
    <div>
      <div class="page-title">🛡️ VirusTotal Multi-Engine Analysis</div>
      <div class="page-sub">${esc(appData.appName || 'Unknown')} &nbsp;·&nbsp; ${esc(appData.packageName || sha256)} &nbsp;·&nbsp; Scanned: ${scanDate}</div>
    </div>
  </div>

  <!-- ── 1. Verdict Banner ──────────────────────────────────────── -->
  <div class="verdict-banner" style="background:${verdictBg};border:1px solid ${verdictBorder}">
    <div>
      <div class="verdict-label" style="color:${verdictColor}">${verdictLabel}</div>
      <div style="font-size:12px;color:#64748b;margin-top:4px">Overall Verdict</div>
    </div>
    <div class="verdict-desc" style="color:#94a3b8">${verdictDesc}</div>
    ${suggestedLabel ? `<div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:10px 14px;font-size:12px"><div style="color:#64748b;font-size:10px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Suggested Threat Label</div><div style="color:#fcd34d;font-weight:600">${esc(suggestedLabel)}</div></div>` : ''}
  </div>

  <!-- ── 2. Detection Stats ─────────────────────────────────────── -->
  <div class="card">
    <div class="card-hdr">
      <div class="card-icon">📊</div>
      <div class="card-title">Detection Statistics</div>
      <div class="card-sub">${totalEngines} engines scanned</div>
    </div>

    <div class="gauge-wrap" style="margin-bottom:16px">
      <div style="font-size:12px;color:#64748b;min-width:110px">Detection Rate</div>
      <div class="gauge-bar-bg">
        <div class="gauge-bar-fill" style="width:${detectionPct}%;background:${gaugeColor}"></div>
      </div>
      <div class="gauge-pct" style="color:${gaugeColor}">${detectionPct}%</div>
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Detection Ratio</div>
        <div class="stat-val sv-blue" style="font-size:22px">${vt.detectionRatio || `${detectedCount}/${totalEngines}`}</div>
        <div style="font-size:10px;color:#64748b;margin-top:4px">engines detected</div>
      </div>
      <div class="stat-card" style="border-color:${malCount>0?'#7f1d1d':'#1e293b'}">
        <div class="stat-label">Malicious</div>
        <div class="stat-val ${malCount>0?'sv-red':'sv-gray'}">${malCount}</div>
        <div style="font-size:10px;color:#64748b;margin-top:4px">confirmed threat</div>
      </div>
      <div class="stat-card" style="border-color:${suspCount>0?'#92400e':'#1e293b'}">
        <div class="stat-label">Suspicious</div>
        <div class="stat-val ${suspCount>0?'sv-yellow':'sv-gray'}">${suspCount}</div>
        <div style="font-size:10px;color:#64748b;margin-top:4px">possible threat</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Clean / Harmless</div>
        <div class="stat-val sv-green">${harmCount}</div>
        <div style="font-size:10px;color:#64748b;margin-top:4px">no threat found</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Undetected</div>
        <div class="stat-val sv-gray">${undetCount}</div>
        <div style="font-size:10px;color:#64748b;margin-top:4px">no signature match</div>
      </div>
      ${(vt.timeoutCount || 0) > 0 ? `
      <div class="stat-card">
        <div class="stat-label">Timeout / Error</div>
        <div class="stat-val sv-gray">${vt.timeoutCount}</div>
        <div style="font-size:10px;color:#64748b;margin-top:4px">scan incomplete</div>
      </div>` : ''}
    </div>
  </div>

  <!-- ── 3. Detected By (Names) ─────────────────────────────────── -->
  ${(maliciousEngines.length + suspiciousEngines.length) > 0 ? `
  <div class="card">
    <div class="card-hdr">
      <div class="card-icon">⚠️</div>
      <div class="card-title">Flagged By Engines</div>
      <div class="card-sub">${detectedCount} of ${totalEngines}</div>
    </div>

    ${maliciousEngines.length > 0 ? `
    <div style="margin-bottom:12px">
      <div style="font-size:11px;color:#64748b;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">🔴 Malicious (${maliciousEngines.length})</div>
      <div class="tbl-wrap"><table>
        <tr><th>Engine</th><th>Threat Name / Signature</th><th>Engine Version</th></tr>
        ${maliciousEngines.map(([engine, r]) => `<tr>
          <td style="font-weight:600;color:#fca5a5">${esc(engine)}</td>
          <td style="color:#f87171;font-style:${r.result?'normal':'italic'}">${esc(r.result) || 'Detected (no name)'}</td>
          <td style="font-family:monospace;font-size:10px;color:#475569">${esc(r.engine_version || '—')}</td>
        </tr>`).join('')}
      </table></div>
    </div>` : ''}

    ${suspiciousEngines.length > 0 ? `
    <div>
      <div style="font-size:11px;color:#64748b;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:.05em">🟡 Suspicious (${suspiciousEngines.length})</div>
      <div class="tbl-wrap"><table>
        <tr><th>Engine</th><th>Reason / Signature</th><th>Engine Version</th></tr>
        ${suspiciousEngines.map(([engine, r]) => `<tr>
          <td style="font-weight:600;color:#fcd34d">${esc(engine)}</td>
          <td style="color:#fbbf24">${esc(r.result) || 'Flagged as suspicious'}</td>
          <td style="font-family:monospace;font-size:10px;color:#475569">${esc(r.engine_version || '—')}</td>
        </tr>`).join('')}
      </table></div>
    </div>` : ''}
  </div>` : ''}

  <!-- ── 4. Threat Names Summary ────────────────────────────────── -->
  ${threatNames.length > 0 ? `
  <div class="card">
    <div class="card-hdr">
      <div class="card-icon">🏷️</div>
      <div class="card-title">Threat Signatures Identified</div>
    </div>
    <p style="font-size:11px;color:#64748b;margin-bottom:10px">These are the malware family names / threat signatures reported by the detecting engines. Different engines may use different names for the same threat.</p>
    <div class="chip-list">
      ${threatNames.map(n => `<span class="chip chip-red">${esc(n)}</span>`).join('')}
    </div>
    ${popThreat?.popular_threat_name ? `
    <div style="margin-top:12px">
      <div style="font-size:11px;color:#64748b;margin-bottom:6px">Most Common Threat Name (across all engines):</div>
      <div class="chip-list">
        ${(Array.isArray(popThreat.popular_threat_name) ? popThreat.popular_threat_name : [popThreat.popular_threat_name])
          .map(t => `<span class="chip chip-red">${esc(typeof t === 'object' ? t.value : t)}</span>`).join('')}
      </div>
    </div>` : ''}
    ${popThreat?.popular_threat_category ? `
    <div style="margin-top:12px">
      <div style="font-size:11px;color:#64748b;margin-bottom:6px">Threat Categories:</div>
      <div class="chip-list">
        ${(Array.isArray(popThreat.popular_threat_category) ? popThreat.popular_threat_category : [popThreat.popular_threat_category])
          .map(t => `<span class="chip chip-yellow">${esc(typeof t === 'object' ? t.value : t)}</span>`).join('')}
      </div>
    </div>` : ''}
  </div>` : ''}

  <!-- ── 5. Community Reputation ────────────────────────────────── -->
  ${vt.reputation !== null && vt.reputation !== undefined ? `
  <div class="card">
    <div class="card-hdr">
      <div class="card-icon">👥</div>
      <div class="card-title">Community Reputation</div>
    </div>
    <div style="display:flex;gap:20px;flex-wrap:wrap">
      <div class="stat-card" style="flex:1;min-width:120px">
        <div class="stat-label">Reputation Score</div>
        <div class="stat-val ${vt.reputation < 0 ? 'sv-red' : vt.reputation === 0 ? 'sv-gray' : 'sv-green'}" style="font-size:24px">${vt.reputation}</div>
        <div style="font-size:10px;color:#64748b;margin-top:4px">${vt.reputation < -10 ? 'Strongly negative' : vt.reputation < 0 ? 'Slightly negative' : vt.reputation === 0 ? 'Neutral' : 'Positive'}</div>
      </div>
      ${vt.totalVotes ? `
      <div class="stat-card" style="flex:1;min-width:120px">
        <div class="stat-label">Community Votes — Harmless</div>
        <div class="stat-val sv-green">${vt.totalVotes.harmless || 0}</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:120px">
        <div class="stat-label">Community Votes — Malicious</div>
        <div class="stat-val sv-red">${vt.totalVotes.malicious || 0}</div>
      </div>` : ''}
    </div>
    <p style="font-size:11px;color:#475569;margin-top:10px">The reputation score is derived from the votes of VirusTotal users and trusted security vendors. Negative scores indicate the community considers this file harmful.</p>
  </div>` : ''}

  <!-- ── 6. File Information ─────────────────────────────────────── -->
  <div class="card">
    <div class="card-hdr">
      <div class="card-icon">📄</div>
      <div class="card-title">File Information</div>
    </div>
    <div class="info-row"><span class="info-lbl">SHA-256</span><span class="info-val">${esc(appData.sha256 || sha256)}</span></div>
    ${vt.md5   ? `<div class="info-row"><span class="info-lbl">MD5</span><span class="info-val">${esc(vt.md5)}</span></div>` : ''}
    ${vt.sha1  ? `<div class="info-row"><span class="info-lbl">SHA-1</span><span class="info-val">${esc(vt.sha1)}</span></div>` : ''}
    ${vt.ssdeep? `<div class="info-row"><span class="info-lbl">SSDeep (fuzzy hash)</span><span class="info-val">${esc(vt.ssdeep)}</span></div>` : ''}
    <div class="info-row"><span class="info-lbl">File Size</span><span class="info-val">${appData.sizeMB ? appData.sizeMB.toFixed(2) + ' MB' : (appData.fileSize ? (appData.fileSize/1024/1024).toFixed(2) + ' MB' : 'N/A')}</span></div>
    ${vt.fileType  ? `<div class="info-row"><span class="info-lbl">File Type</span><span class="info-val">${esc(vt.fileType)}</span></div>` : ''}
    ${vt.fileMagic ? `<div class="info-row"><span class="info-lbl">Magic Bytes</span><span class="info-val">${esc(vt.fileMagic)}</span></div>` : ''}
    ${vt.firstSubmitted ? `<div class="info-row"><span class="info-lbl">First Seen on VT</span><span class="info-val">${new Date(vt.firstSubmitted).toLocaleString()}</span></div>` : ''}
    ${vt.lastSubmitted  ? `<div class="info-row"><span class="info-lbl">Last Submission</span><span class="info-val">${new Date(vt.lastSubmitted).toLocaleString()}</span></div>` : ''}
    ${vt.timesSubmitted ? `<div class="info-row"><span class="info-lbl">Times Submitted</span><span class="info-val">${vt.timesSubmitted}</span></div>` : ''}
    ${vt.names && vt.names.length > 0 ? `<div class="info-row"><span class="info-lbl">Known File Names</span><span class="info-val">${vt.names.slice(0,5).map(n => esc(n)).join(', ')}</span></div>` : ''}
    ${vt.tags && vt.tags.length > 0 ? `<div class="info-row"><span class="info-lbl">Tags</span><span class="info-val"><div class="chip-list" style="justify-content:flex-end">${vt.tags.map(t => `<span class="chip chip-gray">${esc(t)}</span>`).join('')}</div></span></div>` : ''}
  </div>

  <!-- ── 7. All Engines Results ──────────────────────────────────── -->
  ${allEngines.length > 0 ? `
  <div class="card">
    <div class="card-hdr">
      <div class="card-icon">🔍</div>
      <div class="card-title">All Engine Results</div>
      <div class="card-sub">${allEngines.length} engines</div>
    </div>

    <div class="tab-bar">
      <div class="tab active" onclick="showTab('detected',this)">⚠️ Detected (${detectedCount})</div>
      <div class="tab" onclick="showTab('all',this)">📋 All Engines (${allEngines.length})</div>
    </div>

    <div id="tab-detected" class="engine-section active">
      ${detectedCount === 0
        ? '<p style="color:#22c55e;font-size:13px;padding:8px 0">✓ No engines detected any threats in this file.</p>'
        : `<div class="tbl-wrap"><table>
            <tr><th>Engine</th><th>Verdict</th><th>Threat Name / Signature</th><th>Version</th><th>Last Update</th></tr>
            ${[...maliciousEngines, ...suspiciousEngines].map(engineRow).join('')}
          </table></div>`}
    </div>

    <div id="tab-all" class="engine-section">
      <div class="tbl-wrap"><table>
        <tr><th>Engine</th><th>Verdict</th><th>Threat Name / Signature</th><th>Version</th><th>Last Update</th></tr>
        ${[...maliciousEngines, ...suspiciousEngines, ...harmlessEngines, ...undetectedEngines, ...timeoutEngines].map(engineRow).join('')}
      </table></div>
    </div>
  </div>` : `
  <div class="card">
    <div class="card-hdr"><div class="card-icon">🔍</div><div class="card-title">Engine Results</div></div>
    <p style="font-size:12px;color:#64748b">Per-engine results are not available for this scan. This may be because the file was scanned before engine results were stored. Re-run VirusTotal analysis to get detailed per-engine data.</p>
  </div>`}

  <!-- ── External Link ──────────────────────────────────────────── -->
  <div style="text-align:center;padding:24px 0 8px;display:flex;flex-direction:column;align-items:center;gap:12px">
    <a class="vt-ext-link" href="${vtLink}" target="_blank" rel="noopener">
      🔗 View Full Report on VirusTotal.com ↗
    </a>
    <p style="font-size:11px;color:#334155">VirusTotal is a free online service by Google that analyses files using 70+ antivirus engines and website scanners.</p>
  </div>

</div>

<script>
function showTab(id, el) {
  document.querySelectorAll('.engine-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  el.classList.add('active');
}
</script>
</body>
</html>`;

    res.send(html);
  } catch (err) {
    console.error("[VT Results] Error:", err.message);
    res.status(500).send(`<html><body style="background:#05090f;color:white;font-family:Arial;padding:40px"><h1>Error</h1><p>${err.message}</p><a href="/uploadapp/apps" style="color:#60a5fa">← Back</a></body></html>`);
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
      background: #05090f; color: #cbd5e1; min-height: 100vh; padding: 30px 20px;
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
      background: #0b1120;
      border: 1px solid #1a2332;
      border-radius: 10px;
      padding: 30px;
      margin-bottom: 30px;
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
    res.status(500).send(`<html><body style="background:#05090f;color:white;text-align:center;padding:50px"><h1>❌ Error</h1><p>\${err.message}</p><a href="/uploadapp/apps" style="color:#90e0ef">← Back</a></body></html>`);
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
            background: #05090f;
            color: #94a3b8;
            min-height: 100vh;
            display: flex;
            position: relative;
            overflow-x: hidden;
          }

          /* Sidebar styles */
          .sidebar {
            width: 240px;
            background: #0b1120;
            height: 100vh;
            padding: 0;
            display: flex;
            flex-direction: column;
            position: fixed;
            left: -240px;
            top: 0;
            transition: left 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            z-index: 1000;
            box-shadow: 4px 0 24px rgba(0, 0, 0, 0.6);
            border-right: 1px solid #1a2332;
          }

          .sidebar.open {
            left: 0;
          }

          .logo {
            padding: 22px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            color: white;
            font-weight: 700;
            font-size: 16px;
            border-bottom: 1px solid #1a2332;
            letter-spacing: 0.5px;
          }

          .logo-icon {
            width: 38px;
            height: 38px;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
            color: white;
            box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);
          }

          .nav-section-title {
            padding: 20px 20px 8px;
            color: #475569;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.2px;
          }

          .nav-item {
            padding: 11px 20px;
            color: #94a3b8;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 14px;
            transition: all 0.2s ease;
            font-size: 14px;
            cursor: pointer;
            border-left: 3px solid transparent;
            margin: 1px 0;
          }

          .nav-item:hover {
            background: rgba(59, 130, 246, 0.08);
            color: #e2e8f0;
            border-left-color: rgba(59, 130, 246, 0.3);
          }

          .nav-item.active {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border-left-color: #3b82f6;
            font-weight: 600;
          }

          .nav-icon {
            width: 20px;
            text-align: center;
            font-size: 16px;
          }

          .logout-nav {
            margin-top: auto;
            padding: 14px 20px;
            color: #f87171;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 14px;
            transition: all 0.2s ease;
            font-size: 14px;
            border-top: 1px solid #1a2332;
          }

          .logout-nav:hover {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
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

          .sidebar.open ~ .main-content {
            margin-left: 240px;
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
            background: rgba(0, 0, 0, 0.7);
            z-index: 999;
            backdrop-filter: blur(2px);
          }

          .overlay.show {
            display: block;
          }

          .overlay.active {
            display: block;
          }

          .top-bar {
            background: #0b1120;
            padding: 8px 15px 8px 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1a2332;
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
          
          <div class="nav-section-title">NAVIGATION</div>
          <a href="/" class="nav-item">
            <i class="fas fa-home nav-icon"></i>
            <span>Home</span>
          </a>
          <a href="/dashboard" class="nav-item">
            <i class="fas fa-chart-line nav-icon"></i>
            <span>Security Dashboard</span>
          </a>
          <a href="/uploadapp/apps" class="nav-item active">
            <i class="fas fa-mobile-alt nav-icon"></i>
            <span>App Manager</span>
          </a>
          <a href="/results" class="nav-item">
            <i class="fas fa-file-alt nav-icon"></i>
            <span>Analysis Results</span>
          </a>
          
          <div class="nav-section-title" style="margin-top: 12px;">SYSTEM</div>
          <a href="#" class="nav-item">
            <i class="fas fa-cog nav-icon"></i>
            <span>Settings</span>
          </a>
          
          <a href="/logout" class="logout-nav">
            <i class="fas fa-sign-out-alt nav-icon"></i>
            <span>Sign Out</span>
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
router.post("/dynamic-analysis/:sha256", requireWebAuth, async (req, res) => {
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

// GET /dynamic-report/:sha256 - Download dynamic analysis PDF (requires web auth)
router.get("/dynamic-report/:sha256", requireWebAuth, async (req, res) => {
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

// GET /dynamic-results/:sha256 - View dynamic analysis results as HTML page (requires web auth)
router.get("/dynamic-results/:sha256", requireWebAuth, async (req, res) => {
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
      return res.status(404).send('<html><body style="background:#05090f;color:white;font-family:Arial;text-align:center;padding:50px"><h1>App not found</h1><a href="/uploadapp/apps" style="color:#60a5fa">← Back</a></body></html>');
    }

    const appData = searchRes.hits.hits[0]._source;
    const da = appData.dynamicAnalysis;

    if (!da || da.status !== 'completed') {
      return res.status(400).send('<html><body style="background:#05090f;color:white;font-family:Arial;text-align:center;padding:50px"><h1>⚠️ Dynamic analysis not completed yet</h1><a href="/uploadapp/apps" style="color:#60a5fa">← Back</a></body></html>');
    }

    const raw = da.raw_report || {};
    const md5Hash = raw.hash || appData.mobsfHash || null;
    const MOBSF = process.env.MOBSF_URL || 'http://localhost:8000';

    // ── TLS extraction ─────────────────────────────────────────────────────────
    // Try multiple locations MobSF may store TLS data
    let tlsFlat = null;
    const _tlsRaw = da.tls_tests || raw.tls_tests || raw.tls || raw.ssl_tests || null;
    if (_tlsRaw && typeof _tlsRaw === 'object') {
      if ('has_cleartext' in _tlsRaw || 'tls_misconfigured' in _tlsRaw) {
        tlsFlat = _tlsRaw;
      } else if (_tlsRaw.tls_tests && typeof _tlsRaw.tls_tests === 'object' && !Array.isArray(_tlsRaw.tls_tests)) {
        tlsFlat = _tlsRaw.tls_tests;
      } else if (Array.isArray(_tlsRaw.tls_tests)) {
        // array of {name, result}
        tlsFlat = {};
        for (const t of _tlsRaw.tls_tests) {
          const n = (t.name || '').toLowerCase();
          if (n.includes('cleartext'))     tlsFlat.has_cleartext = !t.result;
          if (n.includes('misconfigur'))   tlsFlat.tls_misconfigured = !t.result;
          if (n.includes('bypass'))        tlsFlat.pin_or_transparency_bypassed = !t.result;
          if (n.includes('pinning') && !n.includes('bypass')) tlsFlat.no_tls_pin_or_transparency = !t.result;
        }
      } else if (Array.isArray(_tlsRaw)) {
        tlsFlat = {};
        for (const t of _tlsRaw) {
          const n = (t.name || '').toLowerCase();
          if (n.includes('cleartext'))     tlsFlat.has_cleartext = !t.result;
          if (n.includes('misconfigur'))   tlsFlat.tls_misconfigured = !t.result;
          if (n.includes('bypass'))        tlsFlat.pin_or_transparency_bypassed = !t.result;
          if (n.includes('pinning') && !n.includes('bypass')) tlsFlat.no_tls_pin_or_transparency = !t.result;
        }
      }
    }
    const TLS_TESTS = tlsFlat ? [
      { name: 'Cleartext Traffic Test',                       key: 'has_cleartext',                    desc: 'App does not transmit data in cleartext (HTTP without encryption).' },
      { name: 'TLS Misconfiguration Test',                    key: 'tls_misconfigured',                desc: 'TLS is properly configured — no weak ciphers or outdated protocols detected.' },
      { name: 'TLS Pinning / Certificate Transparency Bypass',key: 'pin_or_transparency_bypassed',     desc: 'Certificate pinning or CT could not be bypassed by MobSF.' },
      { name: 'TLS Pinning / Certificate Transparency',       key: 'no_tls_pin_or_transparency',       desc: 'App implements certificate pinning or Certificate Transparency.' },
    ] : [];

    // ── Data extraction ────────────────────────────────────────────────────────
    const domainsObj     = raw.domains || {};
    const domainList     = Object.entries(domainsObj);
    const trackersObj    = raw.trackers || {};
    // MobSF may use: {detected_trackers:N, trackers:{name:{categories,url}}, total_trackers:N}
    // OR just {name:{...}} flat dict
    const trackerDict    = (trackersObj.trackers && typeof trackersObj.trackers === 'object')
                             ? trackersObj.trackers
                             : (typeof trackersObj === 'object' && !('detected_trackers' in trackersObj) ? trackersObj : {});
    const trackerEntries = Object.entries(trackerDict);
    const urlList        = Array.isArray(raw.urls) ? raw.urls : [];
    const emailList      = Array.isArray(raw.emails) ? raw.emails : [];
    const openRedirects  = Array.isArray(raw.open_redirect) ? raw.open_redirect : [];
    const exportedActs   = Array.isArray(raw.exported_activities) ? raw.exported_activities
                         : Array.isArray(raw.exported_activities_exploitable) ? raw.exported_activities_exploitable : [];
    const testedActs     = Array.isArray(raw.activities) ? raw.activities : [];
    const _clipboardRaw  = raw.clipboard_data || raw.clipboard || null;
    const clipboardData  = (Array.isArray(_clipboardRaw) && _clipboardRaw.length === 0) ? null : _clipboardRaw;
    const screenshots    = Array.isArray(raw.screenshots) ? raw.screenshots : [];
    const networkSec     = Array.isArray(raw.network_security) ? raw.network_security : [];
    const otherFiles     = Array.isArray(raw.other_files) ? raw.other_files
                         : Array.isArray(raw.files_created) ? raw.files_created : [];
    const apiCalls       = da.api_monitor
                           ? (Array.isArray(da.api_monitor) ? da.api_monitor : [da.api_monitor])
                           : [];
    const fridaLogs      = da.frida_logs || null;

    // ── Helper render functions ────────────────────────────────────────────────
    const esc = (s) => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const riskBadge = (v, hi = 'FAIL', lo = 'PASS') =>
      `<span class="badge ${v ? 'badge-red' : 'badge-green'}">${v ? '✗ ' + hi : '✓ ' + lo}</span>`;
    const statusBadge = (flagged) =>
      flagged ? '<span class="badge badge-red">⚠ Flagged</span>' : '<span class="badge badge-green">✓ Clean</span>';
    const sectionHdr = (icon, title, count = null) =>
      `<div class="sec-hdr"><span class="sec-icon">${icon}</span><span class="sec-title">${title}</span>${count !== null ? `<span class="sec-count">${count}</span>` : ''}</div>`;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Dynamic Analysis — ${esc(appData.appName || sha256)}</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:#05090f;color:#cbd5e1;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;min-height:100vh;padding:20px 16px}
    a{color:#3b82f6;text-decoration:none}a:hover{text-decoration:underline}
    .wrap{max-width:1140px;margin:0 auto}
    /* Top bar */
    .topbar{display:flex;align-items:center;gap:12px;margin-bottom:22px;flex-wrap:wrap}
    .back-btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;background:#1e293b;border:1px solid #334155;color:#94a3b8;border-radius:8px;font-size:13px;font-weight:500;transition:background .2s}
    .back-btn:hover{background:#263248;color:#e2e8f0;text-decoration:none}
    .page-title{font-size:20px;font-weight:700;color:#f1f5f9}
    .page-sub{font-size:12px;color:#64748b;margin-top:3px}
    /* Sections */
    .section{background:#0b1120;border:1px solid #1a2332;border-radius:12px;padding:18px 20px;margin-bottom:14px;overflow:hidden}
    .sec-hdr{display:flex;align-items:center;gap:10px;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid #1a2332}
    .sec-icon{font-size:18px;width:32px;height:32px;background:#0f2040;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
    .sec-title{font-size:14px;font-weight:600;color:#e2e8f0;text-transform:uppercase;letter-spacing:.05em}
    .sec-count{margin-left:auto;background:#1e293b;color:#94a3b8;font-size:11px;font-weight:600;padding:2px 8px;border-radius:99px}
    /* Stat grid */
    .stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
    .stat-card{background:#05090f;border:1px solid #1a2332;border-radius:10px;padding:14px;text-align:center}
    .stat-label{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
    .stat-val{font-size:26px;font-weight:700;color:#3b82f6;line-height:1}
    .stat-val.green{color:#22c55e}.stat-val.red{color:#ef4444}.stat-val.yellow{color:#f59e0b}.stat-val.gray{color:#94a3b8;font-size:13px;margin-top:4px}
    /* Env cards */
    .env-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px}
    .env-card{background:#05090f;border:1px solid #1a2332;border-radius:10px;padding:12px;text-align:center}
    .env-card .env-label{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
    .env-card .env-icon{font-size:22px}
    /* Tables */
    .tbl-wrap{overflow-x:auto}
    table{width:100%;border-collapse:collapse;font-size:12px}
    th{background:#070d1a;color:#94a3b8;padding:9px 10px;text-align:left;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #1e293b}
    td{padding:8px 10px;border-bottom:1px solid #0d1a2e;vertical-align:top;word-break:break-word}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:rgba(30,58,100,.25)}
    /* Badges */
    .badge{display:inline-block;padding:3px 8px;border-radius:5px;font-size:11px;font-weight:600}
    .badge-red{background:#450a0a;color:#fca5a5;border:1px solid #7f1d1d}
    .badge-green{background:#052e16;color:#4ade80;border:1px solid #166534}
    .badge-yellow{background:#451a03;color:#fcd34d;border:1px solid #92400e}
    .badge-blue{background:#1e3a8a;color:#93c5fd;border:1px solid #1d4ed8}
    .badge-gray{background:#1e293b;color:#94a3b8;border:1px solid #334155}
    /* TLS tests */
    .tls-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #0d1a2e}
    .tls-row:last-child{border-bottom:none}
    .tls-status{width:80px;flex-shrink:0;text-align:center}
    .tls-name{font-size:13px;color:#e2e8f0;font-weight:500}
    .tls-desc{font-size:11px;color:#475569;margin-top:3px}
    /* URL / email chips */
    .chip-list{display:flex;flex-wrap:wrap;gap:6px}
    .chip{background:#0d1a2e;border:1px solid #1e293b;color:#94a3b8;padding:4px 10px;border-radius:6px;font-size:11px;word-break:break-all}
    .chip.url{color:#60a5fa}.chip.email{color:#a78bfa}
    /* Pre code blocks */
    pre{background:#070d1a;border:1px solid #1e293b;border-radius:8px;padding:12px;font-size:11px;overflow:auto;max-height:280px;color:#94a3b8;line-height:1.6}
    /* Collapsible */
    details summary{cursor:pointer;font-size:12px;color:#64748b;margin-top:8px;padding:4px 0;user-select:none}
    details summary:hover{color:#94a3b8}
    details[open] summary{margin-bottom:8px}
    /* Empty state */
    .empty{color:#334155;font-size:12px;padding:10px 0;font-style:italic}
    /* Screenshot grid */
    .ss-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
    .ss-item{background:#070d1a;border:1px solid #1e293b;border-radius:8px;overflow:hidden;text-align:center}
    .ss-item img{width:100%;display:block;max-height:220px;object-fit:contain;background:#000}
    .ss-item span{font-size:10px;color:#64748b;display:block;padding:4px}
    /* Download btn */
    .dl-btn{display:inline-flex;align-items:center;gap:8px;padding:10px 22px;background:linear-gradient(135deg,#1d4ed8,#2563eb);color:#fff;border-radius:9px;font-size:13px;font-weight:600;transition:opacity .2s}
    .dl-btn:hover{opacity:.88;text-decoration:none}
    .risk-high{color:#ef4444}.risk-med{color:#f59e0b}.risk-low{color:#22c55e}
    @media(max-width:600px){.stat-grid,.env-grid{grid-template-columns:repeat(2,1fr)}}
  </style>
</head>
<body>
<div class="wrap">

  <div class="topbar">
    <a class="back-btn" href="/uploadapp/apps?date=${selectedDate}">← Back to Apps</a>
    <div>
      <div class="page-title">🔍 Dynamic Analysis Results</div>
      <div class="page-sub">${esc(appData.appName || 'Unknown')} &nbsp;·&nbsp; ${esc(appData.packageName || sha256)} &nbsp;·&nbsp; Completed: ${new Date(da.completedAt).toLocaleString()}</div>
    </div>
  </div>

  <!-- ── 1. Environment Setup ─────────────────────────────────── -->
  <div class="section">
    ${sectionHdr('⚙️', 'Environment Setup')}
    <div class="env-grid">
      <div class="env-card"><div class="env-label">MobSFy Applied</div><div class="env-icon">${da.mobsfy_applied ? '✅' : '⚠️'}</div></div>
      <div class="env-card"><div class="env-label">Root CA Installed</div><div class="env-icon">${da.root_ca_installed ? '✅' : '⚠️'}</div></div>
      <div class="env-card"><div class="env-label">HTTPS Proxy</div><div class="env-icon">${da.proxy_set ? '✅' : '⚠️'}</div><div style="font-size:10px;color:#22c55e">${da.proxy_set ? 'Set' : ''}</div></div>
      <div class="env-card"><div class="env-label">Frida Hooks</div><div class="env-icon">${da.frida_applied ? '✅' : '⚠️'}</div></div>
      <div class="env-card"><div class="env-label">Activity Tester</div><div class="env-icon">${da.activity_tester_run ? '✅' : '⚠️'}</div></div>
      <div class="env-card"><div class="env-label">Device / Emulator</div><div class="env-icon" style="font-size:11px;color:#94a3b8;word-break:break-all">${esc(da.device_identifier || 'N/A')}</div></div>
    </div>
  </div>

  <!-- ── 2. TLS / SSL Security Tests ─────────────────────────── -->
  <div class="section">
    ${sectionHdr('🔒', 'TLS / SSL Security Tests', TLS_TESTS.length ? TLS_TESTS.length + ' tests' : null)}
    ${TLS_TESTS.length === 0
      ? `<p class="empty">TLS test data not captured. This happens when TLS tests run before the app starts network traffic. Re-run dynamic analysis and ensure the app makes HTTPS requests. You can view full TLS results on <a href="${MOBSF}/dynamic_report/${md5Hash || ''}" target="_blank">MobSF directly</a>.</p>`
      : TLS_TESTS.map(t => {
          const failed = !!tlsFlat[t.key];
          return `<div class="tls-row">
            <div class="tls-status">${riskBadge(failed)}</div>
            <div><div class="tls-name">${esc(t.name)}</div><div class="tls-desc">${t.desc}</div></div>
          </div>`;
        }).join('')
    }
  </div>

  <!-- ── 3. Traffic & Behaviour Summary ───────────────────────── -->
  <div class="section">
    ${sectionHdr('📊', 'Traffic & Behaviour Summary')}
    <div class="stat-grid">
      <div class="stat-card"><div class="stat-label">Domains Contacted</div><div class="stat-val ${domainList.length > 0 ? 'yellow' : 'green'}">${domainList.length}</div></div>
      <div class="stat-card"><div class="stat-label">URLs Found</div><div class="stat-val">${urlList.length}</div></div>
      <div class="stat-card"><div class="stat-label">Trackers</div><div class="stat-val ${trackerEntries.length > 0 ? 'red' : 'green'}">${da.trackers || trackerEntries.length}</div></div>
      <div class="stat-card"><div class="stat-label">Network Issues</div><div class="stat-val ${networkSec.length > 0 ? 'red' : 'green'}">${networkSec.length}</div></div>
      <div class="stat-card"><div class="stat-label">Open Redirects</div><div class="stat-val ${openRedirects.length > 0 ? 'red' : 'green'}">${openRedirects.length}</div></div>
      <div class="stat-card"><div class="stat-label">Exported Activities</div><div class="stat-val ${exportedActs.length > 0 ? 'yellow' : 'green'}">${exportedActs.length || da.exported_activities || 0}</div></div>
      <div class="stat-card"><div class="stat-label">Emails Found</div><div class="stat-val">${emailList.length}</div></div>
      <div class="stat-card"><div class="stat-label">Screenshots</div><div class="stat-val">${screenshots.length}</div></div>
    </div>
  </div>

  <!-- ── 4. Domains Contacted ─────────────────────────────────── -->
  ${domainList.length > 0 ? `
  <div class="section">
    ${sectionHdr('🌍', 'Domains Contacted', domainList.length)}
    <div class="tbl-wrap"><table>
      <tr><th>Domain</th><th>Status</th><th>IP Address</th><th>Country</th><th>City / Region</th><th>Coordinates</th></tr>
      ${domainList.map(([domain, info]) => {
        const geo = info?.geolocation || info?.geo || {};
        const flagged = info?.bad === true || info?.status === 'bad' || info?.malicious === true;
        const ip = geo.ip || info?.ip || '';
        const country = geo.country_long || geo.country || info?.country || '';
        const city = geo.city || '';
        const region = geo.region || '';
        const cityRegion = [city, region].filter(Boolean).join(', ');
        const lat = geo.latitude || geo.lat || '';
        const lon = geo.longitude || geo.lon || '';
        const coords = (lat && lon) ? `${Number(lat).toFixed(2)}, ${Number(lon).toFixed(2)}` : '';
        return `<tr>
          <td style="font-weight:500;color:#e2e8f0">${esc(domain)}</td>
          <td>${statusBadge(flagged)}</td>
          <td style="font-family:monospace;font-size:11px">${esc(ip)}</td>
          <td>${esc(country)}</td>
          <td>${esc(cityRegion)}</td>
          <td style="font-size:11px;color:#475569">${esc(coords)}</td>
        </tr>`;
      }).join('')}
    </table></div>
  </div>` : ''}

  <!-- ── 5. Trackers Detected ──────────────────────────────────── -->
  ${trackerEntries.length > 0 ? `
  <div class="section">
    ${sectionHdr('🕵️', 'Trackers Detected', trackerEntries.length)}
    <div class="tbl-wrap"><table>
      <tr><th>Tracker Name</th><th>Categories</th><th>Website</th></tr>
      ${trackerEntries.map(([name, info]) => {
        const cats = Array.isArray(info?.categories) ? info.categories : (info?.category ? [info.category] : []);
        const url = info?.url || info?.website || '';
        return `<tr>
          <td style="font-weight:500;color:#fca5a5">${esc(name)}</td>
          <td>${cats.map(c => `<span class="badge badge-yellow">${esc(c)}</span>`).join(' ')}</td>
          <td>${url ? `<a href="${esc(url)}" target="_blank" style="font-size:11px">${esc(url)}</a>` : '<span class="empty">—</span>'}</td>
        </tr>`;
      }).join('')}
    </table></div>
  </div>` : (da.trackers > 0 ? `
  <div class="section">
    ${sectionHdr('🕵️', 'Trackers Detected', da.trackers)}
    <p style="font-size:12px;color:#64748b">${da.trackers} tracker(s) detected. Detailed tracker names are available in the <a href="/uploadapp/dynamic-report/${sha256}?date=${selectedDate}">full PDF report</a>.</p>
  </div>` : '')}

  <!-- ── 6. URLs Found ─────────────────────────────────────────── -->
  ${urlList.length > 0 ? `
  <div class="section">
    ${sectionHdr('🔗', 'URLs Found', urlList.length)}
    <div class="chip-list">
      ${urlList.slice(0, 200).map(u => `<span class="chip url">${esc(u)}</span>`).join('')}
      ${urlList.length > 200 ? `<span class="chip">+${urlList.length - 200} more in PDF report</span>` : ''}
    </div>
  </div>` : ''}

  <!-- ── 7. Emails Found ───────────────────────────────────────── -->
  ${emailList.length > 0 ? `
  <div class="section">
    ${sectionHdr('📧', 'Emails Found', emailList.length)}
    <div class="chip-list">
      ${emailList.map(e => `<span class="chip email">${esc(e)}</span>`).join('')}
    </div>
  </div>` : ''}

  <!-- ── 8. Open Redirects ─────────────────────────────────────── -->
  ${openRedirects.length > 0 ? `
  <div class="section">
    ${sectionHdr('↪️', 'Open Redirects Detected', openRedirects.length)}
    <div class="tbl-wrap"><table>
      <tr><th>#</th><th>Redirect</th></tr>
      ${openRedirects.map((r, i) => `<tr><td>${i+1}</td><td>${esc(typeof r === 'string' ? r : JSON.stringify(r))}</td></tr>`).join('')}
    </table></div>
  </div>` : ''}

  <!-- ── 9. Exported / Exploitable Activities ─────────────────── -->
  ${exportedActs.length > 0 ? `
  <div class="section">
    ${sectionHdr('⚠️', 'Exported / Exploitable Activities', exportedActs.length)}
    <p style="font-size:11px;color:#64748b;margin-bottom:10px">These activities are exported and may be launchable by external apps without permission.</p>
    <div class="tbl-wrap"><table>
      <tr><th>#</th><th>Activity Name</th><th>Details</th></tr>
      ${exportedActs.map((a, i) => {
        const name = typeof a === 'string' ? a : (a.activity || a.name || JSON.stringify(a).substring(0,80));
        const det  = typeof a === 'object' ? (a.details || a.screenshot ? `Screenshot: ${a.screenshot || 'N/A'}` : '') : '';
        return `<tr><td style="color:#64748b">${i+1}</td><td style="font-family:monospace;font-size:11px;color:#fcd34d">${esc(name)}</td><td style="font-size:11px;color:#64748b">${esc(det)}</td></tr>`;
      }).join('')}
    </table></div>
  </div>` : ''}

  <!-- ── 10. Activities Tested ─────────────────────────────────── -->
  ${testedActs.length > 0 ? `
  <div class="section">
    ${sectionHdr('🏃', 'Activities Tested During Analysis', testedActs.length)}
    <details>
      <summary>Show / hide ${testedActs.length} activities</summary>
      <div class="chip-list" style="margin-top:8px">
        ${testedActs.map(a => `<span class="chip" style="font-family:monospace">${esc(typeof a === 'string' ? a : JSON.stringify(a))}</span>`).join('')}
      </div>
    </details>
  </div>` : ''}

  <!-- ── 11. Network Security Findings ────────────────────────── -->
  ${networkSec.length > 0 ? `
  <div class="section">
    ${sectionHdr('📡', 'Network Security Findings', networkSec.length)}
    <div class="tbl-wrap"><table>
      <tr><th>Finding</th><th>Description</th></tr>
      ${networkSec.slice(0,50).map(n => {
        const title = n.title || n.issue || n.name || JSON.stringify(n).substring(0,80);
        const desc  = n.description || n.details || n.info || '';
        return `<tr><td style="font-weight:500;color:#fca5a5">${esc(title)}</td><td style="font-size:11px">${esc(desc)}</td></tr>`;
      }).join('')}
    </table></div>
  </div>` : ''}

  <!-- ── 12. Clipboard Dump ────────────────────────────────────── -->
  ${clipboardData ? `
  <div class="section">
    ${sectionHdr('📋', 'Clipboard Dump')}
    <pre>${esc(typeof clipboardData === 'string' ? clipboardData : JSON.stringify(clipboardData, null, 2))}</pre>
  </div>` : ''}

  <!-- ── 13. Screenshots ───────────────────────────────────────── -->
  ${screenshots.length > 0 ? `
  <div class="section">
    ${sectionHdr('📷', 'Screenshots', screenshots.length)}
    ${md5Hash ? `
    <div class="ss-grid">
      ${screenshots.slice(0,20).map(s => {
        const fname = typeof s === 'string' ? s : (s.name || s.screenshot || '');
        const url = fname ? `${MOBSF}/screenshot/${md5Hash}/${fname}` : '';
        return fname
          ? `<div class="ss-item"><img src="${esc(url)}" alt="${esc(fname)}" onerror="this.style.display='none';this.nextSibling.textContent='Image not available'"/><span>${esc(fname)}</span></div>`
          : '';
      }).join('')}
    </div>
    ${screenshots.length > 20 ? `<p style="font-size:11px;color:#64748b;margin-top:8px">Showing first 20 of ${screenshots.length}. See full report on <a href="${MOBSF}/dynamic_report/${md5Hash}" target="_blank">MobSF</a>.</p>` : ''}` :
    `<p class="empty">Screenshots captured but MobSF hash unavailable for direct links. View on <a href="${MOBSF}" target="_blank">MobSF</a>.</p>`}
  </div>` : ''}

  <!-- ── 14. Other Files Created ───────────────────────────────── -->
  ${otherFiles.length > 0 ? `
  <div class="section">
    ${sectionHdr('📁', 'Other Files Created / Accessed', otherFiles.length)}
    <div class="tbl-wrap"><table>
      <tr><th>#</th><th>File Path</th></tr>
      ${otherFiles.slice(0,100).map((f, i) => `<tr><td style="color:#64748b">${i+1}</td><td style="font-family:monospace;font-size:11px">${esc(typeof f === 'string' ? f : JSON.stringify(f))}</td></tr>`).join('')}
      ${otherFiles.length > 100 ? `<tr><td colspan="2" style="color:#475569">… and ${otherFiles.length - 100} more</td></tr>` : ''}
    </table></div>
  </div>` : ''}

  <!-- ── 15. Frida API Monitor ─────────────────────────────────── -->
  ${apiCalls.length > 0 ? `
  <div class="section">
    ${sectionHdr('🪝', 'Frida API Monitor Calls', apiCalls.length)}
    ${apiCalls.length > 0 && apiCalls[0] && typeof apiCalls[0] === 'object' && apiCalls[0].data ? `
    <div class="tbl-wrap"><table>
      <tr><th>Method</th><th>Class</th><th>Arguments</th><th>Called From</th></tr>
      ${(Array.isArray(apiCalls[0].data) ? apiCalls[0].data : apiCalls).slice(0,50).map(call => {
        const c = typeof call === 'object' ? call : {};
        const args = Array.isArray(c.arguments) ? c.arguments.map(a => `<code>${esc(a)}</code>`).join(', ') : esc(JSON.stringify(c.arguments || ''));
        return `<tr>
          <td><span class="badge badge-blue">${esc(c.method || '—')}</span></td>
          <td style="font-family:monospace;font-size:10px;color:#a5b4fc">${esc(c.class || '—')}</td>
          <td style="font-size:11px">${args}</td>
          <td style="font-size:10px;color:#475569">${esc((c.calledFrom || '').split('(')[0])}</td>
        </tr>`;
      }).join('')}
    </table></div>
    <details><summary>View raw JSON</summary><pre>${esc(JSON.stringify(apiCalls, null, 2).substring(0, 6000))}</pre></details>` :
    `<pre>${esc(JSON.stringify(apiCalls, null, 2).substring(0, 6000))}</pre>`}
  </div>` : ''}

  <!-- ── 16. Frida Logs ────────────────────────────────────────── -->
  ${fridaLogs ? `
  <div class="section">
    ${sectionHdr('📝', 'Frida Logs')}
    <pre>${esc(typeof fridaLogs === 'string' ? fridaLogs.substring(0,4000) : JSON.stringify(fridaLogs, null, 2).substring(0,4000))}</pre>
  </div>` : ''}

  <!-- ── Download ──────────────────────────────────────────────── -->
  <div style="text-align:center;padding:24px 0 8px">
    <a class="dl-btn" href="/uploadapp/dynamic-report/${sha256}?date=${selectedDate}">📄 Download Full Dynamic Analysis PDF</a>
    ${md5Hash ? `<br/><a href="${MOBSF}/dynamic_report/${md5Hash}" target="_blank" style="font-size:12px;color:#64748b;display:block;margin-top:10px">View original MobSF report ↗</a>` : ''}
  </div>

</div>
</body>
</html>`;

    res.send(html);
  } catch (err) {
    console.error("[Dynamic Results] Error:", err.message);
    res.status(500).send(`<html><body style="background:#05090f;color:white;font-family:Arial;padding:40px"><h1>Error loading results</h1><p>${err.message}</p><a href="/uploadapp/apps" style="color:#60a5fa">← Back</a></body></html>`);
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


