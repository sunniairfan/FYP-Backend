const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { checkVirusTotal, analyzeFileWithVirusTotal } = require("../utils/virusTotal");
const mobsf = require("../utils/mobsf");

// Path to signature database
const signaturePath = path.join(__dirname, "../signatureDB.json");
const knownHashes = fs.existsSync(signaturePath)
  ? JSON.parse(fs.readFileSync(signaturePath, "utf-8"))
  : [];

// Directory for storing uploaded APK files
const uploadsDir = path.join(__dirname, "../uploads/apks");

// Create uploads directory if it doesn't exist
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Helper function to get dynamic index name
const getIndexName = () => {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, "0");
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const year = today.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
};

const isHashMalicious = (hash) => knownHashes.includes(hash);

// Calculate SHA-256 hash of a file
const calculateFileHash = (filePath) => {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (data) => hash.update(data));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", (err) => reject(err));
  });
};

// Filter dangerous Android permissions from a list
const separateDangerousPermissions = (permissions) => {
  const dangerousPerms = permissions.filter((perm) => {
    const dangerousPermissions = [
      "android.permission.CAMERA",
      "android.permission.RECORD_AUDIO",
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.ACCESS_COARSE_LOCATION",
      "android.permission.ACCESS_BACKGROUND_LOCATION",
      "android.permission.READ_CONTACTS",
      "android.permission.WRITE_CONTACTS",
      "android.permission.READ_SMS",
      "android.permission.SEND_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.READ_PHONE_STATE",
      "android.permission.READ_PHONE_NUMBERS",
      "android.permission.CALL_PHONE",
      "android.permission.READ_CALL_LOG",
      "android.permission.WRITE_CALL_LOG",
      "android.permission.READ_EXTERNAL_STORAGE",
      "android.permission.WRITE_EXTERNAL_STORAGE",
      "android.permission.READ_MEDIA_IMAGES",
      "android.permission.READ_MEDIA_VIDEO",
      "android.permission.READ_MEDIA_AUDIO",
      "android.permission.MANAGE_EXTERNAL_STORAGE",
      "android.permission.GET_ACCOUNTS",
      "android.permission.READ_CALENDAR",
      "android.permission.WRITE_CALENDAR",
    ];
    return dangerousPermissions.includes(perm);
  });

  const result = {};
  dangerousPerms.forEach((perm, index) => {
    result[`dangerousPermission${index + 1}`] = perm;
  });
  
  return result;
};

// Controller to handle APK uploads
const uploadApp = async (req, res) => {
  console.log(">>> Received APK upload request:", new Date().toISOString());
  console.log("Request headers:", req.headers);
  console.log("Request body metadata:", req.body.metadata);
  console.log("Uploaded files:", req.files);
  
  try {
    if (!req.files || !req.files.apk || !req.files.apk[0]) {
      console.error("No APK file uploaded");
      return res.status(400).json({ error: "No APK file uploaded" });
    }

    const apkFile = req.files.apk[0];
    const metadata = JSON.parse(req.body.metadata || "{}");
    const apps = metadata.apps || [];
    
    if (apps.length === 0) {
      console.error("No app metadata provided");
      fs.unlinkSync(apkFile.path);
      return res.status(400).json({ error: "No app metadata provided" });
    }

    const app = apps[0];
    const esClient = req.app.get("esClient");
    const ensureIndexExists = req.app.get("ensureIndexExists") || (async () => {});

    const uploadedFileHash = await calculateFileHash(apkFile.path);
    const expectedHash = app.sha256;

    if (uploadedFileHash.toLowerCase() !== expectedHash.toLowerCase()) {
      console.error("File integrity check failed", {
        expected: expectedHash,
        actual: uploadedFileHash,
      });
      fs.unlinkSync(apkFile.path);
      return res.status(400).json({
        error: "File integrity check failed",
        expected: expectedHash,
        actual: uploadedFileHash,
      });
    }

    const newFileName = `${app.packageName}_${Date.now()}.apk`;
    const newFilePath = path.join(uploadsDir, newFileName);
    fs.renameSync(apkFile.path, newFilePath);
    console.log(`Renamed file to: ${newFilePath}`);

    let status = "unknown";
    let source = "Unknown";

    await ensureIndexExists(esClient);
    const existing = await esClient.search({
      index: getIndexName(),
      size: 1,
      query: { term: { sha256: { value: uploadedFileHash } } },
    });

    let docId;

    if (existing.hits.hits.length > 0) {
      const doc = existing.hits.hits[0];
      docId = doc._id;
      status = doc._source.status || "unknown";
      source = doc._source.source || "Elasticsearch";

      await esClient.update({
        index: getIndexName(),
        id: docId,
        body: {
          doc: {
            uploadedByUser: true,
            timestamp: new Date(),
            apkFilePath: newFilePath,
            apkFileName: newFileName,
            uploadSource: "android_app",
          },
        },
      });

      console.log(`✅ Updated existing app → ${app.packageName}: ${status}`);
    } else {
      if (isHashMalicious(uploadedFileHash)) {
        status = "malicious";
        source = "SignatureDB";
        console.log(`Detected malicious app via SignatureDB: ${app.packageName}`);
      } else {
        status = "unknown";
        source = "User Upload";
        console.log(`New app uploaded: ${app.packageName} - awaiting manual analysis`);
      }

      const dangerousPermissions = separateDangerousPermissions(app.permissions || []);

      const docData = {
        appName: app.appName,
        packageName: app.packageName,
        sha256: uploadedFileHash,
        sizeMB: app.sizeMB,
        ...dangerousPermissions,
        status: status,
        source: source,
        timestamp: new Date(),
        uploadedByUser: true,
        apkFilePath: newFilePath,
        apkFileName: newFileName,
        uploadSource: "android_app",
      };

      const indexResponse = await esClient.index({
        index: getIndexName(),
        document: docData,
      });

      docId = indexResponse._id;
      console.log(`📤 Indexed new app → ${app.packageName} (${status})`);
    }

    // Trigger MobSF analysis in the background
    setTimeout(async () => {
      try {
        const dynamicIndex = getIndexName();
        const searchRes = await esClient.search({
          index: dynamicIndex,
          size: 1,
          query: { term: { sha256: { value: uploadedFileHash } } },
        });

        if (searchRes.hits.hits.length === 0) {
          console.error(`App not found for background MobSF analysis: ${app.packageName}`);
          return;
        }

        const docId = searchRes.hits.hits[0]._id;
        const appData = searchRes.hits.hits[0]._source;
        const filePath = appData.apkFilePath;

        if (!filePath || !fs.existsSync(filePath)) {
          console.error(`APK file not found for MobSF analysis: ${filePath || 'undefined'}`);
          await esClient.update({
            index: dynamicIndex,
            id: docId,
            body: {
              doc: {
                mobsfStatus: "analysis_failed",
                mobsfError: `APK file not found: ${filePath || 'undefined'}`,
                lastMobsfAnalysis: new Date().toISOString(),
              },
            },
          });
          return;
        }

        const uploadRes = await mobsf.uploadToMobSF(filePath);
        const md5Hash = uploadRes.hash;
        await mobsf.scanWithMobSF(md5Hash);
        const report = await mobsf.getJsonReport(md5Hash);

        const dangerousPermissions = Object.entries(report.permissions || {})
          .filter(([_, perm]) => perm.status === "dangerous")
          .map(([perm]) => perm);

        const highRiskFindings = Object.entries(report.code_analysis || {})
          .filter(([_, finding]) => finding.metadata.severity === "high")
          .length;

        const mobsfAnalysis = {
          security_score: report.security_score || 0,
          dangerous_permissions: dangerousPermissions,
          high_risk_findings: highRiskFindings,
          scan_type: uploadRes.scan_type || "unknown",
          file_name: uploadRes.file_name || path.basename(filePath),
        };

        let mobsfStatus = "unknown";
        if (report.security_score >= 70) mobsfStatus = "safe";
        else if (report.security_score < 40) mobsfStatus = "malicious";
        else mobsfStatus = "suspicious";

        await esClient.update({
          index: dynamicIndex,
          id: docId,
          body: {
            doc: {
              mobsfAnalysis,
              lastMobsfAnalysis: new Date().toISOString(),
              mobsfHash: md5Hash,
              mobsfScanType: uploadRes.scan_type,
              mobsfStatus: mobsfStatus,  // Store MobSF status separately
            },
          },
        });

        console.log(`Background MobSF analysis completed for ${app.packageName} (${uploadedFileHash})`);
      } catch (error) {
        console.error(`Background MobSF analysis failed for ${app.packageName}:`, error.message);
        try {
          const dynamicIndex = getIndexName();
          const searchRes = await esClient.search({
            index: dynamicIndex,
            size: 1,
            query: { term: { sha256: { value: uploadedFileHash } } },
          });

          if (searchRes.hits.hits.length > 0) {
            const docId = searchRes.hits.hits[0]._id;
            await esClient.update({
              index: dynamicIndex,
              id: docId,
              body: {
                doc: {
                  mobsfStatus: "analysis_failed",
                  mobsfError: error.message,
                  lastMobsfAnalysis: new Date().toISOString(),
                },
              },
            });
          }
        } catch (updateError) {
          console.error(`Failed to update MobSF error status:`, updateError.message);
        }
      }
    }, 0);

    res.status(200).json({
      message: "APK uploaded and queued for MobSF analysis",
      app: {
        id: docId,
        packageName: app.packageName,
        appName: app.appName,
        status: status,
        source: source,
        fileName: newFileName,
        sha256: uploadedFileHash,
      },
    });
  } catch (err) {
    console.error("❌ Error processing APK upload:", err.message, err.stack);
    if (req.files && req.files.apk && req.files.apk[0] && fs.existsSync(req.files.apk[0].path)) {
      fs.unlinkSync(req.files.apk[0].path);
      console.log(`Cleaned up failed APK file: ${req.files.apk[0].path}`);
    }
    res.status(500).json({
      error: "Failed to process APK upload",
      details: err.message,
    });
  }
};

// Controller to handle app scan requests
const receiveAppData = async (req, res) => {
  console.log(">>> Received scan request:", new Date().toISOString());
  console.log("Request body:", req.body);

  const userApps = req.body.userApps || [];
  const systemApps = req.body.systemApps || [];
  const esClient = req.app.get("esClient");

  if ((userApps.length === 0 && systemApps.length === 0) || (!Array.isArray(userApps) && !Array.isArray(systemApps))) {
    console.error("Invalid or missing userApps or systemApps array");
    return res.status(400).json({ error: "Invalid or missing userApps or systemApps array" });
  }

  const userResults = [];
  const systemResults = [];

  // Process user apps
  for (const app of userApps) {
    const { appName, packageName, sha256, sizeMB, permissions } = app;
    const uploadedByUserFlag = app.uploadedByUser === true;

    if (!packageName || !sha256) {
      console.error(`Missing packageName or sha256 for user app: ${packageName || "unknown"}`);
      userResults.push({ packageName: packageName || "unknown", status: "error", error: "Missing packageName or sha256", appType: "user" });
      continue;
    }

    let status = "unknown";
    let source = "Unknown";
    let virusTotalHashCheck = null;

    try {
      const ensureIndexExists = req.app.get("ensureIndexExists") || (async () => {});
      await ensureIndexExists(esClient);
      const existing = await esClient.search({
        index: getIndexName(),
        size: 1,
        query: { term: { sha256: { value: sha256 } } },
      });

      if (existing.hits.hits.length > 0) {
        const doc = existing.hits.hits[0];
        status = doc._source.status || "unknown";
        source = doc._source.source || "Elasticsearch";
        virusTotalHashCheck = doc._source.virusTotalHashCheck || null;

        await esClient.update({
          index: getIndexName(),
          id: doc._id,
          body: { doc: { timestamp: new Date(), appType: "user" } },
        });

        if (uploadedByUserFlag && !doc._source.uploadedByUser) {
          await esClient.update({
            index: getIndexName(),
            id: doc._id,
            body: { doc: { uploadedByUser: true } },
          });
        }

        console.log(`✅ Already indexed → ${packageName} (User): ${status} (${source})`);
      } else {
        if (isHashMalicious(sha256)) {
          status = "malicious";
          source = "SignatureDB";
          console.log(`Detected malicious user app via SignatureDB: ${packageName}`);
        } else {
          // Check with VirusTotal for hash lookup
          console.log(`🦠 Checking VirusTotal hash for user app: ${packageName}`);
          const vtResult = await checkVirusTotal(sha256);
          
          if (vtResult && vtResult.status !== "unknown") {
            status = vtResult.status;
            source = "VirusTotal";
            virusTotalHashCheck = {
              detectionRatio: vtResult.detectionRatio,
              totalEngines: vtResult.totalEngines,
              detectedEngines: vtResult.detectedEngines,
              scanTime: vtResult.scanTime
            };
            console.log(`✅ VirusTotal hash check for user app ${packageName}: ${status} (${vtResult.detectionRatio})`);
          } else {
            console.log(`ℹ️  VirusTotal: Hash not found for user app ${packageName}`);
            status = "unknown";
            source = "Unknown";
          }
        }

        const dangerousPermissions = separateDangerousPermissions(permissions || []);

        const docData = {
          appName,
          packageName,
          sha256,
          sizeMB,
          ...dangerousPermissions,
          status,
          source,
          timestamp: new Date(),
          uploadedByUser: uploadedByUserFlag,
          virusTotalHashCheck,
          appType: "user",
        };

        await esClient.index({
          index: getIndexName(),
          document: docData,
        });
        console.log(`📤 Indexed (User App Scan) → ${packageName} (${status})`);
      }

      userResults.push({ packageName, status, source, virusTotalHashCheck, appType: "user" });
    } catch (err) {
      console.error(`❌ Error processing user app ${packageName}:`, err.message);
      userResults.push({ packageName, status: "error", error: err.message, appType: "user" });
    }
  }

  // Process system apps
  for (const app of systemApps) {
    const { appName, packageName, sha256, sizeMB, permissions } = app;
    const uploadedByUserFlag = app.uploadedByUser === true;

    if (!packageName || !sha256) {
      console.error(`Missing packageName or sha256 for system app: ${packageName || "unknown"}`);
      systemResults.push({ packageName: packageName || "unknown", status: "error", error: "Missing packageName or sha256", appType: "system" });
      continue;
    }

    let status = "unknown";
    let source = "Unknown";
    let virusTotalHashCheck = null;

    try {
      const ensureIndexExists = req.app.get("ensureIndexExists") || (async () => {});
      await ensureIndexExists(esClient);
      const existing = await esClient.search({
        index: getIndexName(),
        size: 1,
        query: { term: { sha256: { value: sha256 } } },
      });

      if (existing.hits.hits.length > 0) {
        const doc = existing.hits.hits[0];
        status = doc._source.status || "unknown";
        source = doc._source.source || "Elasticsearch";
        virusTotalHashCheck = doc._source.virusTotalHashCheck || null;

        await esClient.update({
          index: getIndexName(),
          id: doc._id,
          body: { doc: { timestamp: new Date(), appType: "system" } },
        });

        if (uploadedByUserFlag && !doc._source.uploadedByUser) {
          await esClient.update({
            index: getIndexName(),
            id: doc._id,
            body: { doc: { uploadedByUser: true } },
          });
        }

        console.log(`✅ Already indexed → ${packageName} (System): ${status} (${source})`);
      } else {
        if (isHashMalicious(sha256)) {
          status = "malicious";
          source = "SignatureDB";
          console.log(`Detected malicious system app via SignatureDB: ${packageName}`);
        } else {
          // Check with VirusTotal for hash lookup for SYSTEM APPS
          console.log(`🦠 Checking VirusTotal hash for system app: ${packageName}`);
          const vtResult = await checkVirusTotal(sha256);
          
          if (vtResult && vtResult.status !== "unknown") {
            status = vtResult.status;
            source = "VirusTotal";
            virusTotalHashCheck = {
              detectionRatio: vtResult.detectionRatio,
              totalEngines: vtResult.totalEngines,
              detectedEngines: vtResult.detectedEngines,
              scanTime: vtResult.scanTime
            };
            console.log(`✅ VirusTotal hash check for system app ${packageName}: ${status} (${vtResult.detectionRatio})`);
          } else {
            console.log(`ℹ️  VirusTotal: Hash not found for system app ${packageName}`);
            status = "unknown";
            source = "Unknown";
          }
        }

        const dangerousPermissions = separateDangerousPermissions(permissions || []);

        const docData = {
          appName,
          packageName,
          sha256,
          sizeMB,
          ...dangerousPermissions,
          status,
          source,
          timestamp: new Date(),
          uploadedByUser: uploadedByUserFlag,
          virusTotalHashCheck,
          appType: "system",
        };

        await esClient.index({
          index: getIndexName(),
          document: docData,
        });
        console.log(`📤 Indexed (System App Scan) → ${packageName} (${status})`);
      }

      systemResults.push({ packageName, status, source, virusTotalHashCheck, appType: "system" });
    } catch (err) {
      console.error(`❌ Error processing system app ${packageName}:`, err.message);
      systemResults.push({ packageName, status: "error", error: err.message, appType: "system" });
    }
  }

  console.log("User Apps Results:", userResults);
  console.log("System Apps Results:", systemResults);
  res.status(200).json({ 
    message: "Scan complete", 
    userApps: userResults,
    systemApps: systemResults
  });
};

const getAppDetails = async (req, res) => {
  const { identifier } = req.params;
  const esClient = req.app.get("esClient");

  try {
    const ensureIndexExists = req.app.get("ensureIndexExists") || (async () => {});
    await ensureIndexExists(esClient);
    let searchQuery;

    if (/^[a-fA-F0-9]{64}$/.test(identifier)) {
      searchQuery = { term: { sha256: { value: identifier } } };
    } else {
      const result = await esClient.get({
        index: getIndexName(),
        id: identifier,
      });
      return res.status(200).json({
        app: {
          id: result._id,
          ...result._source,
        },
      });
    }

    const searchRes = await esClient.search({
      index: getIndexName(),
      size: 1,
      query: searchQuery,
    });

    if (searchRes.hits.hits.length === 0) {
      console.error(`App not found for identifier: ${identifier}`);
      return res.status(404).json({ error: "App not found" });
    }

    const doc = searchRes.hits.hits[0];
    res.status(200).json({
      app: {
        id: doc._id,
        ...doc._source,
      },
    });
  } catch (err) {
    console.error("Error fetching app details:", err.message);
    res.status(500).json({ error: "Failed to fetch app details" });
  }
};

const downloadApp = (req, res) => {
  const fileName = req.params.fileName;
  const filePath = path.join(uploadsDir, fileName);

  if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    return res.status(404).json({ error: "File not found" });
  }

  res.download(filePath, fileName, (err) => {
    if (err) {
      console.error("Error downloading file:", err.message);
      res.status(500).json({ error: "Failed to download file" });
    }
  });
};

const deleteApp = async (req, res) => {
  const { sha256 } = req.params;
  const esClient = req.app.get("esClient");

  try {
    const ensureIndexExists = req.app.get("ensureIndexExists") || (async () => {});
    await ensureIndexExists(esClient);

    const searchRes = await esClient.search({
      index: getIndexName(),
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      console.error(`App not found for SHA256: ${sha256}`);
      return res.status(404).json({ error: "App not found" });
    }

    const doc = searchRes.hits.hits[0];
    const appData = doc._source;

    if (appData.mobsfHash) {
      try {
        await mobsf.deleteScan(appData.mobsfHash);
        console.log(`🗑️ Deleted MobSF scan for ${appData.packageName}`);
      } catch (mobsfErr) {
        console.error(`Failed to delete MobSF scan for ${appData.packageName}:`, mobsfErr.message);
      }
    }

    if (appData.apkFilePath && fs.existsSync(appData.apkFilePath)) {
      fs.unlinkSync(appData.apkFilePath);
      console.log(`🗑️ Deleted APK file: ${appData.apkFileName}`);
    }

    await esClient.delete({
      index: getIndexName(),
      id: doc._id,
    });

    console.log(`🗑️ Deleted app from database: ${appData.packageName}`);

    res.status(200).json({
      message: "App and APK file deleted successfully",
      packageName: appData.packageName,
    });
  } catch (err) {
    console.error("Error deleting app:", err.message);
    res.status(500).json({ error: "Failed to delete app" });
  }
};

// Store ML Prediction Results
const storeMLPrediction = async (req, res) => {
  const esClient = req.app.get("esClient");
  const ensureIndexExists = req.app.get("ensureIndexExists") || (async () => {});

  try {
    const { packageName, mlPredictionScore, mlPredictionLabel, confidence, timestamp } = req.body;

    if (!packageName || mlPredictionScore === undefined || !mlPredictionLabel) {
      return res.status(400).json({
        error: "Missing required fields: packageName, mlPredictionScore, mlPredictionLabel"
      });
    }

    await ensureIndexExists(esClient);

    // Search for the app by packageName in the current date's index
    const indexName = getIndexName();
    const searchResult = await esClient.search({
      index: indexName,
      query: { term: { packageName: { value: packageName } } },
      size: 1,
    });

    if (searchResult.hits.hits.length === 0) {
      console.warn(`🤖 ML Prediction: App not found for ${packageName}`);
      return res.status(404).json({
        error: "App not found in database",
        packageName
      });
    }

    const doc = searchResult.hits.hits[0];
    const docId = doc._id;

    // Prepare ML prediction data (stored separately, does NOT update overall status)
    const mlPredictionData = {
      mlPredictionScore: parseFloat(mlPredictionScore),
      mlPredictionLabel: mlPredictionLabel, // "safe", "risky", "malware"
      mlAnalysisTimestamp: new Date().toISOString()
    };

    // Update the document with ML prediction data ONLY (status remains unchanged)
    await esClient.update({
      index: indexName,
      id: docId,
      body: {
        doc: {
          ...mlPredictionData,
          mlAnalysisDate: new Date()
        },
      },
    });

    console.log(`🤖 ML Prediction stored for ${packageName} (Status NOT updated - kept as: ${doc._source.status})`);
    console.log(`   Score: ${mlPredictionScore}, Label: ${mlPredictionLabel}`);

    res.status(200).json({
      message: "ML Prediction stored successfully (status unchanged)",
      packageName,
      mlPredictionScore,
      mlPredictionLabel,
      currentStatus: doc._source.status,
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    console.error("Error storing ML prediction:", err.message);
    res.status(500).json({
      error: "Failed to store ML prediction",
      details: err.message
    });
  }
};

module.exports = {
  receiveAppData,
  uploadApp,
  getAppDetails,
  downloadApp,
  deleteApp,
  storeMLPrediction,
  separateDangerousPermissions,
  isHashMalicious,
};