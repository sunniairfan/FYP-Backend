const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { checkVirusTotal, analyzeFileWithVirusTotal } = require("../utils/virusTotal");
const { createNotification, getDetectedEnginesFromDoc } = require("../utils/notifications");
const {
  createAnalysisRequestFromHashCheck,
  isAlreadyUploadedFromDoc,
} = require("../utils/analysisRequests");
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
    let metadata = {};
    let rawMetadata = req.body?.metadata;

    if (!rawMetadata && req.files?.metadata?.[0]?.path) {
      try {
        rawMetadata = fs.readFileSync(req.files.metadata[0].path, "utf-8");
      } catch (readErr) {
        console.error("Failed to read metadata file:", readErr.message);
      }
    }

    try {
      if (typeof rawMetadata === "string") {
        metadata = JSON.parse(rawMetadata || "{}");
      } else if (rawMetadata && typeof rawMetadata === "object") {
        metadata = rawMetadata;
      }
    } catch (parseErr) {
      console.error("Failed to parse metadata JSON:", parseErr.message);
    }

    const apps = Array.isArray(metadata.apps)
      ? metadata.apps
      : Array.isArray(metadata.userApps)
        ? metadata.userApps
        : metadata.app
          ? [metadata.app]
          : metadata.packageName
            ? [metadata]
            : [];
    
    console.log(`📊 [UPLOAD] Extracted apps count: ${apps.length}, metadata keys: ${Object.keys(metadata)}`);
    
    if (apps.length === 0) {
      console.warn("⚠️  [UPLOAD] No app metadata found, creating fallback entry from APK filename");
      const fileName = path.parse(apkFile.originalname).name;
      apps.push({
        appName: fileName,
        packageName: fileName.toLowerCase().replace(/[^\w.-]/g, "_"),
        sizeMB: (apkFile.size / (1024 * 1024)).toFixed(2),
        permissions: [],
      });
    }

    const app = apps[0];
    const esClient = req.app.get("esClient");
    const ensureIndexExists = req.app.get("ensureIndexExists") || (async () => {});

    const uploadedFileHash = await calculateFileHash(apkFile.path);
    const expectedHash = app.sha256 || app.hash || app.sha256Hash;

    if (expectedHash) {
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
    } else {
      console.warn("No expected hash provided in metadata; skipping integrity check.");
    }

    const safePackageName = app.packageName || "unknown_package";
    const newFileName = `${safePackageName}_${Date.now()}.apk`;
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

      console.log(`✅ Updated existing app → ${safePackageName}: ${status}`);
    } else {
      if (isHashMalicious(uploadedFileHash)) {
        status = "malicious";
        source = "SignatureDB";
        console.log(`⚠️  [UPLOAD] Detected malicious app via SignatureDB: ${safePackageName}`);
      } else {
        status = "unknown";
        source = "User Upload";
        console.log(`➕ [UPLOAD] New app uploaded: ${safePackageName}`);
      }

      const dangerousPermissions = separateDangerousPermissions(app.permissions || []);

      const docData = {
        appName: app.appName || safePackageName,
        packageName: safePackageName,
        sha256: uploadedFileHash,
        sizeMB: app.sizeMB || (apkFile.size / (1024 * 1024)).toFixed(2),
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
      console.log(`📤 Indexed new app → ${safePackageName} (${status})`);
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
          console.error(`App not found for background MobSF analysis: ${safePackageName}`);
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

        // Count high and warning severity manifest issues (exported components, etc.)
        const manifestFindings = Array.isArray(report.manifest_analysis?.manifest_findings)
          ? report.manifest_analysis.manifest_findings
          : [];
        const highManifestIssues = manifestFindings.filter(
          (f) => f.severity === "high" || f.severity === "error"
        ).length;
        const warnManifestIssues = manifestFindings.filter(
          (f) => f.severity === "warning"
        ).length;

        // Count network security issues (cleartext traffic, etc.)
        const networkFindings = Array.isArray(report.network_security?.network_findings)
          ? report.network_security.network_findings
          : [];
        const highNetworkIssues = networkFindings.filter(
          (f) => f.severity === "high"
        ).length;

        const mobsfAnalysis = {
          security_score: report.security_score || 0,
          dangerous_permissions: dangerousPermissions,
          high_risk_findings: highRiskFindings,
          scan_type: uploadRes.scan_type || "unknown",
          file_name: uploadRes.file_name || path.basename(filePath),
          dynamic_analysis: {
            high_manifest_issues: highManifestIssues,
            warn_manifest_issues: warnManifestIssues,
            high_network_issues: highNetworkIssues,
            total_manifest_findings: manifestFindings.length,
            total_network_findings: networkFindings.length,
          },
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

        console.log(`Background MobSF analysis completed for ${safePackageName} (${uploadedFileHash})`);
      } catch (error) {
        console.error(`Background MobSF analysis failed for ${safePackageName}:`, error.message);
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

    console.log(`✅ [UPLOAD] Response sent for ${safePackageName}`);
    res.status(200).json({
      success: true,
      message: "APK uploaded successfully",
      app: {
        id: docId,
        packageName: safePackageName,
        appName: app.appName || safePackageName,
        status: status,
        source: source,
        fileName: newFileName,
        sha256: uploadedFileHash,
      },
    });
  } catch (err) {
    console.error("❌ [UPLOAD] Error processing APK upload:", err.message, err.stack);
    if (req.files && req.files.apk && req.files.apk[0] && fs.existsSync(req.files.apk[0].path)) {
      fs.unlinkSync(req.files.apk[0].path);
      console.log(`🗑️  [UPLOAD] Cleaned up failed APK file: ${req.files.apk[0].path}`);
    }
    res.status(500).json({
      success: false,
      error: "Failed to process APK upload",
      details: err.message,
    });
  }
};

// Controller to handle app scan requests - OPTIMIZED FOR PERFORMANCE
const receiveAppData = async (req, res) => {
  console.log(">>> Received scan request:", new Date().toISOString());
  console.log("Request body:", req.body);

  // Extract device information from request body
  const device_model = req.body.device_model || req.body.deviceModel || null;
  const device_id = req.body.device_id || req.body.deviceId || null;
  const scan_time = req.body.scan_time || req.body.scanTime || null;

  const userApps = req.body.userApps || [];
  const systemApps = req.body.systemApps || [];
  const esClient = req.app.get("esClient");

  if ((userApps.length === 0 && systemApps.length === 0) || (!Array.isArray(userApps) && !Array.isArray(systemApps))) {
    console.error("Invalid or missing userApps or systemApps array");
    return res.status(400).json({ error: "Invalid or missing userApps or systemApps array" });
  }

  const userResults = [];
  const systemResults = [];

  // OPTIMIZATION: Process apps concurrently in batches instead of sequentially
  const processingStartTime = Date.now();

  // Helper function to process a single app
  const processApp = async (app, appType) => {
    const { appName, packageName, sha256, sizeMB, permissions } = app;
    const uploadedByUserFlag = app.uploadedByUser === true;

    if (!packageName || !sha256) {
      console.error(`Missing packageName or sha256 for ${appType} app: ${packageName || "unknown"}`);
      return { packageName: packageName || "unknown", status: "error", error: "Missing packageName or sha256", appType };
    }

    let status = "unknown";
    let source = "Unknown";
    let virusTotalHashCheck = null;
    let existingDoc = null;
    let uploadTrigger = {
      required: false,
      queued: false,
      triggerType: null,
      threshold: 30,
      detectedEngines: 0,
      reason: null,
    };

    try {
      const ensureIndexExists = req.app.get("ensureIndexExists") || (async () => {});
      await ensureIndexExists(esClient);
      
      const existing = await esClient.search({
        index: getIndexName(),
        size: 1,
        query: { term: { sha256: { value: sha256 } } },
      });

      if (existing.hits.hits.length > 0) {
        existingDoc = existing.hits.hits[0];
        const doc = existingDoc;
        status = doc._source.status || "unknown";
        source = doc._source.source || "Elasticsearch";
        virusTotalHashCheck = doc._source.virusTotalHashCheck || null;

        const updateDoc = { timestamp: new Date(), appType };
        if (device_model) updateDoc.device_model = device_model;
        if (device_id) updateDoc.device_id = device_id;
        if (scan_time) updateDoc.scan_time = scan_time;

        await esClient.update({
          index: getIndexName(),
          id: doc._id,
          body: { doc: updateDoc },
        });

        if (uploadedByUserFlag && !doc._source.uploadedByUser) {
          await esClient.update({
            index: getIndexName(),
            id: doc._id,
            body: { doc: { uploadedByUser: true } },
          });
        }

        // For already-indexed apps, still trigger one-time notification based on stored VT data.
        let existingDetectedEngines = getDetectedEnginesFromDoc(doc._source);
        let existingTotalEngines =
          doc._source?.virusTotalHashCheck?.totalEngines ||
          doc._source?.virusTotalAnalysis?.totalEngines ||
          0;
        let existingDetectionRatio =
          doc._source?.virusTotalHashCheck?.detectionRatio ||
          doc._source?.virusTotalAnalysis?.detectionRatio ||
          "N/A";

        // If old docs don't have stored VT details, perform a hash lookup once in this flow.
        if (!Number.isFinite(existingDetectedEngines)) {
          const vtResult = await checkVirusTotal(sha256);
          if (vtResult && vtResult.status !== "unknown") {
            existingDetectedEngines = vtResult.detectedEngines;
            existingTotalEngines = vtResult.totalEngines;
            existingDetectionRatio = vtResult.detectionRatio;

            await esClient.update({
              index: getIndexName(),
              id: doc._id,
              body: {
                doc: {
                  status: vtResult.status,
                  source: "VirusTotal",
                  virusTotalHashCheck: {
                    detectionRatio: vtResult.detectionRatio,
                    totalEngines: vtResult.totalEngines,
                    detectedEngines: vtResult.detectedEngines,
                    scanTime: vtResult.scanTime,
                  },
                },
              },
            });
          }
        }

        if (Number.isFinite(existingDetectedEngines) && existingDetectedEngines >= 1) {
          createNotification(esClient, {
            appName: doc._source.appName || packageName,
            packageName,
            sha256,
            detectedEngines: existingDetectedEngines,
            totalEngines: existingTotalEngines,
            detectionRatio: existingDetectionRatio,
          }).catch((err) => console.error("❌ Notification error:", err.message));

        }

        if (Number.isFinite(existingDetectedEngines) && existingDetectedEngines >= 30) {
          const alreadyUploaded = isAlreadyUploadedFromDoc(doc._source);
          uploadTrigger = {
            required: !alreadyUploaded,
            queued: false,
            triggerType: !alreadyUploaded ? "apk_upload_request" : null,
            threshold: 30,
            detectedEngines: existingDetectedEngines,
            reason: alreadyUploaded
              ? "already_uploaded_today"
              : "detected_30_plus",
          };

          if (!alreadyUploaded) {
            const queued = await createAnalysisRequestFromHashCheck(esClient, {
              appName: doc._source.appName || packageName,
              packageName,
              sha256,
              detectionRatio: existingDetectionRatio,
              totalEngines: existingTotalEngines,
              detectedEngines: existingDetectedEngines,
              sourceIndex: getIndexName(),
              sourceDate: new Date().toISOString().slice(0, 10),
              alreadyUploaded,
            });

            uploadTrigger.queued = queued;
            if (!queued) {
              uploadTrigger.reason = "already_triggered_or_uploaded";
            }
          }
        }

        console.log(`✅ Already indexed → ${packageName} (${appType}): ${status} (${source})`);
      } else {
        if (isHashMalicious(sha256)) {
          status = "malicious";
          source = "SignatureDB";
          console.log(`Detected malicious ${appType} app via SignatureDB: ${packageName}`);
        } else {
          // Check with VirusTotal for hash lookup - async, non-blocking
          console.log(`🦠 Checking VirusTotal hash for ${appType} app: ${packageName}`);
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
            console.log(`✅ VirusTotal hash check for ${appType} app ${packageName}: ${status} (${vtResult.detectionRatio})`);

            // Send notification if engines detected (1-3: Suspicious, 4-29: Malicious, 30+: High Risk)
            if (vtResult.detectedEngines >= 1) {
              createNotification(esClient, {
                appName: appName || packageName,
                packageName,
                sha256,
                detectedEngines: vtResult.detectedEngines,
                totalEngines: vtResult.totalEngines,
                detectionRatio: vtResult.detectionRatio,
              }).catch((err) => console.error("❌ Notification error:", err.message));

            }

            if (vtResult.detectedEngines >= 30) {
              const queued = await createAnalysisRequestFromHashCheck(esClient, {
                appName: appName || packageName,
                packageName,
                sha256,
                detectionRatio: vtResult.detectionRatio,
                totalEngines: vtResult.totalEngines,
                detectedEngines: vtResult.detectedEngines,
                sourceIndex: getIndexName(),
                sourceDate: new Date().toISOString().slice(0, 10),
                alreadyUploaded: false,
              });

              uploadTrigger = {
                required: true,
                queued,
                triggerType: "apk_upload_request",
                threshold: 30,
                detectedEngines: vtResult.detectedEngines,
                reason: queued
                  ? "detected_30_plus"
                  : "already_triggered_or_uploaded",
              };
            }
          } else {
            console.log(`ℹ️  VirusTotal: Hash not found for ${appType} app ${packageName}`);
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
          appType,
        };

        if (device_model) docData.device_model = device_model;
        if (device_id) docData.device_id = device_id;
        if (scan_time) docData.scan_time = scan_time;

        await esClient.index({
          index: getIndexName(),
          document: docData,
        });
        console.log(`📤 Indexed (${appType} App Scan) → ${packageName} (${status})`);
      }

      return {
        packageName,
        status,
        source,
        virusTotalHashCheck,
        appType,
        uploadTrigger,
      };
    } catch (err) {
      console.error(`❌ Error processing ${appType} app ${packageName}:`, err.message);
      return { packageName, status: "error", error: err.message, appType };
    }
  };

  // Process all apps concurrently in parallel batches for better performance
  const batchSize = 5; // Process 5 apps at a time
  
  const processAppsInBatches = async (apps, appType) => {
    const results = [];
    for (let i = 0; i < apps.length; i += batchSize) {
      const batch = apps.slice(i, i + batchSize);
      const batchResults = await Promise.allSettled(
        batch.map(app => processApp(app, appType))
      );
      
      batchResults.forEach((result, idx) => {
        if (result.status === "fulfilled") {
          results.push(result.value);
        } else {
          results.push({
            packageName: batch[idx].packageName || "unknown",
            status: "error",
            error: result.reason?.message || "Unknown error",
            appType
          });
        }
      });
    }
    return results;
  };

  try {
    // Process user and system apps concurrently
    const [userResultsProcessing, systemResultsProcessing] = await Promise.all([
      processAppsInBatches(userApps, "user"),
      processAppsInBatches(systemApps, "system")
    ]);

    userResults.push(...userResultsProcessing);
    systemResults.push(...systemResultsProcessing);

    const processingTimeMs = Date.now() - processingStartTime;
    console.log(`⏱️  Processing completed in ${processingTimeMs}ms for ${userApps.length + systemApps.length} apps`);
    
    console.log("User Apps Results:", userResults);
    console.log("System Apps Results:", systemResults);
    
    // Return results immediately to frontend (non-blocking)
    res.status(200).json({ 
      message: "Scan complete", 
      processingTimeMs,
      userApps: userResults,
      systemApps: systemResults
    });
  } catch (err) {
    console.error("Error during app processing:", err.message);
    res.status(500).json({
      message: "Error processing apps",
      error: err.message,
      userApps: userResults,
      systemApps: systemResults
    });
  }
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

    // Determine new status from ML prediction label
    const normalizedLabel = (mlPredictionLabel || '').toUpperCase();
    let newStatus;
    if (normalizedLabel === 'SAFE') {
      newStatus = 'safe';
    } else if (normalizedLabel === 'MALICIOUS' || normalizedLabel === 'MALWARE') {
      newStatus = 'malicious';
    } else if (normalizedLabel === 'RISKY' || normalizedLabel === 'SUSPICIOUS') {
      newStatus = 'suspicious';
    } else {
      // Threshold-based fallback using score (0–1 probability)
      const score = parseFloat(mlPredictionScore);
      if (score < 0.3) newStatus = 'safe';
      else if (score < 0.6) newStatus = 'suspicious';
      else newStatus = 'malicious';
    }

    const mlPredictionData = {
      mlPredictionScore: parseFloat(mlPredictionScore),
      mlPredictionLabel: mlPredictionLabel,
      mlAnalysisTimestamp: new Date().toISOString()
    };

    // Update the document with ML prediction data AND updated status
    await esClient.update({
      index: indexName,
      id: docId,
      body: {
        doc: {
          ...mlPredictionData,
          mlAnalysisDate: new Date(),
          status: newStatus
        },
      },
    });

    console.log(`🤖 ML Prediction stored for ${packageName} (Status updated: ${doc._source.status} → ${newStatus})`);
    console.log(`   Score: ${mlPredictionScore}, Label: ${mlPredictionLabel}`);

    res.status(200).json({
      message: "ML Prediction stored successfully",
      packageName,
      mlPredictionScore,
      mlPredictionLabel,
      previousStatus: doc._source.status,
      currentStatus: newStatus,
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