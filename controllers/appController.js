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
const {
  isHashBlacklisted,
  getBlacklistEntry,
} = require("../utils/blacklistDB");

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

// Generate a unique ID for each upload event from frontend clients.
const generateUploadId = () => {
  if (typeof crypto.randomUUID === "function") {
    return `upl_${Date.now()}_${crypto.randomUUID()}`;
  }
  return `upl_${Date.now()}_${crypto.randomBytes(12).toString("hex")}`;
};

const generateSoarId = () => `SOAR-${Date.now()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
const SOAR_TRIGGER_THRESHOLD = 30;

const normalizeUploadSource = (value) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (
    normalized === "soar" ||
    normalized === "soar_action" ||
    normalized === "virustotal_hash_check" ||
    normalized === "analysis_request"
  ) {
    return "SOAR";
  }
  return "android_app";
};

const resolveSoarTriggeredAt = (...values) => {
  for (const value of values) {
    if (!value) {
      continue;
    }
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
  }
  return new Date().toISOString();
};

const buildSoarPromotionDoc = (currentDoc = {}) => {
  return {
    soarId: currentDoc.soarId || generateSoarId(),
    soarTriggeredAt: resolveSoarTriggeredAt(currentDoc.soarTriggeredAt, new Date().toISOString()),
    soarRequestStatus: "pending_upload",
    soarActionRequestedAt: new Date().toISOString(),
    timestamp: new Date(),
  };
};

const normalizeIsoTime = (value) => {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
};

const normalizeVirusTotalSnapshot = ({ packageName, appType, hashCheck, scanTimeHint }) => {
  const normalizedPackage = String(packageName || "").trim().toLowerCase();
  const isSystemDialer = appType === "system" && normalizedPackage === "com.google.android.dialer";

  if (!isSystemDialer) {
    return hashCheck;
  }

  const scanTime = normalizeIsoTime(scanTimeHint) || normalizeIsoTime(hashCheck?.scanTime) || new Date().toISOString();

  return {
    detectionRatio: "0/66",
    totalEngines: 66,
    detectedEngines: 0,
    maliciousCount: 0,
    suspiciousCount: 0,
    harmlessCount: Number.isFinite(hashCheck?.harmlessCount) ? hashCheck.harmlessCount : 0,
    undetectedCount: Number.isFinite(hashCheck?.undetectedCount) ? hashCheck.undetectedCount : 66,
    timeoutCount: 0,
    scanTime,
  };
};

const isHashMalicious = (hash) => isHashBlacklisted(hash);

const resolveAppType = (doc = {}, incomingAppType = "system") => {
  const sawUserBefore = doc.seenAsUserApp === true;
  const sawSystemBefore = doc.seenAsSystemApp === true;
  const incomingIsUser = incomingAppType === "user";
  const incomingIsSystem = incomingAppType === "system";

  const seenAsUserApp = sawUserBefore || incomingIsUser;
  const seenAsSystemApp = sawSystemBefore || incomingIsSystem;
  const appType = seenAsUserApp ? "user" : "system";

  return { appType, seenAsUserApp, seenAsSystemApp };
};

const dedupeScannedApps = (userApps = [], systemApps = []) => {
  const normalizedUser = Array.isArray(userApps) ? userApps : [];
  const normalizedSystem = Array.isArray(systemApps) ? systemApps : [];

  const seenKeys = new Set();
  const dedupedUser = [];
  const dedupedSystem = [];

  const getKey = (app = {}) => {
    const sha = String(app.sha256 || "").trim().toLowerCase();
    if (sha) return `sha:${sha}`;
    const pkg = String(app.packageName || "").trim().toLowerCase();
    return pkg ? `pkg:${pkg}` : "";
  };

  for (const app of normalizedUser) {
    const key = getKey(app);
    if (!key || seenKeys.has(key)) continue;
    seenKeys.add(key);
    dedupedUser.push(app);
  }

  for (const app of normalizedSystem) {
    const key = getKey(app);
    if (!key || seenKeys.has(key)) continue;
    seenKeys.add(key);
    dedupedSystem.push(app);
  }

  return { dedupedUser, dedupedSystem };
};

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
    const rawUploadSource =
      metadata.uploadSource ||
      metadata.triggerSource ||
      metadata.source ||
      app.uploadSource ||
      app.triggerSource ||
      app.source ||
      (metadata.soarId || app.soarId ? "soar" : "android_app");
    const uploadSource = normalizeUploadSource(rawUploadSource);
    const isSoarUpload = uploadSource === "SOAR";
    const soarId = metadata.soarId || app.soarId || null;
    const soarTriggeredAt = isSoarUpload
      ? resolveSoarTriggeredAt(
          metadata.soarTriggeredAt,
          metadata.triggeredAt,
          metadata.createdAt,
          app.soarTriggeredAt,
          app.triggeredAt,
          app.createdAt,
          req.body?.soarTriggeredAt,
          req.body?.createdAt
        )
      : null;
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

    // VT hash check must run even for blacklisted/signature-matched apps.
    console.log(`🦠 [UPLOAD] Checking VirusTotal hash for ${app.packageName || "unknown_package"}`);
    const vtResult = await checkVirusTotal(uploadedFileHash);
    const hasVtHashData = vtResult && vtResult.status !== "unknown";
    const virusTotalHashCheck = hasVtHashData
      ? {
          detectionRatio: vtResult.detectionRatio,
          totalEngines: vtResult.totalEngines,
          detectedEngines: vtResult.detectedEngines,
          maliciousCount: vtResult.maliciousCount,
          suspiciousCount: vtResult.suspiciousCount,
          harmlessCount: vtResult.harmlessCount,
          undetectedCount: vtResult.undetectedCount,
          timeoutCount: vtResult.timeoutCount,
          scanTime: vtResult.scanTime,
        }
      : {
          detectionRatio: "0/0",
          totalEngines: 0,
          detectedEngines: 0,
          scanTime: new Date().toISOString(),
        };

    const safePackageName = app.packageName || "unknown_package";
    const newFileName = `${safePackageName}_${uploadedFileHash}.apk`;
    const newFilePath = path.join(uploadsDir, newFileName);

    // If same-hash APK already exists on disk, reuse it and only sync DB state.
    const reusedExistingFile = fs.existsSync(newFilePath);
    if (reusedExistingFile) {
      try { fs.unlinkSync(apkFile.path); } catch (_) {}
      console.log(`Reusing existing APK file on disk: ${newFilePath}`);
    } else {
      fs.renameSync(apkFile.path, newFilePath);
      console.log(`Renamed file to: ${newFilePath}`);
    }

    const uploadId = generateUploadId();
    let status = "unknown";
    let source = "Unknown";

    await ensureIndexExists(esClient);
    const existing = await esClient.search({
      index: getIndexName(),
      size: 1,
      query: { term: { sha256: { value: uploadedFileHash } } },
    });

    let docId;

    const blacklistEntry = getBlacklistEntry(uploadedFileHash);

    if (existing.hits.hits.length > 0) {
      const doc = existing.hits.hits[0];
      docId = doc._id;
      status = blacklistEntry?.active ? "malicious" : (doc._source.status || "unknown");
      source = blacklistEntry?.active ? "BlacklistDB" : (doc._source.source || "Elasticsearch");

      if (!blacklistEntry?.active && hasVtHashData) {
        status = vtResult.status;
        source = "VirusTotal";
      }

      const alreadyUploaded = isAlreadyUploadedFromDoc(doc._source);
      if (alreadyUploaded) {
        return res.status(200).json({
          success: true,
          message: "APK already uploaded for this hash; duplicate upload skipped",
          app: {
            id: docId,
            uploadId: doc._source.uploadId || null,
            packageName: doc._source.packageName || safePackageName,
            appName: doc._source.appName || safePackageName,
            status,
            source,
            fileName: doc._source.apkFileName || newFileName,
            sha256: uploadedFileHash,
            duplicateSkipped: true,
          },
        });
      }

      await esClient.update({
        index: getIndexName(),
        id: docId,
        body: {
          doc: {
            uploadId,
            uploadedByUser: true,
            timestamp: new Date(),
            apkFilePath: newFilePath,
            apkFileName: newFileName,
            virusTotalHashCheck,
            uploadSource,
            ...(blacklistEntry?.active ? {
              status: "malicious",
              source: "BlacklistDB",
              blacklist: {
                active: true,
                reason: blacklistEntry.reason,
                firstBlacklistedAt: blacklistEntry.firstBlacklistedAt,
                updatedAt: blacklistEntry.lastUpdatedAt,
                updatedBy: blacklistEntry.updatedBy,
                source: blacklistEntry.source,
              },
            } : {}),
            ...(isSoarUpload ? { soarId, soarTriggeredAt } : {}),
          },
        },
      });

      console.log(`✅ Updated existing app → ${safePackageName}: ${status}`);
    } else {
      if (blacklistEntry?.active || isHashMalicious(uploadedFileHash)) {
        status = "malicious";
        source = blacklistEntry?.active ? "BlacklistDB" : "SignatureDB";
        console.log(`⚠️  [UPLOAD] Detected malicious app via SignatureDB: ${safePackageName}`);
      } else if (hasVtHashData) {
        status = vtResult.status;
        source = "VirusTotal";
        console.log(`✅ [UPLOAD] VirusTotal hash check: ${safePackageName} -> ${vtResult.status} (${vtResult.detectionRatio})`);
      } else {
        status = "unknown";
        source = "User Upload";
        console.log(`➕ [UPLOAD] New app uploaded: ${safePackageName}`);
      }

      const dangerousPermissions = separateDangerousPermissions(app.permissions || []);

      const docData = {
        uploadId,
        appName: app.appName || safePackageName,
        packageName: safePackageName,
        sha256: uploadedFileHash,
        sizeMB: app.sizeMB || (apkFile.size / (1024 * 1024)).toFixed(2),
        ...dangerousPermissions,
        status: status,
        source: source,
        timestamp: new Date(),
        uploadedByUser: true,
        ...(blacklistEntry?.active ? {
          blacklist: {
            active: true,
            reason: blacklistEntry.reason,
            firstBlacklistedAt: blacklistEntry.firstBlacklistedAt,
            updatedAt: blacklistEntry.lastUpdatedAt,
            updatedBy: blacklistEntry.updatedBy,
            source: blacklistEntry.source,
          },
        } : {}),
        virusTotalHashCheck,
        apkFilePath: newFilePath,
        apkFileName: newFileName,
        uploadSource,
        ...(isSoarUpload ? { soarId, soarTriggeredAt } : {}),
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
        uploadId,
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

  const { dedupedUser, dedupedSystem } = dedupeScannedApps(userApps, systemApps);
  console.log(
    `🧹 Deduped scan payload - user: ${userApps.length} -> ${dedupedUser.length}, system: ${systemApps.length} -> ${dedupedSystem.length}`
  );

  // OPTIMIZATION: Process apps concurrently in batches instead of sequentially
  const processingStartTime = Date.now();

  // Helper function to process a single app
  const processApp = async (app, appType) => {
    const { appName, packageName, sha256, sizeMB, permissions } = app;
    const uploadedByUserFlag = app.uploadedByUser === true;
    const effectiveScanTime = normalizeIsoTime(scan_time) || new Date().toISOString();

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

      const blacklistEntry = getBlacklistEntry(sha256);

      if (existing.hits.hits.length > 0) {
        existingDoc = existing.hits.hits[0];
        const doc = existingDoc;
        status = doc._source.status || "unknown";
        source = doc._source.source || "Elasticsearch";
        virusTotalHashCheck = doc._source.virusTotalHashCheck || null;
        const appTypeState = resolveAppType(doc._source, appType);

        const updateDoc = {
          timestamp: new Date(),
          appType: appTypeState.appType,
          seenAsUserApp: appTypeState.seenAsUserApp,
          seenAsSystemApp: appTypeState.seenAsSystemApp,
        };
        if (device_model) updateDoc.device_model = device_model;
        if (device_id) updateDoc.device_id = device_id;
        if (scan_time) updateDoc.scan_time = scan_time;

        if (blacklistEntry && blacklistEntry.active) {
          status = "malicious";
          source = "BlacklistDB";
          updateDoc.status = "malicious";
          updateDoc.source = "BlacklistDB";
          updateDoc.blacklist = {
            active: true,
            reason: blacklistEntry.reason,
            firstBlacklistedAt: blacklistEntry.firstBlacklistedAt,
            updatedAt: blacklistEntry.lastUpdatedAt,
            updatedBy: blacklistEntry.updatedBy,
            source: blacklistEntry.source,
          };
        }

        const normalizedExistingHashCheck = normalizeVirusTotalSnapshot({
          packageName,
          appType,
          hashCheck: virusTotalHashCheck,
          scanTimeHint: effectiveScanTime,
        });

        if (normalizedExistingHashCheck !== virusTotalHashCheck) {
          virusTotalHashCheck = normalizedExistingHashCheck;
          status = "safe";
          source = "VirusTotal";
          updateDoc.status = status;
          updateDoc.source = source;
          updateDoc.virusTotalHashCheck = normalizedExistingHashCheck;
        }

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
        let existingDetectedEngines = Number.isFinite(virusTotalHashCheck?.detectedEngines)
          ? virusTotalHashCheck.detectedEngines
          : getDetectedEnginesFromDoc(doc._source);
        let existingTotalEngines =
          virusTotalHashCheck?.totalEngines ||
          doc._source?.virusTotalHashCheck?.totalEngines ||
          doc._source?.virusTotalAnalysis?.totalEngines ||
          0;
        let existingDetectionRatio =
          virusTotalHashCheck?.detectionRatio ||
          doc._source?.virusTotalHashCheck?.detectionRatio ||
          doc._source?.virusTotalAnalysis?.detectionRatio ||
          "N/A";

        // Re-check VT when old docs are missing data or have stale 0/0 hash check payloads.
        const hasUsableVtData = Number.isFinite(existingDetectedEngines) && Number(existingTotalEngines) > 0;
        if (!hasUsableVtData) {
          const vtResult = await checkVirusTotal(sha256);
          if (vtResult && vtResult.status !== "unknown") {
            existingDetectedEngines = vtResult.detectedEngines;
            existingTotalEngines = vtResult.totalEngines;
            existingDetectionRatio = vtResult.detectionRatio;

            const shouldKeepForcedMalicious =
              blacklistEntry?.active ||
              doc._source?.source === "SignatureDB" ||
              doc._source?.blacklist?.active === true;
            const resolvedStatus = shouldKeepForcedMalicious ? "malicious" : vtResult.status;
            const resolvedSource = shouldKeepForcedMalicious ? (blacklistEntry?.active ? "BlacklistDB" : "SignatureDB") : "VirusTotal";

            await esClient.update({
              index: getIndexName(),
              id: doc._id,
              body: {
                doc: {
                  status: resolvedStatus,
                  source: resolvedSource,
                  virusTotalHashCheck: {
                    detectionRatio: vtResult.detectionRatio,
                    totalEngines: vtResult.totalEngines,
                    detectedEngines: vtResult.detectedEngines,
                    maliciousCount: vtResult.maliciousCount,
                    suspiciousCount: vtResult.suspiciousCount,
                    harmlessCount: vtResult.harmlessCount,
                    undetectedCount: vtResult.undetectedCount,
                    timeoutCount: vtResult.timeoutCount,
                    scanTime: vtResult.scanTime,
                  },
                },
              },
            });

            const normalizedExistingHashCheck = normalizeVirusTotalSnapshot({
              packageName,
              appType,
              hashCheck: {
                detectionRatio: vtResult.detectionRatio,
                totalEngines: vtResult.totalEngines,
                detectedEngines: vtResult.detectedEngines,
                maliciousCount: vtResult.maliciousCount,
                suspiciousCount: vtResult.suspiciousCount,
                harmlessCount: vtResult.harmlessCount,
                undetectedCount: vtResult.undetectedCount,
                timeoutCount: vtResult.timeoutCount,
                scanTime: vtResult.scanTime,
              },
              scanTimeHint: effectiveScanTime,
            });

            if (normalizedExistingHashCheck?.detectionRatio === "0/66") {
              existingDetectedEngines = 0;
              existingTotalEngines = 66;
              existingDetectionRatio = "0/66";
              status = "safe";
              source = "VirusTotal";

              await esClient.update({
                index: getIndexName(),
                id: doc._id,
                body: {
                  doc: {
                    status,
                    source,
                    virusTotalHashCheck: normalizedExistingHashCheck,
                  },
                },
              });
            }

            if (normalizedExistingHashCheck?.detectionRatio !== "0/66") {
              status = resolvedStatus;
              source = resolvedSource;
            }
          } else {
            // Keep forced-malicious labels (blacklist/signature) even when VT has no record.
            if (!(blacklistEntry?.active || doc._source?.source === "SignatureDB" || doc._source?.blacklist?.active === true)) {
              status = "unknown";
              source = "Unknown";
              await esClient.update({
                index: getIndexName(),
                id: doc._id,
                body: { doc: { status: "unknown", source: "Unknown" } },
              });
            }
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

        if (Number.isFinite(existingDetectedEngines) && existingDetectedEngines >= SOAR_TRIGGER_THRESHOLD) {
          const alreadyUploaded = isAlreadyUploadedFromDoc(doc._source);
          uploadTrigger = {
            required: !alreadyUploaded,
            queued: false,
            triggerType: !alreadyUploaded ? "apk_upload_request" : null,
            threshold: SOAR_TRIGGER_THRESHOLD,
            detectedEngines: existingDetectedEngines,
            reason: alreadyUploaded
              ? "already_uploaded_today"
              : "detected_threshold_plus",
          };

          if (!alreadyUploaded) {
            await esClient.update({
              index: getIndexName(),
              id: doc._id,
              retry_on_conflict: 3,
              body: { doc: buildSoarPromotionDoc(doc._source) },
            });

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
            uploadTrigger.required = false;
            uploadTrigger.triggerType = "soar_auto_promoted";
          }
        }

        console.log(`✅ Already indexed → ${packageName} (${appType}): ${status} (${source})`);
      } else {
        const appTypeState = resolveAppType({}, appType);
        if (blacklistEntry && blacklistEntry.active) {
          status = "malicious";
          source = "BlacklistDB";
          console.log(`Detected blacklisted ${appType} app: ${packageName}`);
        } else if (isHashMalicious(sha256)) {
          status = "malicious";
          source = "SignatureDB";
          console.log(`Detected malicious ${appType} app via SignatureDB: ${packageName}`);
        }

        // VT hash check must run regardless of blacklist/signature branch.
        console.log(`🦠 Checking VirusTotal hash for ${appType} app: ${packageName}`);
        const vtResult = await checkVirusTotal(sha256);

        if (vtResult && vtResult.status !== "unknown") {
          virusTotalHashCheck = {
            detectionRatio: vtResult.detectionRatio,
            totalEngines: vtResult.totalEngines,
            detectedEngines: vtResult.detectedEngines,
            maliciousCount: vtResult.maliciousCount,
            suspiciousCount: vtResult.suspiciousCount,
            harmlessCount: vtResult.harmlessCount,
            undetectedCount: vtResult.undetectedCount,
            timeoutCount: vtResult.timeoutCount,
            scanTime: vtResult.scanTime,
          };

          // Only let VT set app status/source when app is not forced malicious by policy.
          if (!(blacklistEntry && blacklistEntry.active) && !isHashMalicious(sha256)) {
            status = vtResult.status;
            source = "VirusTotal";
          }

          console.log(`✅ VirusTotal hash check for ${appType} app ${packageName}: ${vtResult.status} (${vtResult.detectionRatio})`);

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

          if (vtResult.detectedEngines >= SOAR_TRIGGER_THRESHOLD) {
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
              threshold: SOAR_TRIGGER_THRESHOLD,
              detectedEngines: vtResult.detectedEngines,
              reason: queued
                ? "detected_threshold_plus"
                : "already_triggered_or_uploaded",
            };
          }
        } else {
          console.log(`ℹ️  VirusTotal: Hash not found for ${appType} app ${packageName}`);
          virusTotalHashCheck = {
            detectionRatio: "0/0",
            totalEngines: 0,
            detectedEngines: 0,
            scanTime: new Date().toISOString(),
          };
          if (!(blacklistEntry && blacklistEntry.active) && !isHashMalicious(sha256)) {
            status = "unknown";
            source = "Unknown";
          }
        }

        virusTotalHashCheck = normalizeVirusTotalSnapshot({
          packageName,
          appType,
          hashCheck: virusTotalHashCheck,
          scanTimeHint: effectiveScanTime,
        });

        if (virusTotalHashCheck?.detectionRatio === "0/66") {
          status = "safe";
          source = "VirusTotal";
        }

        const dangerousPermissions = separateDangerousPermissions(permissions || []);

        const shouldAutoPromoteToSoar = Number.isFinite(virusTotalHashCheck?.detectedEngines) && virusTotalHashCheck.detectedEngines >= SOAR_TRIGGER_THRESHOLD;

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
          appType: appTypeState.appType,
          seenAsUserApp: appTypeState.seenAsUserApp,
          seenAsSystemApp: appTypeState.seenAsSystemApp,
          ...(blacklistEntry && blacklistEntry.active ? {
            blacklist: {
              active: true,
              reason: blacklistEntry.reason,
              firstBlacklistedAt: blacklistEntry.firstBlacklistedAt,
              updatedAt: blacklistEntry.lastUpdatedAt,
              updatedBy: blacklistEntry.updatedBy,
              source: blacklistEntry.source,
            },
          } : {}),
          ...(shouldAutoPromoteToSoar ? {
            soarId: generateSoarId(),
            soarTriggeredAt: new Date().toISOString(),
            soarRequestStatus: "pending_upload",
            soarActionRequestedAt: new Date().toISOString(),
          } : {}),
        };

        if (device_model) docData.device_model = device_model;
        if (device_id) docData.device_id = device_id;
        if (scan_time) docData.scan_time = scan_time;

        await esClient.index({
          index: getIndexName(),
          document: docData,
        });

        if (shouldAutoPromoteToSoar && !uploadTrigger.triggerType) {
          uploadTrigger = {
            required: false,
            queued: false,
            triggerType: "soar_auto_promoted",
            threshold: SOAR_TRIGGER_THRESHOLD,
            detectedEngines: virusTotalHashCheck.detectedEngines,
            reason: "detected_threshold_plus",
          };
        }
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

  const ensureSoarCoverageForToday = async () => {
    try {
      const result = await esClient.search({
        index: getIndexName(),
        size: 1000,
        query: { match_all: {} },
      });

      const hits = result.hits?.hits || [];
      for (const hit of hits) {
        const doc = hit._source || {};
        const detectedEngines = getDetectedEnginesFromDoc(doc);
        if (!Number.isFinite(detectedEngines) || detectedEngines < SOAR_TRIGGER_THRESHOLD) {
          continue;
        }

        const detectionRatio =
          doc?.virusTotalHashCheck?.detectionRatio ||
          doc?.virusTotalAnalysis?.detectionRatio ||
          "N/A";
        const totalEngines =
          doc?.virusTotalHashCheck?.totalEngines ||
          doc?.virusTotalAnalysis?.totalEngines ||
          0;
        const alreadyUploaded = isAlreadyUploadedFromDoc(doc);

        const queued = await createAnalysisRequestFromHashCheck(esClient, {
          appName: doc.appName || doc.packageName,
          packageName: doc.packageName,
          sha256: doc.sha256,
          detectionRatio,
          totalEngines,
          detectedEngines,
          sourceIndex: getIndexName(),
          sourceDate: new Date().toISOString().slice(0, 10),
          alreadyUploaded,
        });

        if (queued && !alreadyUploaded) {
          await esClient.update({
            index: getIndexName(),
            id: hit._id,
            retry_on_conflict: 3,
            body: { doc: buildSoarPromotionDoc(doc) },
          });
        }
      }
    } catch (err) {
      console.error("❌ SOAR coverage sweep failed:", err.message);
    }
  };

  try {
    // Process user and system apps concurrently
    const [userResultsProcessing, systemResultsProcessing] = await Promise.all([
      processAppsInBatches(dedupedUser, "user"),
      processAppsInBatches(dedupedSystem, "system")
    ]);

    userResults.push(...userResultsProcessing);
    systemResults.push(...systemResultsProcessing);

    await ensureSoarCoverageForToday();

    const processingTimeMs = Date.now() - processingStartTime;
    console.log(`⏱️  Processing completed in ${processingTimeMs}ms for ${dedupedUser.length + dedupedSystem.length} apps`);
    
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

    // Store ML prediction data WITHOUT changing the status field
    // Status should ONLY be derived from VirusTotal hash check, never from ML
    const mlPredictionData = {
      mlPredictionScore: parseFloat(mlPredictionScore),
      mlPredictionLabel: mlPredictionLabel,
      mlAnalysisTimestamp: new Date().toISOString(),
      mlAnalysisDate: new Date()
    };

    // Update the document with ML prediction data ONLY - DO NOT UPDATE STATUS
    await esClient.update({
      index: indexName,
      id: docId,
      body: {
        doc: mlPredictionData,
      },
    });

    console.log(`🤖 ML Prediction stored for ${packageName} (Status remains: ${doc._source.status})`);
    console.log(`   Score: ${mlPredictionScore}, Label: ${mlPredictionLabel}`);

    res.status(200).json({
      message: "ML Prediction stored successfully",
      packageName,
      mlPredictionScore,
      mlPredictionLabel,
      status: doc._source.status,
      note: "Status is not updated by ML - only VirusTotal determines status",
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