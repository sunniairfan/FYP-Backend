const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { checkVirusTotal } = require("../utils/virusTotal");
const mobsf = require("../utils/mobsf");

const signaturePath = path.join(__dirname, "../signatureDB.json");
const knownHashes = fs.existsSync(signaturePath)
  ? JSON.parse(fs.readFileSync(signaturePath, "utf-8"))
  : [];

const uploadsDir = path.join(__dirname, "../Uploads/apks");

// Create uploads directory if it doesn't exist
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Helper function to get dynamic index name
const getIndexName = () => {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, '0');
  const month = String(today.getMonth() + 1).padStart(2, '0');
  const year = today.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
};

const isHashMalicious = (hash) => knownHashes.includes(hash);

// Calculate SHA-256 hash of a file
const calculateFileHash = (filePath) => {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
};

// Helper function to separate dangerous permissions
const separateDangerousPermissions = (permissions) => {
  const dangerousPerms = permissions.filter(perm => {
    const dangerousPermissions = [
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.ACCESS_COARSE_LOCATION',
      'android.permission.ACCESS_BACKGROUND_LOCATION',
      'android.permission.READ_CONTACTS',
      'android.permission.WRITE_CONTACTS',
      'android.permission.READ_SMS',
      'android.permission.SEND_SMS',
      'android.permission.RECEIVE_SMS',
      'android.permission.READ_PHONE_STATE',
      'android.permission.READ_PHONE_NUMBERS',
      'android.permission.CALL_PHONE',
      'android.permission.READ_CALL_LOG',
      'android.permission.WRITE_CALL_LOG',
      'android.permission.READ_EXTERNAL_STORAGE',
      'android.permission.WRITE_EXTERNAL_STORAGE',
      'android.permission.READ_MEDIA_IMAGES',
      'android.permission.READ_MEDIA_VIDEO',
      'android.permission.READ_MEDIA_AUDIO',
      'android.permission.MANAGE_EXTERNAL_STORAGE',
      'android.permission.GET_ACCOUNTS',
      'android.permission.READ_CALENDAR',
      'android.permission.WRITE_CALENDAR'
    ];
    return dangerousPermissions.includes(perm);
  });

  const result = {};
  dangerousPerms.forEach((perm, index) => {
    result[`dangerousPermission${index + 1}`] = perm;
  });
  
  return result;
};

// Helper function to ensure index exists
const ensureIndexExists = async (esClient) => {
  const indexName = getIndexName();
  try {
    const existsResp = await esClient.indices.exists({ index: indexName });
    const exists = existsResp.body === true || existsResp === true;
    
    if (!exists) {
      await esClient.indices.create({
        index: indexName,
        mappings: {
          properties: {
            appName: { type: 'text' },
            packageName: { type: 'keyword' },
            sha256: { type: 'keyword' },
            sizeMB: { type: 'float' },
            status: { type: 'keyword' },
            timestamp: { type: 'date' },
            uploadedByUser: { type: 'boolean' },
            dangerousPermission1: { type: 'keyword' },
            dangerousPermission2: { type: 'keyword' },
            dangerousPermission3: { type: 'keyword' },
            dangerousPermission4: { type: 'keyword' },
            dangerousPermission5: { type: 'keyword' },
            dangerousPermission6: { type: 'keyword' },
            dangerousPermission7: { type: 'keyword' },
            dangerousPermission8: { type: 'keyword' },
            dangerousPermission9: { type: 'keyword' },
            dangerousPermission10: { type: 'keyword' },
            dangerousPermission11: { type: 'keyword' },
            dangerousPermission12: { type: 'keyword' },
            source: { type: 'keyword' },
            scanTime: { type: 'date' },
            detectionRatio: { type: 'keyword' },
            totalEngines: { type: 'integer' },
            detectedEngines: { type: 'integer' },
            apkFilePath: { type: 'keyword' },
            apkFileName: { type: 'keyword' },
            uploadSource: { type: 'keyword' }
          }
        }
      });
      console.log(`✅ Created index: ${indexName}`);
    }
  } catch (err) {
    console.error('❌ Failed to ensure index exists:', err.message);
  }
};

// Helper function to analyze app with MobSF
async function analyzeApp(sha256, esClient) {
  await ensureIndexExists(esClient);
  const searchRes = await esClient.search({
    index: getIndexName(),
    size: 1,
    query: { term: { sha256: { value: sha256 } } },
  });

  if (searchRes.hits.hits.length === 0) {
    throw new Error("App not found");
  }

  const docId = searchRes.hits.hits[0]._id;
  const appData = searchRes.hits.hits[0]._source;
  const filePath = appData.apkFilePath;

  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error("APK file not found");
  }

  const uploadRes = await mobsf.uploadToMobSF(filePath);
  const md5Hash = uploadRes.hash;

  await mobsf.scanWithMobSF(md5Hash);
  const report = await mobsf.getJsonReport(md5Hash);

  const dangerousPermissions = Object.entries(report.permissions || {})
    .filter(([_, perm]) => perm.status === 'dangerous')
    .map(([perm]) => perm);

  const highRiskFindings = Object.entries(report.code_analysis || {})
    .filter(([_, finding]) => finding.metadata.severity === 'high')
    .length;

  const malwareProbability = report.virus_total 
    ? `${report.virus_total.malicious}/${report.virus_total.total}`
    : 'unknown';

  const mobsfAnalysis = {
    security_score: report.security_score || 0,
    dangerous_permissions: dangerousPermissions,
    high_risk_findings: highRiskFindings,
    malware_probability: malwareProbability
  };

  let status = 'unknown';
  if (report.security_score >= 70) status = 'safe';
  else if (report.security_score < 40) status = 'malicious';
  else status = 'suspicious';

  await esClient.update({
    index: getIndexName(),
    id: docId,
    body: {
      doc: {
        mobsfAnalysis,
        lastMobsfAnalysis: new Date().toISOString(),
        mobsfHash: md5Hash,
        status
      },
    },
  });

  return { success: true, analysis: mobsfAnalysis, app: appData };
}

// APK Upload Controller
const uploadApp = async (req, res) => {
  console.log(">>> Received APK upload request:", new Date().toISOString());
  console.log("Request headers:", req.headers);
  console.log("Request body metadata:", req.body.metadata);
  console.log("Uploaded file:", req.file);
  
  try {
    // Check if file was uploaded
    if (!req.file) {
      console.error("No APK file uploaded");
      return res.status(400).json({ error: "No APK file uploaded" });
    }

    // Parse metadata from form data
    const metadata = JSON.parse(req.body.metadata || '{}');
    const apps = metadata.apps || [];
    
    if (apps.length === 0) {
      console.error("No app metadata provided");
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "No app metadata provided" });
    }

    const app = apps[0]; // Get first app from metadata
    const esClient = req.app.get("esClient");

    // Verify file integrity by calculating hash
    const uploadedFileHash = await calculateFileHash(req.file.path);
    const expectedHash = app.sha256;

    if (uploadedFileHash.toLowerCase() !== expectedHash.toLowerCase()) {
      console.error("File integrity check failed", {
        expected: expectedHash,
        actual: uploadedFileHash
      });
      fs.unlinkSync(req.file.path);
      return res.status(400).json({
        error: "File integrity check failed",
        expected: expectedHash,
        actual: uploadedFileHash
      });
    }

    // Rename file to include package name for better organization
    const newFileName = `${app.packageName}_${Date.now()}.apk`;
    const newFilePath = path.join(uploadsDir, newFileName);
    fs.renameSync(req.file.path, newFilePath);
    console.log(`Renamed file to: ${newFilePath}`);

    let status = "unknown";
    let source = "Unknown";
    let scanTime = null;
    let detectionRatio = null;
    let totalEngines = null;
    let detectedEngines = null;

    // Check if app already exists in Elasticsearch
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
            uploadSource: "android_app"
          }
        },
      });

      console.log(`✅ Updated existing app → ${app.packageName}: ${status}`);
    } else {
      if (isHashMalicious(uploadedFileHash)) {
        status = "malicious";
        source = "SignatureDB";
        console.log(`Detected malicious app via SignatureDB: ${app.packageName}`);
      } else {
        console.log(`Checking VirusTotal for ${app.packageName}`);
        const vtResult = await checkVirusTotal(uploadedFileHash);
        
        // Extract VirusTotal scan information
        if (vtResult && typeof vtResult === 'object') {
          status = vtResult.status || "unknown";
          scanTime = vtResult.scanTime || new Date().toISOString();
          detectionRatio = vtResult.detectionRatio || "0/0";
          totalEngines = vtResult.totalEngines || 0;
          detectedEngines = vtResult.detectedEngines || 0;
        } else {
          status = vtResult || "unknown";
        }
        
        source = "VirusTotal";
        console.log(`VirusTotal result for ${app.packageName}: ${status}`);
      }

      // Separate dangerous permissions
      const dangerousPermissions = separateDangerousPermissions(app.permissions || []);

      const docData = {
        appName: app.appName,
        packageName: app.packageName,
        sha256: uploadedFileHash,
        sizeMB: app.sizeMB,
        ...dangerousPermissions, // Spread dangerous permissions as separate fields
        status: status,
        source: source,
        timestamp: new Date(),
        uploadedByUser: true,
        apkFilePath: newFilePath,
        apkFileName: newFileName,
        uploadSource: "android_app"
      };

      // Add VirusTotal scan info if available
      if (scanTime) docData.scanTime = scanTime;
      if (detectionRatio) docData.detectionRatio = detectionRatio;
      if (totalEngines) docData.totalEngines = totalEngines;
      if (detectedEngines !== null) docData.detectedEngines = detectedEngines;

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
        await analyzeApp(uploadedFileHash, esClient);
        console.log(`Background MobSF analysis completed for ${app.packageName} (${uploadedFileHash})`);
      } catch (error) {
        console.error(`Background MobSF analysis failed for ${app.packageName}:`, error);
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
        sha256: uploadedFileHash
      }
    });

  } catch (err) {
    console.error("❌ Error processing APK upload:", err.message, err.stack);
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
      console.log(`Cleaned up failed APK file: ${req.file.path}`);
    }
    res.status(500).json({
      error: "Failed to process APK upload",
      details: err.message
    });
  }
};

// Original scan endpoint (for backward compatibility)
const receiveAppData = async (req, res) => {
  console.log(">>> Received scan request:", new Date().toISOString());
  console.log("Request body:", req.body);

  const apps = req.body.apps;
  const esClient = req.app.get("esClient");

  if (!apps || !Array.isArray(apps)) {
    console.error("Invalid or missing apps array");
    return res.status(400).json({ error: "Invalid or missing apps array" });
  }

  const results = [];

  for (const app of apps) {
    const { appName, packageName, sha256, sizeMB, permissions } = app;
    const uploadedByUserFlag = app.uploadedByUser === true;

    if (!packageName || !sha256) {
      console.error(`Missing packageName or sha256 for app: ${packageName || "unknown"}`);
      results.push({ packageName: packageName || "unknown", status: "error", error: "Missing packageName or sha256" });
      continue;
    }

    let status = "unknown";
    let source = "Unknown";
    let scanTime = null;
    let detectionRatio = null;
    let totalEngines = null;
    let detectedEngines = null;

    try {
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

        await esClient.update({
          index: getIndexName(),
          id: doc._id,
          body: { doc: { timestamp: new Date() } },
        });

        if (uploadedByUserFlag && !doc._source.uploadedByUser) {
          await esClient.update({
            index: getIndexName(),
            id: doc._id,
            body: { doc: { uploadedByUser: true } },
          });
        }

        console.log(`✅ Already indexed → ${packageName}: ${status} (${source})`);
      } else {
        if (isHashMalicious(sha256)) {
          status = "malicious";
          source = "SignatureDB";
          console.log(`Detected malicious app via SignatureDB: ${packageName}`);
        } else {
          console.log(`Checking VirusTotal for ${packageName}`);
          const vtResult = await checkVirusTotal(sha256);
          
          // Extract VirusTotal scan information
          if (vtResult && typeof vtResult === 'object') {
            status = vtResult.status || "unknown";
            scanTime = vtResult.scanTime || new Date().toISOString();
            detectionRatio = vtResult.detectionRatio || "0/0";
            totalEngines = vtResult.totalEngines || 0;
            detectedEngines = vtResult.detectedEngines || 0;
          } else {
            status = vtResult || "unknown";
          }
          
          source = "VirusTotal";
          console.log(`VirusTotal result for ${packageName}: ${status}`);
        }

        // Separate dangerous permissions
        const dangerousPermissions = separateDangerousPermissions(permissions || []);

        const docData = {
          appName,
          packageName,
          sha256,
          sizeMB,
          ...dangerousPermissions, // Spread dangerous permissions as separate fields
          status,
          source,
          timestamp: new Date(),
          uploadedByUser: uploadedByUserFlag,
        };

        // Add VirusTotal scan info if available
        if (scanTime) docData.scanTime = scanTime;
        if (detectionRatio) docData.detectionRatio = detectionRatio;
        if (totalEngines) docData.totalEngines = totalEngines;
        if (detectedEngines !== null) docData.detectedEngines = detectedEngines;

        await esClient.index({
          index: getIndexName(),
          document: docData,
        });
        console.log(`📤 Indexed (Scan) → ${packageName} (${status})`);
      }

      results.push({ packageName, status, source });
    } catch (err) {
      console.error(`❌ Error processing ${packageName}:`, err.message);
      results.push({ packageName, status: "error", error: err.message });
    }
  }

  console.log("Scan results:", results);
  res.status(200).json({ message: "Scan complete", results });
};

// Get app details by ID or SHA256
const getAppDetails = async (req, res) => {
  const { identifier } = req.params;
  const esClient = req.app.get("esClient");

  try {
    await ensureIndexExists(esClient);
    let searchQuery;
    
    if (/^[a-fA-F0-9]{64}$/.test(identifier)) {
      searchQuery = { term: { sha256: { value: identifier } } };
    } else {
      const result = await esClient.get({
        index: getIndexName(),
        id: identifier
      });
      return res.status(200).json({
        app: {
          id: result._id,
          ...result._source
        }
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
        ...doc._source
      }
    });

  } catch (err) {
    console.error("Error fetching app details:", err.message);
    res.status(500).json({ error: "Failed to fetch app details" });
  }
};

// Download APK file
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

// Delete app and its APK file
const deleteApp = async (req, res) => {
  const { sha256 } = req.params;
  const esClient = req.app.get("esClient");

  try {
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

    // Delete MobSF scan if it exists
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
      id: doc._id
    });

    console.log(`🗑️ Deleted app from database: ${appData.packageName}`);

    res.status(200).json({
      message: "App and APK file deleted successfully",
      packageName: appData.packageName
    });

  } catch (err) {
    console.error("Error deleting app:", err.message);
    res.status(500).json({ error: "Failed to delete app" });
  }
};

module.exports = {
  receiveAppData,
  uploadApp,
  getAppDetails,
  downloadApp,
  deleteApp
};