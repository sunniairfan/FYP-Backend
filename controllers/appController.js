const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { checkVirusTotal } = require("../utils/virusTotal");

const signaturePath = path.join(__dirname, "../signatureDB.json");
const knownHashes = fs.existsSync(signaturePath)
  ? JSON.parse(fs.readFileSync(signaturePath, "utf-8"))
  : [];

const uploadsDir = path.join(__dirname, "../uploads/apks");

// Create uploads directory if it doesn't exist
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

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

    // Check if app already exists in Elasticsearch
    const existing = await esClient.search({
      index: "apps",
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
        index: "apps",
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
        status = vtResult;
        source = "VirusTotal";
        console.log(`VirusTotal result for ${app.packageName}: ${status}`);
      }

      const indexResponse = await esClient.index({
        index: "apps",
        document: {
          appName: app.appName,
          packageName: app.packageName,
          sha256: uploadedFileHash,
          sizeMB: app.sizeMB,
          permissions: app.permissions || [],
          status: status,
          source: source,
          timestamp: new Date(),
          uploadedByUser: true,
          apkFilePath: newFilePath,
          apkFileName: newFileName,
          uploadSource: "android_app"
        },
      });

      docId = indexResponse._id;
      console.log(`📤 Indexed new app → ${app.packageName} (${status})`);
    }

    res.status(200).json({
      message: "APK uploaded and analyzed successfully",
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

    try {
      const existing = await esClient.search({
        index: "apps",
        size: 1,
        query: { term: { sha256: { value: sha256 } } },
      });

      if (existing.hits.hits.length > 0) {
        const doc = existing.hits.hits[0];
        status = doc._source.status || "unknown";
        source = doc._source.source || "Elasticsearch";

        await esClient.update({
          index: "apps",
          id: doc._id,
          body: { doc: { timestamp: new Date() } },
        });

        if (uploadedByUserFlag && !doc._source.uploadedByUser) {
          await esClient.update({
            index: "apps",
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
          status = vtResult;
          source = "VirusTotal";
          console.log(`VirusTotal result for ${packageName}: ${status}`);
        }

        await esClient.index({
          index: "apps",
          document: {
            appName,
            packageName,
            sha256,
            sizeMB,
            permissions,
            status,
            source,
            timestamp: new Date(),
            uploadedByUser: uploadedByUserFlag,
          },
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
    let searchQuery;
    
    if (/^[a-fA-F0-9]{64}$/.test(identifier)) {
      searchQuery = { term: { sha256: { value: identifier } } };
    } else {
      const result = await esClient.get({
        index: "apps",
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
      index: "apps",
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
    const searchRes = await esClient.search({
      index: "apps",
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      console.error(`App not found for SHA256: ${sha256}`);
      return res.status(404).json({ error: "App not found" });
    }

    const doc = searchRes.hits.hits[0];
    const appData = doc._source;

    if (appData.apkFilePath && fs.existsSync(appData.apkFilePath)) {
      fs.unlinkSync(appData.apkFilePath);
      console.log(`🗑️ Deleted APK file: ${appData.apkFileName}`);
    }

    await esClient.delete({
      index: "apps",
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