const fs = require("fs");
const path = require("path");
const { checkVirusTotal } = require("../utils/virusTotal");

const signaturePath = path.join(__dirname, "../signatureDB.json");
const knownHashes = fs.existsSync(signaturePath)
  ? JSON.parse(fs.readFileSync(signaturePath, "utf-8"))
  : [];

const isHashMalicious = (hash) => knownHashes.includes(hash);

const receiveAppData = async (req, res) => {
  console.log(">>> Received scan request:", new Date().toISOString());
  console.log("Request body:", req.body);

  const apps = req.body.apps;
  const esClient = req.app.get("esClient");

  if (!apps || !Array.isArray(apps)) {
    return res.status(400).json({ error: "Invalid or missing apps array" });
  }

  const results = [];

  for (const app of apps) {
    const { appName, packageName, sha256, sizeMB, permissions } = app;
    // Support optional uploadedByUser flag from the frontend
    const uploadedByUserFlag = app.uploadedByUser === true;

    if (!packageName || !sha256) continue;

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

        // Update timestamp
        await esClient.update({
          index: "apps",
          id: doc._id,
          body: { doc: { timestamp: new Date() } },
        });

        // If this upload is by user and doc wasn't flagged yet, mark it
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
        } else {
          const vtResult = await checkVirusTotal(sha256);
          status = vtResult;
          source = "VirusTotal";
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

  res.status(200).json({ message: "Scan complete", results });
};

module.exports = { receiveAppData };