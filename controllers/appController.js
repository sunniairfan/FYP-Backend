const fs = require("fs");
const path = require("path");
const { checkVirusTotal } = require("../utils/virusTotal");

const signaturePath = path.join(__dirname, "../signatureDB.json");
const knownHashes = fs.existsSync(signaturePath)
  ? JSON.parse(fs.readFileSync(signaturePath, "utf-8"))
  : [];

const isHashMalicious = (hash) => knownHashes.includes(hash);

const receiveAppData = async (req, res) => {
  const apps = req.body.apps;
  const esClient = req.app.get("esClient");

  if (!apps || !Array.isArray(apps)) {
    return res.status(400).json({ error: "Invalid or missing apps array" });
  }

  try {
    const results = [];

    for (const app of apps) {
      const { appName, packageName, sha256, sizeMB, permissions } = app;
      if (!packageName || !sha256) continue;

      let status = "unknown";
      let source = "Unknown";

      const existing = await esClient.search({
        index: "apps",
        query: { match: { sha256 } },
        size: 1,
      });

      if (existing.hits.hits.length > 0) {
        const doc = existing.hits.hits[0]._source;
        status = doc.status || "unknown";
        source = doc.source || "Unknown";
        console.log(`📦 Found in Elasticsearch → ${packageName}: ${status}`);
      } else {
        if (isHashMalicious(sha256)) {
          status = "malicious";
          source = "SignatureDB";
          console.log(`☠️ Found in SignatureDB → ${packageName}`);
        } else {
          const vtResult = await checkVirusTotal(sha256);
          if (vtResult === "malicious") {
            status = "malicious";
            source = "VirusTotal";
          } else {
            status = vtResult;
            source = "VirusTotal";
          }
          console.log(`🧪 VirusTotal → ${packageName}: ${status}`);
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
          },
        });
      }

      results.push({ packageName, status, source });
    }

    res.status(200).json({ message: "Apps uploaded", results });
  } catch (error) {
    console.error("❌ Upload error:", error.message);
    res.status(500).json({ error: "Upload failed" });
  }
};

module.exports = { receiveAppData };
