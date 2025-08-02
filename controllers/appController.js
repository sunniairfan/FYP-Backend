const fs = require("fs");
const path = require("path");
const { checkVirusTotal } = require("../utils/virusTotal");
const { checkAbuseCH } = require("../utils/abusech");

const signaturePath = path.join(__dirname, "../signatureDB.json");
const knownHashes = fs.existsSync(signaturePath)
  ? JSON.parse(fs.readFileSync(signaturePath, "utf-8"))
  : [];

// Step 1: Check Local Signature DB
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

      // Check if app already in Elasticsearch
      const existing = await esClient.search({
        index: "apps",
        query: {
          match: { sha256 }
        },
        size: 1
      });

      if (existing.hits.hits.length > 0) {
        const doc = existing.hits.hits[0]._source;
        status = doc.status || "unknown";
        source = doc.source || "Unknown";
        console.log(`📦 Found in Elasticsearch → ${packageName}: ${status}`);
      } else {
        // Step 2: Check local signature DB
        if (isHashMalicious(sha256)) {
          status = "malicious";
          source = "SignatureDB";
          console.log(`☠️ Found in SignatureDB → ${packageName}`);
        } else {
          // Step 3: Check VirusTotal
          const vtResult = await checkVirusTotal(sha256);
          if (vtResult === "malicious") {
            status = "malicious";
            source = "VirusTotal";
            console.log(`🧪 VirusTotal → ${packageName}: malicious`);
          } else {
            status = vtResult; // safe or unknown
            source = "VirusTotal";
            console.log(`🧪 VirusTotal → ${packageName}: ${status}`);
          }

          // Step 4: Check Abuse.ch only if safe/unknown
          if (status === "safe" || status === "unknown") {
            const abuseStatus = await checkAbuseCH(sha256);
            if (abuseStatus === "malicious") {
              status = "malicious";
              source = "Abuse.ch";
              console.log(`☠️ Abuse.ch detected malicious → ${packageName}`);
            } else {
              console.log(`✔️ Abuse.ch → ${packageName}: ${abuseStatus}`);
            }
          }
        }

        // Step 5: Save to Elasticsearch
        const doc = {
          appName,
          packageName,
          sha256,
          sizeMB,
          permissions,
          status,
          source,
          timestamp: new Date(),
        };

        await esClient.index({
          index: "apps",
          document: doc
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
