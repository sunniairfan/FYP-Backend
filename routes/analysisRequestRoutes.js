const express = require("express");
const router = express.Router();
const {
  getRequestsIndexName,
  getHashCheckDetectedFromDoc,
  getHashCheckRatioFromDoc,
  isAlreadyUploadedFromDoc,
  hasUploadedApkForPackage,
  createAnalysisRequestFromHashCheck,
} = require("../utils/analysisRequests");

const getTodayAppsIndex = () => {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, "0");
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const year = today.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
};

const backfillHashCheckRequests = async (esClient, limit = 2000) => {
  if (!esClient) return;

  try {
    const todayAppsIndex = getTodayAppsIndex();
    console.log(`\n🔄 [BACKFILL] Starting analysis request backfill from index: ${todayAppsIndex}`);
    
    const result = await esClient.search({
      index: todayAppsIndex,
      size: limit,
      sort: [{ timestamp: { order: "desc", unmapped_type: "date" } }],
      query: {
        exists: { field: "virusTotalHashCheck" },
      },
    });

    const hits = result.hits?.hits || [];
    console.log(`📊 [BACKFILL] Found ${hits.length} apps with VT hash checks`);
    
    for (const hit of hits) {
      const doc = hit._source || {};
      const detectedEngines = getHashCheckDetectedFromDoc(doc);
      const detectionRatio = getHashCheckRatioFromDoc(doc);
      const alreadyUploaded = isAlreadyUploadedFromDoc(doc);

      await createAnalysisRequestFromHashCheck(esClient, {
        appName: doc.appName,
        packageName: doc.packageName,
        sha256: doc.sha256,
        detectionRatio,
        totalEngines: doc.virusTotalHashCheck?.totalEngines,
        detectedEngines,
        sourceIndex: todayAppsIndex,
        sourceDate: new Date().toISOString().slice(0, 10),
        alreadyUploaded,
      });
    }
  } catch (err) {
    console.error("❌ [BACKFILL] Analysis request backfill error:", err.message);
  }
};

router.get("/", async (req, res) => {
  const esClient = req.app.get("esClient");
  const limit = Math.min(parseInt(req.query.limit, 10) || 10, 50);
  const requestsIndex = getRequestsIndexName();
  const todayAppsIndex = getTodayAppsIndex();
  const todayDate = new Date().toISOString().slice(0, 10);

  try {
    console.log(`\n📡 [ANALYSIS REQUESTS API] Request received - querying index: ${requestsIndex}`);
    await backfillHashCheckRequests(esClient);

    const result = await esClient.search({
      index: requestsIndex,
      size: limit,
      sort: [{ createdAt: { order: "desc", unmapped_type: "date" } }],
      query: {
        bool: {
          filter: [
            {
              bool: {
                should: [
                  { term: { sourceIndex: todayAppsIndex } },
                  { term: { sourceDate: todayDate } },
                ],
                minimum_should_match: 1,
              },
            },
          ],
        },
      },
      track_total_hits: true,
    });

    const requests = result.hits.hits.map((hit) => ({
      id: hit._id,
      ...hit._source,
    }));

    const uploadedCache = new Map();
    const filteredRequests = [];
    for (const request of requests) {
      const key = request.packageName || request.sha256 || request.id;
      if (uploadedCache.has(key)) {
        if (uploadedCache.get(key)) {
          continue;
        }
      } else {
        const alreadyUploaded = await hasUploadedApkForPackage(
          esClient,
          todayAppsIndex,
          request.packageName
        );
        uploadedCache.set(key, alreadyUploaded);
        if (alreadyUploaded) {
          continue;
        }
      }
      if (!filteredRequests.find((item) => (item.packageName || item.sha256) === (request.packageName || request.sha256))) {
        filteredRequests.push(request);
      }
    }

    return res.json({
      success: true,
      total: filteredRequests.length,
      requests: filteredRequests,
    });
  } catch (err) {
    if (err?.meta?.statusCode === 404) {
      return res.json({ success: true, total: 0, requests: [] });
    }
    console.error("Analysis requests fetch error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to fetch analysis requests" });
  }
});

module.exports = router;
