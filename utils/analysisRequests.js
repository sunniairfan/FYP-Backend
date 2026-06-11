const fs = require("fs");

const getRequestsIndexName = () => {
  const today = new Date();
  const year = today.getFullYear();
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const day = String(today.getDate()).padStart(2, "0");
  return `analysis_requests_${year}-${month}-${day}`;
};

const getTodayAppsIndexName = () => {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, "0");
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const year = today.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
};

const REQUESTS_INDEX_PATTERN = "analysis_requests_*";
const SOAR_TRIGGER_THRESHOLD = 30;

const parseDetectionRatioNumerator = (ratio) => {
  if (!ratio || typeof ratio !== "string") {
    return null;
  }

  const parts = ratio.split("/");
  if (parts.length < 1) {
    return null;
  }

  const numerator = Number(parts[0]);
  return Number.isFinite(numerator) ? numerator : null;
};

const getHashCheckRatioFromDoc = (doc) => {
  return doc?.virusTotalHashCheck?.detectionRatio || null;
};

const getHashCheckDetectedFromDoc = (doc) => {
  const direct = doc?.virusTotalHashCheck?.detectedEngines;
  if (Number.isFinite(direct)) {
    return direct;
  }
  return parseDetectionRatioNumerator(getHashCheckRatioFromDoc(doc));
};

const isAlreadyUploadedFromDoc = (doc) => {
  const filePath = doc?.apkFilePath;
  if (!filePath || typeof filePath !== "string") {
    return false;
  }

  try {
    return fs.existsSync(filePath);
  } catch (_) {
    return false;
  }
};

const hasUploadedApkForPackage = async (esClient, sourceIndex, packageName, sha256) => {
  if (!esClient || (!packageName && !sha256)) {
    return false;
  }

  try {
    const identityShould = [];
    // Prefer exact hash identity to avoid package-level false positives.
    if (sha256) {
      identityShould.push({ term: { sha256: { value: sha256 } } });
    } else if (packageName) {
      identityShould.push({ term: { packageName: { value: packageName } } });
    }

    const candidateIndices = Array.from(
      // Only current-day indices should decide whether re-upload is needed.
      new Set([sourceIndex, getTodayAppsIndexName()].filter(Boolean))
    );

    for (const idx of candidateIndices) {
      try {
        const result = await esClient.search({
          index: idx,
          size: 25,
          query: {
            bool: {
              filter: [
                {
                  bool: {
                    should: identityShould,
                    minimum_should_match: 1,
                  },
                },
                { exists: { field: "apkFilePath" } },
              ],
            },
          },
        });

        const hits = result.hits?.hits || [];
        const hasLiveUpload = hits.some((hit) => isAlreadyUploadedFromDoc(hit?._source || {}));
        if (hasLiveUpload) {
          return true;
        }
      } catch (err) {
        if (err?.meta?.statusCode !== 404) {
          console.error(
            `[ANALYSIS REQUEST] Uploaded APK lookup failed for index ${idx}:`,
            err.message
          );
        }
      }
    }

    return false;
  } catch (err) {
    console.error(
      "[ANALYSIS REQUEST] Failed to check uploaded APK by package/hash:",
      err.message
    );
    return false;
  }
};

const findExistingAnalysisRequest = async (esClient, packageName, sha256) => {
  if (!esClient || (!packageName && !sha256)) {
    return null;
  }

  const should = [];
  if (sha256) {
    should.push({ term: { sha256: { value: sha256 } } });
  }
  if (packageName) {
    should.push({ term: { packageName: { value: packageName } } });
  }

  if (!should.length) {
    return false;
  }

  try {
    const result = await esClient.search({
      index: getRequestsIndexName(),
      size: 1,
      sort: [{ createdAt: { order: "desc", unmapped_type: "date" } }],
      query: {
        bool: {
          filter: [{ term: { type: "apk_upload_request" } }],
          should,
          minimum_should_match: 1,
        },
      },
    });

    const hit = (result.hits?.hits || [])[0];
    return hit || null;
  } catch (err) {
    if (err?.meta?.statusCode === 404) {
      return null;
    }
    console.error("[ANALYSIS REQUEST] Failed to check duplicate SOAR request:", err.message);
    return null;
  }
};

const createAnalysisRequestFromHashCheck = async (esClient, payload) => {
  const {
    appName,
    packageName,
    sha256,
    detectionRatio,
    totalEngines,
    detectedEngines,
    sourceIndex,
    sourceDate,
    alreadyUploaded,
  } = payload || {};

  console.log("\n📋 [ANALYSIS REQUEST] Checking hash check for:", {
    appName,
    packageName,
    sha256: sha256 ? sha256.substring(0, 16) + "..." : "MISSING",
    detectionRatio,
    detectedEngines,
    alreadyUploaded,
  });

  if (!esClient || !sha256) {
    console.log("❌ [ANALYSIS REQUEST] Validation failed: ", {
      hasClient: !!esClient,
      hasSha256: !!sha256,
    });
    return false;
  }

  const detectedFromRatio = parseDetectionRatioNumerator(detectionRatio);
  const finalDetected = Number.isFinite(detectedEngines) ? detectedEngines : detectedFromRatio;

  console.log("🔍 [ANALYSIS REQUEST] Detection calculation:", {
    detectedEnginesInput: detectedEngines,
    detectedFromRatio,
    finalDetected,
  });

  if (!Number.isFinite(finalDetected) || finalDetected < SOAR_TRIGGER_THRESHOLD) {
    console.log(
      `⚠️  [ANALYSIS REQUEST] Skipped - detected engines (${finalDetected}) < ${SOAR_TRIGGER_THRESHOLD} threshold`
    );
    return false;
  }

  if (alreadyUploaded) {
    console.log(
      `⚠️  [ANALYSIS REQUEST] Skipped - APK already uploaded for ${packageName}`
    );
    return false;
  }

  const uploadedForPackage = await hasUploadedApkForPackage(
    esClient,
    sourceIndex,
    packageName,
    sha256
  );
  if (uploadedForPackage) {
    console.log(
      `⚠️  [ANALYSIS REQUEST] Skipped - APK already uploaded for package/hash ${packageName || sha256} (today index)`
    );
    return false;
  }

  const existingRequestHit = await findExistingAnalysisRequest(esClient, packageName, sha256);

  const indexName = getRequestsIndexName();
  const requestId = existingRequestHit?._id || `vt_hash_req_${sha256}`;
  const createdAt = new Date().toISOString();
  const soarId = `SOAR-${Date.now()}-${Math.random().toString(16).slice(2, 10).toUpperCase()}`;
  
  console.log(`📋 [DEDUP CHECK] RequestId: ${requestId} - checking if already exists`);

  const document = {
    type: "apk_upload_request",
    source: "virustotal_hash_check",
    title: "Upload APK for deeper analysis",
    message: `VT hash check detected ${finalDetected} engines. Please upload APK for further analysis.`,
    appName: appName || "Unknown App",
    packageName: packageName || "unknown",
    sha256,
    detectionRatio: detectionRatio || "N/A",
    totalEngines: totalEngines || 0,
    detectedEngines: finalDetected,
    sourceIndex: sourceIndex || "unknown",
    sourceDate: sourceDate || createdAt.slice(0, 10),
    createdAt,
    soarId,
  };

  try {
    console.log(
      `✏️  [ANALYSIS REQUEST] Creating request for ${appName} (${finalDetected} engines detected)`
    );
    console.log(`📌 Index: ${indexName}`);
    
    if (existingRequestHit) {
      await esClient.update({
        index: indexName,
        id: requestId,
        body: {
          doc: {
            ...document,
            refreshedAt: createdAt,
          },
          doc_as_upsert: true,
        },
      });
      console.log(`🔄 [ANALYSIS REQUEST] Refreshed existing request for ${appName}`);
      return true;
    }

    await esClient.index({
      index: indexName,
      id: requestId,
      document,
      op_type: "create",
    });
    
    console.log(
      `✅ [ANALYSIS REQUEST] Successfully created! Message: "${document.message}"`
    );
    return true;
  } catch (err) {
    if (err?.meta?.statusCode === 409) {
      console.log(
        `ℹ️  [ANALYSIS REQUEST] Request already exists for ${sha256.substring(0, 16)}`
      );
      return false;
    }
    console.error(
      `❌ [ANALYSIS REQUEST] Failed for ${appName}:`,
      err.message
    );
    return false;
  }
};

module.exports = {
  getRequestsIndexName,
  getTodayAppsIndexName,
  parseDetectionRatioNumerator,
  getHashCheckRatioFromDoc,
  getHashCheckDetectedFromDoc,
  isAlreadyUploadedFromDoc,
  hasUploadedApkForPackage,
  findExistingAnalysisRequest,
  createAnalysisRequestFromHashCheck,
};
