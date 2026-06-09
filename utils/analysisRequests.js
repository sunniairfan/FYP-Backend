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

const APPS_INDEX_PATTERN = "mobile_apps_*";
const REQUESTS_INDEX_PATTERN = "analysis_requests_*";

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
  return Boolean(doc?.apkFilePath) || Boolean(doc?.apkFileName) || Boolean(doc?.uploadId);
};

const hasUploadedApkForPackage = async (esClient, sourceIndex, packageName, sha256) => {
  if (!esClient || (!packageName && !sha256)) {
    return false;
  }

  try {
    const identityShould = [];
    if (packageName) {
      identityShould.push({ term: { packageName: { value: packageName } } });
    }
    if (sha256) {
      identityShould.push({ term: { sha256: { value: sha256 } } });
    }

    const candidateIndices = Array.from(
      new Set([sourceIndex, getTodayAppsIndexName(), APPS_INDEX_PATTERN].filter(Boolean))
    );

    for (const idx of candidateIndices) {
      try {
        const result = await esClient.search({
          index: idx,
          size: 1,
          query: {
            bool: {
              filter: [
                {
                  bool: {
                    should: identityShould,
                    minimum_should_match: 1,
                  },
                },
                {
                  bool: {
                    should: [
                      { exists: { field: "apkFilePath" } },
                      { exists: { field: "apkFileName" } },
                      { exists: { field: "uploadId" } },
                    ],
                    minimum_should_match: 1,
                  },
                },
              ],
            },
          },
        });

        if ((result.hits?.hits || []).length > 0) {
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

const hasExistingAnalysisRequest = async (esClient, packageName, sha256) => {
  if (!esClient || (!packageName && !sha256)) {
    return false;
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
      index: REQUESTS_INDEX_PATTERN,
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

    return (result.hits?.hits || []).length > 0;
  } catch (err) {
    if (err?.meta?.statusCode === 404) {
      return false;
    }
    console.error("[ANALYSIS REQUEST] Failed to check duplicate SOAR request:", err.message);
    return false;
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

  if (!Number.isFinite(finalDetected) || finalDetected < 30) {
    console.log(
      `⚠️  [ANALYSIS REQUEST] Skipped - detected engines (${finalDetected}) < 30 threshold`
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

  const duplicateRequestExists = await hasExistingAnalysisRequest(esClient, packageName, sha256);
  if (duplicateRequestExists) {
    console.log(
      `⚠️  [ANALYSIS REQUEST] Skipped - existing SOAR request already present for ${packageName || sha256}`
    );
    return false;
  }

  const indexName = getRequestsIndexName();
  const requestId = `vt_hash_req_${sha256}`;
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
  hasExistingAnalysisRequest,
  createAnalysisRequestFromHashCheck,
};
