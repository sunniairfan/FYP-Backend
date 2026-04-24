const getNotificationsIndexName = () => {
  const today = new Date();
  const year = today.getFullYear();
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const day = String(today.getDate()).padStart(2, "0");
  return `notifications_${year}-${month}-${day}`;
};

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

const getDetectionRatioFromDoc = (doc) => {
  return (
    doc?.virusTotalHashCheck?.detectionRatio ||
    doc?.virusTotalAnalysis?.detectionRatio ||
    doc?.detectionRatio ||
    null
  );
};

const getDetectedEnginesFromDoc = (doc) => {
  const direct = doc?.virusTotalHashCheck?.detectedEngines ?? doc?.virusTotalAnalysis?.detectedEngines ?? doc?.detectedEngines;
  if (Number.isFinite(direct)) {
    return direct;
  }
  return parseDetectionRatioNumerator(getDetectionRatioFromDoc(doc));
};

// Check if notification already sent for this app (DEDUPLICATION - Send only ONCE)
const hasNotificationBeenSent = async (esClient, sha256, detectedEngines) => {
  if (!esClient || !sha256) {
    return false;
  }

  try {
    const notificationsIndex = getNotificationsIndexName();
    const result = await esClient.search({
      index: notificationsIndex,
      size: 1,
      query: {
        bool: {
          must: [
            { term: { sha256: { value: sha256 } } },
            { term: { detectedEngines: { value: detectedEngines } } }
          ]
        }
      }
    });

    const alreadySent = result.hits.hits.length > 0;
    if (alreadySent) {
      console.log(`⚠️  [NOTIFICATION DEDUP] Already sent for SHA256: ${sha256.substring(0, 16)}... (${detectedEngines} engines)`);
    }
    return alreadySent;
  } catch (err) {
    // If index doesn't exist yet, notification hasn't been sent
    if (err?.meta?.statusCode === 404) {
      return false;
    }
    console.error("Error checking notification history:", err.message);
    return false;
  }
};

// Create and send notification - ONLY ONCE PER APP
const createNotification = async (esClient, payload) => {
  const {
    appName,
    packageName,
    sha256,
    detectedEngines,
    totalEngines,
    detectionRatio,
  } = payload || {};

  if (!esClient || !sha256 || !detectedEngines) {
    return false;
  }

  // CHECK IF NOTIFICATION ALREADY SENT - DEDUPLICATION
  const alreadySent = await hasNotificationBeenSent(esClient, sha256, detectedEngines);
  if (alreadySent) {
    console.log(`⏭️  [NOTIFICATION] Skipped - notification already sent for ${appName} (${detectedEngines} engines)`);
    return false;
  }

  // Format date and time
  const now = new Date();
  const dateTime = `${String(now.getDate()).padStart(2, '0')}/${String(now.getMonth() + 1).padStart(2, '0')}/${now.getFullYear()} ${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;

  let notification = null;

  if (detectedEngines >= 30) {
    // HIGH RISK APP (30+ engines)
    notification = {
      id: `notif_high_${sha256}_${Date.now()}`,
      type: "high_risk",
      severity: "critical",
      title: "⚠️ ALERT: High risk app found",
      message: `⚠️ ALERT: High risk app found (${appName}) detected by ${detectedEngines} engines. Please check Upload APK page. ${dateTime}`,
      appName: appName || "Unknown App",
      packageName: packageName || "unknown",
      sha256,
      detectedEngines,
      totalEngines: totalEngines || 0,
      detectionRatio: detectionRatio || "N/A",
      createdAt: now.toISOString(),
      shouldUpload: true, // Flag for frontend to trigger upload
    };
  } else if (detectedEngines >= 4) {
    // MALICIOUS APPLICATION (4-29 engines)
    notification = {
      id: `notif_malicious_${sha256}_${Date.now()}`,
      type: "malicious",
      severity: "high",
      title: "Malicious application found!",
      message: `Malicious application found! (${appName}) detected by ${detectedEngines} engines. ${dateTime}`,
      appName: appName || "Unknown App",
      packageName: packageName || "unknown",
      sha256,
      detectedEngines,
      totalEngines: totalEngines || 0,
      detectionRatio: detectionRatio || "N/A",
      createdAt: now.toISOString(),
    };
  } else if (detectedEngines >= 1) {
    // SUSPICIOUS APP (1-3 engines)
    notification = {
      id: `notif_suspicious_${sha256}_${Date.now()}`,
      type: "suspicious",
      severity: "medium",
      title: "Suspicious app found!",
      message: `Suspicious app found! (${appName}) detected by ${detectedEngines} engines. ${dateTime}`,
      appName: appName || "Unknown App",
      packageName: packageName || "unknown",
      sha256,
      detectedEngines,
      totalEngines: totalEngines || 0,
      detectionRatio: detectionRatio || "N/A",
      createdAt: now.toISOString(),
    };
  }

  if (!notification) {
    return false;
  }

  try {
    await esClient.index({
      index: getNotificationsIndexName(),
      id: notification.id,
      document: notification,
    });
    console.log(`✅ [NOTIFICATION SENT] ${notification.title}`);
    return true;
  } catch (err) {
    console.error(`❌ [NOTIFICATION] Failed for ${appName}:`, err.message);
    return false;
  }
};

module.exports = {
  getNotificationsIndexName,
  createNotification,
  hasNotificationBeenSent,
  parseDetectionRatioNumerator,
  getDetectionRatioFromDoc,
  getDetectedEnginesFromDoc,
};
