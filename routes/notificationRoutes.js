const express = require("express");
const router = express.Router();
const {
  parseDetectionRatioNumerator,
} = require("../utils/notifications");

const formatFriendlyTime = (value) => {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) {
    const fallback = new Date();
    return `${fallback.getDate()} ${fallback.toLocaleString("en-GB", { month: "long" })} ${String(fallback.getHours()).padStart(2, "0")}:${String(fallback.getMinutes()).padStart(2, "0")}`;
  }
  const day = date.getDate();
  const month = date.toLocaleString("en-GB", { month: "long" });
  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  return `${day} ${month} ${hh}:${mm}`;
};

const resolveDetectedEngines = (source) => {
  if (Number.isFinite(source?.detectedEngines)) {
    return source.detectedEngines;
  }
  const fromNested =
    source?.virusTotalHashCheck?.detectedEngines ??
    source?.virusTotalAnalysis?.detectedEngines;
  if (Number.isFinite(fromNested)) {
    return fromNested;
  }
  return parseDetectionRatioNumerator(
    source?.detectionRatio ||
      source?.virusTotalHashCheck?.detectionRatio ||
      source?.virusTotalAnalysis?.detectionRatio
  ) || 0;
};

const resolveNotificationType = (detectedEngines) => {
  if (detectedEngines >= 30) {
    return { type: "high_risk", severity: "critical", title: "Alert! High risk app found" };
  }
  if (detectedEngines >= 4) {
    return { type: "malicious", severity: "high", title: "Malicious application found!" };
  }
  if (detectedEngines >= 1) {
    return { type: "suspicious", severity: "medium", title: "Suspicious app found!" };
  }
  return { type: "info", severity: "low", title: "App scan notification" };
};

const normalizeNotification = (hit) => {
  const source = hit?._source || {};
  const createdAt = source.createdAt || source.timestamp || new Date().toISOString();
  const detectedEngines = resolveDetectedEngines(source);
  const appName = source.appName || source.packageName || "Unknown App";
  const typed = resolveNotificationType(detectedEngines);

  return {
    ...source,
    id: source.id || hit._id,
    appName,
    detectedEngines,
    type: source.type || typed.type,
    severity: source.severity || typed.severity,
    title: source.title || typed.title,
    createdAt,
    displayTime: formatFriendlyTime(createdAt),
    highPriority: detectedEngines >= 30, // Extra flag for frontend styling
  };
};

const getNotificationPriority = (type) => {
  if (type === "high_risk") return 0; // Highest priority
  if (type === "malicious") return 1;
  if (type === "suspicious") return 2;
  return 3;
};

// GET notifications endpoint
router.get("/", async (req, res) => {
  const esClient = req.app.get("esClient");
  const limit = Math.min(parseInt(req.query.limit, 10) || 10, 50);
  const fetchSize = Math.min(Math.max(limit * 5, 200), 1000);
  const notificationsIndex = "notifications_*";

  try {
    const result = await esClient.search({
      index: notificationsIndex,
      size: fetchSize,
      sort: [
        { createdAt: { order: "desc" } },
      ],
    });

    const notifications = result.hits.hits
      .map(normalizeNotification)
      .sort((a, b) => {
        const priorityDiff = getNotificationPriority(a.type) - getNotificationPriority(b.type);
        if (priorityDiff !== 0) {
          return priorityDiff;
        }
        const timeA = new Date(a.createdAt).getTime() || 0;
        const timeB = new Date(b.createdAt).getTime() || 0;
        return timeB - timeA;
      })
      .slice(0, limit);

    return res.json({
      success: true,
      total: result.hits.total?.value || notifications.length,
      notifications,
    });
  } catch (err) {
    if (err?.meta?.statusCode === 404) {
      return res.json({ success: true, total: 0, notifications: [] });
    }
    console.error("Notifications fetch error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to fetch notifications" });
  }
});

module.exports = router;
