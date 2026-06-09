const fs = require("fs");
const path = require("path");

const blacklistDbPath = path.join(__dirname, "../blacklistDB.json");
const legacySignaturePath = path.join(__dirname, "../signatureDB.json");

let cachedDb = null;
let cachedLegacySet = null;

const normalizeHash = (hash) => String(hash || "").trim().toLowerCase();
const nowIso = () => new Date().toISOString();

const readJsonFile = (filePath, fallbackValue) => {
  try {
    if (!fs.existsSync(filePath)) {
      return fallbackValue;
    }
    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw);
  } catch (err) {
    console.error(`Failed to parse JSON at ${filePath}:`, err.message);
    return fallbackValue;
  }
};

const persistDb = (db) => {
  fs.writeFileSync(blacklistDbPath, JSON.stringify(db, null, 2), "utf-8");
};

const loadLegacySet = () => {
  if (cachedLegacySet) {
    return cachedLegacySet;
  }

  const legacy = readJsonFile(legacySignaturePath, []);
  const hashes = Array.isArray(legacy) ? legacy : [];
  cachedLegacySet = new Set(hashes.map(normalizeHash).filter(Boolean));
  return cachedLegacySet;
};

const createDefaultDb = () => ({
  version: 1,
  updatedAt: nowIso(),
  hashes: {},
});

const ensureDb = () => {
  if (cachedDb) {
    return cachedDb;
  }

  const fromDisk = readJsonFile(blacklistDbPath, null);
  const db = fromDisk && typeof fromDisk === "object" && !Array.isArray(fromDisk)
    ? {
        version: 1,
        updatedAt: fromDisk.updatedAt || nowIso(),
        hashes: fromDisk.hashes && typeof fromDisk.hashes === "object" ? fromDisk.hashes : {},
      }
    : createDefaultDb();

  const legacySet = loadLegacySet();
  if (legacySet.size > 0) {
    const importedAt = nowIso();
    for (const hash of legacySet) {
      if (!db.hashes[hash]) {
        db.hashes[hash] = {
          active: true,
          source: "SignatureDB",
          reason: "Known malicious hash from signature database",
          firstBlacklistedAt: importedAt,
          lastUpdatedAt: importedAt,
          updatedBy: "system",
        };
      }
    }
  }

  db.updatedAt = nowIso();
  cachedDb = db;

  if (!fs.existsSync(blacklistDbPath)) {
    persistDb(db);
  }

  return cachedDb;
};

const getBlacklistEntry = (hash) => {
  const key = normalizeHash(hash);
  if (!key) {
    return null;
  }

  const db = ensureDb();
  const entry = db.hashes[key];
  if (!entry) {
    return null;
  }

  return {
    hash: key,
    active: entry.active !== false,
    source: entry.source || "SOC",
    reason: entry.reason || "Blacklisted by analyst",
    firstBlacklistedAt: entry.firstBlacklistedAt || entry.lastUpdatedAt || db.updatedAt,
    lastUpdatedAt: entry.lastUpdatedAt || db.updatedAt,
    updatedBy: entry.updatedBy || "system",
    appName: entry.appName || null,
    packageName: entry.packageName || null,
  };
};

const isHashBlacklisted = (hash) => {
  const entry = getBlacklistEntry(hash);
  return Boolean(entry && entry.active);
};

const upsertBlacklistEntry = (hash, options = {}) => {
  const key = normalizeHash(hash);
  if (!key) {
    return null;
  }

  const db = ensureDb();
  const existing = db.hashes[key] || {};
  const blacklistedAt = options.blacklistedAt || options.timestamp || nowIso();
  const reason = String(options.reason || "").trim();

  db.hashes[key] = {
    active: options.active !== undefined ? Boolean(options.active) : true,
    source: options.source || existing.source || "SOC Analyst",
    reason: reason || existing.reason || "Marked as malicious by SOC analyst",
    firstBlacklistedAt: existing.firstBlacklistedAt || blacklistedAt,
    lastUpdatedAt: blacklistedAt,
    updatedBy: options.updatedBy || existing.updatedBy || "SOC Analyst",
    appName: options.appName || existing.appName || null,
    packageName: options.packageName || existing.packageName || null,
  };

  db.updatedAt = nowIso();
  cachedDb = db;
  persistDb(db);

  return getBlacklistEntry(key);
};

const listBlacklistEntries = ({ activeOnly = true } = {}) => {
  const db = ensureDb();
  const entries = Object.keys(db.hashes || {}).map((hash) => getBlacklistEntry(hash)).filter(Boolean);
  const filtered = activeOnly ? entries.filter((entry) => entry.active) : entries;
  filtered.sort((a, b) => {
    const aTs = new Date(a.firstBlacklistedAt || a.lastUpdatedAt || 0).getTime() || 0;
    const bTs = new Date(b.firstBlacklistedAt || b.lastUpdatedAt || 0).getTime() || 0;
    return bTs - aTs;
  });
  return filtered;
};

module.exports = {
  isHashBlacklisted,
  getBlacklistEntry,
  upsertBlacklistEntry,
  listBlacklistEntries,
};
