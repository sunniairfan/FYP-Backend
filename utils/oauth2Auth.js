/**
 * OAuth2-inspired JWT authentication helper.
 * Provides access tokens (short-lived) and refresh tokens (long-lived).
 * Used alongside session-based auth – the web dashboard uses sessions,
 * API clients (e.g. Postman, scripts) can use Bearer JWT tokens.
 *
 * Env vars:
 *   JWT_SECRET          – HS256 signing secret (REQUIRED in production)
 *   JWT_ACCESS_TTL_SEC  – access token TTL in seconds  (default 3600 = 1 h)
 *   JWT_REFRESH_TTL_SEC – refresh token TTL in seconds (default 604800 = 7 d)
 */

"use strict";

const crypto = require("crypto");

// ──────────────────────────────────────────────
// Secret key
// ──────────────────────────────────────────────
let _secret = null;

const getSecret = () => {
  if (_secret) return _secret;
  const envSecret = process.env.JWT_SECRET;
  if (!envSecret) {
    // Development fallback – tokens are invalidated on restart
    console.warn(
      "⚠️  JWT_SECRET is not set in .env. Using a random key – tokens will be " +
        "invalid after every server restart. Set JWT_SECRET in .env for production."
    );
    _secret = crypto.randomBytes(32).toString("hex");
  } else {
    _secret = envSecret;
  }
  return _secret;
};

// ──────────────────────────────────────────────
// Minimal JWT (HS256) implementation
// Uses only Node.js built-in crypto – no extra dependencies needed.
// ──────────────────────────────────────────────
const b64url = (str) => Buffer.from(str).toString("base64url");
const parseB64url = (str) => Buffer.from(str, "base64url").toString("utf8");

/**
 * Create a signed HS256 JWT.
 * @param {object} payload  – claims to embed
 * @param {number} ttlSec   – token lifetime in seconds
 * @returns {string}        – compact serialisation: header.payload.signature
 */
const createJWT = (payload, ttlSec = 3600) => {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const claims = { ...payload, iat: now, exp: now + ttlSec };

  const headerEnc = b64url(JSON.stringify(header));
  const payloadEnc = b64url(JSON.stringify(claims));
  const data = `${headerEnc}.${payloadEnc}`;
  const sig = crypto
    .createHmac("sha256", getSecret())
    .update(data)
    .digest("base64url");

  return `${data}.${sig}`;
};

/**
 * Verify and decode a JWT.
 * Returns the decoded payload on success, or null on failure / expiry.
 * @param {string} token
 * @returns {object|null}
 */
const verifyJWT = (token) => {
  try {
    if (typeof token !== "string") return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [headerEnc, payloadEnc, sig] = parts;
    const data = `${headerEnc}.${payloadEnc}`;

    const expectedSig = crypto
      .createHmac("sha256", getSecret())
      .update(data)
      .digest("base64url");

    // Constant-time comparison to prevent timing attacks
    const sigBuf = Buffer.from(sig, "base64url");
    const expectedBuf = Buffer.from(expectedSig, "base64url");
    if (
      sigBuf.length !== expectedBuf.length ||
      !crypto.timingSafeEqual(sigBuf, expectedBuf)
    ) {
      return null;
    }

    const claims = JSON.parse(parseB64url(payloadEnc));

    // Check expiry
    if (claims.exp < Math.floor(Date.now() / 1000)) return null;

    return claims;
  } catch {
    return null;
  }
};

// ──────────────────────────────────────────────
// Refresh token store
// In-memory for simplicity; survives process lifetime.
// Keys: jti (token id) → { userId, email, issuedAt }
// ──────────────────────────────────────────────
const _refreshStore = new Map();

/**
 * Issue a new access + refresh token pair for a user.
 * @param {{ id, email, name, role }} user
 * @returns {{ accessToken, refreshToken, expiresIn }}
 */
const createTokenPair = (user) => {
  const accessTtl = Number(process.env.JWT_ACCESS_TTL_SEC) || 3600;
  const refreshTtl = Number(process.env.JWT_REFRESH_TTL_SEC) || 7 * 24 * 3600;

  const accessToken = createJWT(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      type: "access",
    },
    accessTtl
  );

  const jti = crypto.randomBytes(32).toString("hex");
  const refreshToken = createJWT(
    { sub: user.id, jti, type: "refresh" },
    refreshTtl
  );

  _refreshStore.set(jti, {
    userId: user.id,
    email: user.email,
    issuedAt: Date.now(),
  });

  return { accessToken, refreshToken, expiresIn: accessTtl, tokenType: "Bearer" };
};

/**
 * Exchange a valid refresh token for a new access token.
 * Returns { accessToken, expiresIn } or null if invalid/revoked.
 * @param {string} refreshToken
 * @param {{ id, email, name, role }} user  – must match token subject
 */
const refreshAccessToken = (refreshToken, user) => {
  const payload = verifyJWT(refreshToken);
  if (!payload || payload.type !== "refresh") return null;
  if (!_refreshStore.has(payload.jti)) return null; // revoked

  const accessTtl = Number(process.env.JWT_ACCESS_TTL_SEC) || 3600;
  const accessToken = createJWT(
    {
      sub: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      type: "access",
    },
    accessTtl
  );

  return { accessToken, expiresIn: accessTtl, tokenType: "Bearer" };
};

/**
 * Revoke a refresh token so it can never be exchanged again.
 * @param {string} refreshToken
 * @returns {boolean} true if the token was found and removed
 */
const revokeRefreshToken = (refreshToken) => {
  const payload = verifyJWT(refreshToken);
  if (payload?.jti && _refreshStore.has(payload.jti)) {
    _refreshStore.delete(payload.jti);
    return true;
  }
  return false;
};

/**
 * Revoke ALL active refresh tokens for a given userId.
 * Call this on logout or password change to invalidate all sessions.
 * @param {string} userId
 */
const revokeAllForUser = (userId) => {
  for (const [jti, meta] of _refreshStore.entries()) {
    if (meta.userId === userId) _refreshStore.delete(jti);
  }
};

/**
 * Extract a Bearer token from an Authorization header.
 * Returns the token string or null.
 * @param {import('express').Request} req
 * @returns {string|null}
 */
const extractBearerToken = (req) => {
  const auth = String(req.headers.authorization || "");
  if (auth.startsWith("Bearer ")) return auth.slice(7).trim() || null;
  return null;
};

module.exports = {
  createJWT,
  verifyJWT,
  createTokenPair,
  refreshAccessToken,
  revokeRefreshToken,
  revokeAllForUser,
  extractBearerToken,
};
