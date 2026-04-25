const { verifyJWT, extractBearerToken } = require("../utils/oauth2Auth");

/**
 * Check if the request carries a valid admin JWT Bearer token.
 * Returns the decoded payload or null.
 */
const _verifyAdminBearer = (req) => {
  const token = extractBearerToken(req);
  if (!token) return null;
  const payload = verifyJWT(token);
  if (payload && payload.type === "access" && payload.role === "admin") {
    return payload;
  }
  return null;
};

/**
 * Require admin identity via session cookie OR JWT Bearer token.
 * For HTML requests: redirects to /login on failure.
 * For JSON/API requests: returns 401.
 */
const requireAdminSession = (req, res, next) => {
  // 1. Session-based check
  const user = req.session?.user;
  if (req.session?.authenticated && user?.role === "admin" && user?.status !== "deleted") {
    return next();
  }

  // 2. JWT Bearer token check (OAuth2-style)
  const jwtPayload = _verifyAdminBearer(req);
  if (jwtPayload) {
    req.jwtUser = jwtPayload; // available to downstream handlers
    return next();
  }

  // 3. Redirect HTML, reject API
  if (req.accepts(["html", "json"]) === "html") {
    const redirectPath = encodeURIComponent(req.originalUrl || "/");
    return res.redirect(`/login?redirected=1&next=${redirectPath}`);
  }

  return res.status(401).json({
    success: false,
    error: "Authentication required",
    message: "Please login with a verified admin account",
    authenticated: false,
  });
};

/**
 * Require admin identity via session cookie OR JWT Bearer token.
 * Always returns JSON – never redirects.
 */
const requireAdminApi = (req, res, next) => {
  // 1. Session check
  const user = req.session?.user;
  if (req.session?.authenticated && user?.role === "admin" && user?.status !== "deleted") {
    return next();
  }

  // 2. JWT Bearer token check
  const jwtPayload = _verifyAdminBearer(req);
  if (jwtPayload) {
    req.jwtUser = jwtPayload;
    return next();
  }

  return res.status(401).json({
    success: false,
    error: "Authentication required",
    message: "Please login with a verified admin account",
    authenticated: false,
  });
};

/**
 * Allow access to admin session/JWT users OR requests carrying a valid device token.
 * Used for endpoints shared between the admin web dashboard and the mobile agent.
 */
const requireDeviceOrAdminApi = (req, res, next) => {
  // 1. Admin session
  const user = req.session?.user;
  if (req.session?.authenticated && user?.role === "admin" && user?.status !== "deleted") {
    return next();
  }

  // 2. Admin JWT Bearer token
  const jwtPayload = _verifyAdminBearer(req);
  if (jwtPayload) {
    req.jwtUser = jwtPayload;
    return next();
  }

  // 3. Device token (mobile agent)
  const deviceToken = req.get("x-device-token") || req.query?.deviceToken;
  const configuredToken = process.env.DEVICE_API_TOKEN;
  if (configuredToken && deviceToken && deviceToken === configuredToken) {
    return next();
  }

  return res.status(401).json({
    success: false,
    error: "Authentication required",
    message: "Admin session, Bearer token, or device token required",
    authenticated: false,
  });
};

module.exports = {
  requireAdminSession,
  requireAdminApi,
  requireDeviceOrAdminApi,
};