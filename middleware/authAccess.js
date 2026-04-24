const requireAdminSession = (req, res, next) => {
  const user = req.session?.user;
  if (req.session?.authenticated && user?.role === "admin" && user?.status !== "deleted") {
    return next();
  }

  if (req.accepts(["html", "json"]) === "html") {
    return res.redirect("/login");
  }

  return res.status(401).json({
    success: false,
    error: "Authentication required",
    message: "Please login with a verified admin account",
    authenticated: false,
  });
};

const requireAdminApi = (req, res, next) => {
  const user = req.session?.user;
  if (req.session?.authenticated && user?.role === "admin" && user?.status !== "deleted") {
    return next();
  }

  return res.status(401).json({
    success: false,
    error: "Authentication required",
    message: "Please login with a verified admin account",
    authenticated: false,
  });
};

const requireDeviceOrAdminApi = (req, res, next) => {
  const user = req.session?.user;
  if (req.session?.authenticated && user?.role === "admin" && user?.status !== "deleted") {
    return next();
  }

  const deviceToken = req.get("x-device-token") || req.query?.deviceToken;
  const configuredToken = process.env.DEVICE_API_TOKEN;
  if (configuredToken && deviceToken && deviceToken === configuredToken) {
    return next();
  }

  return res.status(401).json({
    success: false,
    error: "Authentication required",
    message: "Admin session or device token required",
    authenticated: false,
  });
};

module.exports = {
  requireAdminSession,
  requireAdminApi,
  requireDeviceOrAdminApi,
};