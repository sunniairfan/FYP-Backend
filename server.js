const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const session = require("express-session");
const { esClient } = require("./elasticsearch");
const appRoutes = require("./routes/appRoutes");
const uploadAppRoutes = require("./routes/uploadAppRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
// Set up session for user authentication
app.use(
  session({
    secret: process.env.SESSION_SECRET || "cyber-security-malware-detection-2024",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true if using HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);
// Middleware for parsing requests and enabling CORS
app.use(cors());  // Allow cross-origin requests
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse form data
app.set("esClient", esClient); // Attach Elasticsearch client to app

// Create daily Elasticsearch index name (e.g., mobile_apps_02-09-2025)
const getIndexName = () => {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, "0");
  const month = String(today.getMonth() + 1).padStart(2, "0");
  const year = today.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
};

// Helper function to ensure index exists
const ensureIndexExists = async (esClient) => {
  const indexName = getIndexName();
  try {
    const existsResp = await esClient.indices.exists({ index: indexName });
    const exists = existsResp.body === true || existsResp === true;

    if (!exists) {
      await esClient.indices.create({
        index: indexName,
        mappings: {
          properties: {
            appName: { type: "text" },
            packageName: { type: "keyword" },
            sha256: { type: "keyword" },
            sizeMB: { type: "float" },
            status: { type: "keyword" },
            timestamp: { type: "date" },
            uploadedByUser: { type: "boolean" },
            dangerousPermission1: { type: "keyword" },
            dangerousPermission2: { type: "keyword" },
            dangerousPermission3: { type: "keyword" },
            dangerousPermission4: { type: "keyword" },
            dangerousPermission5: { type: "keyword" },
            dangerousPermission6: { type: "keyword" },
            dangerousPermission7: { type: "keyword" },
            dangerousPermission8: { type: "keyword" },
            dangerousPermission9: { type: "keyword" },
            dangerousPermission10: { type: "keyword" },
            dangerousPermission11: { type: "keyword" },
            dangerousPermission12: { type: "keyword" },
            dangerousPermission13: { type: "keyword" },
            dangerousPermission14: { type: "keyword" },
            dangerousPermission15: { type: "keyword" },
            dangerousPermission16: { type: "keyword" },
            dangerousPermission17: { type: "keyword" },
            dangerousPermission18: { type: "keyword" },
            source: { type: "keyword" },
            scanTime: { type: "date" },
            detectionRatio: { type: "keyword" },
            totalEngines: { type: "integer" },
            detectedEngines: { type: "integer" },
            apkFilePath: { type: "keyword" },
            apkFileName: { type: "keyword" },
            uploadSource: { type: "keyword" },
            mobsfAnalysis: { type: "object" },
            lastMobsfAnalysis: { type: "date" },
            mobsfHash: { type: "keyword" },
            mobsfScanType: { type: "keyword" },
            mobsfError: { type: "text" },
          },
        },
      });
      console.log(`✅ Created index: ${indexName}`);
    }
  } catch (err) {
    console.error("❌ Failed to ensure index exists:", err.message);
  }
};

// Run index creation on startup
app.set("ensureIndexExists", ensureIndexExists);

// Ensure index exists and has mapping for uploadedByUser
(async () => {
  await ensureIndexExists(esClient);
})();

// Authentication middleware for web routes
const requireAuth = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    return next();
  } else {
    return res.redirect("/login");
  }
};

// Authentication middleware for API routes
const requireAuthAPI = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    return next();
  } else {
    return res.status(401).json({
      success: false,
      error: "Authentication required",
      message: "Please login to access this resource",
      authenticated: false,
      results: {
        authenticated: false,
        status: "authentication_required",
        error: "Please login to access this resource",
      },
    });
  }
};
// API route to check login status
app.get("/api/auth/status", (req, res) => {
  res.json({
    success: true,
    authenticated: !!(req.session && req.session.authenticated),
    username: req.session?.username || null,
    results: {
      authenticated: !!(req.session && req.session.authenticated),
      username: req.session?.username || null,
      status: req.session && req.session.authenticated ? "authenticated" : "not_authenticated",
    },
  });
});
// API route for login
app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;

  if (username === process.env.AUTH_USERNAME && password === process.env.AUTH_PASSWORD) {
    req.session.authenticated = true;
    req.session.username = username;
    res.json({
      success: true,
      authenticated: true,
      username: username,
      message: "Login successful",
      results: {
        authenticated: true,
        username: username,
        status: "login_successful",
      },
    });
  } else {
    res.status(401).json({
      success: false,
      authenticated: false,
      error: "Invalid credentials",
      message: "Invalid username or password",
      results: {
        authenticated: false,
        status: "login_failed",
        error: "Invalid credentials",
      },
    });
  }
});
// API route for logout
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
      res.status(500).json({
        success: false,
        error: "Logout failed",
      });
    } else {
      res.json({
        success: true,
        authenticated: false,
        message: "Logout successful",
      });
    }
  });
});

// Web Login page
app.get("/login", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Android Malware Detection System - Login</title>
      <style>
        body {
          background: linear-gradient(135deg, #0a0f1c 0%, #1a1f3a 50%, #0d1421 100%);
          color: #60a5fa;
          font-family: 'Courier New', monospace;
          margin: 0;
          padding: 0;
          min-height: 100vh;
          display: flex;
          justify-content: center;
          align-items: center;
        }
        .login-container {
          background: rgba(26, 31, 58, 0.8);
          border: 2px solid #3b82f6;
          border-radius: 15px;
          padding: 40px;
          box-shadow: 0 0 30px rgba(59, 130, 246, 0.3);
          text-align: center;
          backdrop-filter: blur(10px);
          max-width: 400px;
          width: 100%;
        }
        .cyber-title {
          font-size: 2.5em;
          margin-bottom: 10px;
          color: #60a5fa;
          text-shadow: 0 0 20px rgba(96, 165, 250, 0.5);
        }
        .subtitle {
          color: #94a3b8;
          margin-bottom: 30px;
          font-size: 1.1em;
        }
        .form-group {
          margin-bottom: 20px;
          text-align: left;
        }
        label {
          display: block;
          margin-bottom: 8px;
          color: #60a5fa;
          font-weight: bold;
        }
        input[type="text"], input[type="password"] {
          width: 100%;
          padding: 12px;
          background: rgba(15, 23, 42, 0.8);
          border: 2px solid #3b82f6;
          border-radius: 8px;
          color: #60a5fa;
          font-size: 16px;
          box-sizing: border-box;
        }
        input[type="text"]:focus, input[type="password"]:focus {
          outline: none;
          border-color: #60a5fa;
          box-shadow: 0 0 10px rgba(96, 165, 250, 0.3);
        }
        .login-btn {
          background: linear-gradient(45deg, #1e40af, #3b82f6);
          color: white;
          border: none;
          padding: 15px 30px;
          border-radius: 8px;
          font-weight: bold;
          cursor: pointer;
          width: 100%;
          font-size: 16px;
          transition: all 0.3s ease;
          box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
        }
        .login-btn:hover {
          background: linear-gradient(45deg, #2563eb, #60a5fa);
          transform: translateY(-2px);
          box-shadow: 0 6px 20px rgba(96, 165, 250, 0.4);
        }
        .error {
          color: #f87171;
          margin-top: 15px;
          padding: 10px;
          background: rgba(239, 68, 68, 0.1);
          border: 1px solid #f87171;
          border-radius: 5px;
        }
        .shield-icon {
          font-size: 3em;
          margin-bottom: 20px;
          color: #3b82f6;
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <div class="shield-icon">🛡️</div>
        <h1 class="cyber-title">SECURE ACCESS</h1>
        <p class="subtitle">Android Malware Detection System</p>
        <form method="POST" action="/login">
          <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
          </div>
          <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
          </div>
          <button type="submit" class="login-btn">🔐 ACCESS SYSTEM</button>
        </form>
        ${req.query.error ? '<div class="error">⚠️ Invalid credentials. Access denied.</div>' : ""}
      </div>
    </body>
    </html>
  `);
});

// Web login form submission
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username === process.env.AUTH_USERNAME && password === process.env.AUTH_PASSWORD) {
    req.session.authenticated = true;
    req.session.username = username;
    res.redirect("/");
  } else {
    res.redirect("/login?error=1");
  }
});

// Web Logout route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
    }
    res.redirect("/login");
  });
});

// Mount routes
app.use("/api/app", appRoutes); // Mobile API routes 
app.use("/dashboard", requireAuth, dashboardRoutes); // Web dashboard routes
app.use("/uploadapp", uploadAppRoutes); // Upload app routes 

// Main dashboard page (requires login)
app.get("/", requireAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Android Malware Detection System</title>
      <style>
        body {
          background: linear-gradient(135deg, #0a0f1c 0%, #1a1f3a 50%, #0d1421 100%);
          color: #60a5fa;
          font-family: 'Courier New', monospace;
          text-align: center;
          padding: 50px;
          min-height: 100vh;
          margin: 0;
        }
        .main-container {
          max-width: 1200px;
          margin: 0 auto;
        }
        .cyber-header {
          margin-bottom: 40px;
        }
        .main-title {
          font-size: 3.5em;
          margin-bottom: 10px;
          color: #60a5fa;
          text-shadow: 0 0 30px rgba(96, 165, 250, 0.5);
          letter-spacing: 2px;
        }
        .subtitle {
          font-size: 1.3em;
          margin-bottom: 20px;
          color: #94a3b8;
          font-weight: 300;
        }
        .status-badge {
          display: inline-block;
          background: linear-gradient(45deg, #059669, #10b981);
          color: white;
          padding: 10px 20px;
          border-radius: 25px;
          font-weight: bold;
          margin: 20px 0;
          box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
        }
        .user-info {
          position: absolute;
          top: 20px;
          right: 20px;
          color: #94a3b8;
          font-size: 0.9em;
        }
        .logout-btn {
          background: linear-gradient(45deg, #dc2626, #ef4444);
          color: white;
          text-decoration: none;
          padding: 8px 16px;
          border-radius: 5px;
          margin-left: 15px;
          font-size: 0.8em;
          transition: all 0.3s ease;
        }
        .logout-btn:hover {
          background: linear-gradient(45deg, #b91c1c, #dc2626);
          transform: translateY(-1px);
        }
        .button-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 30px;
          margin-top: 40px;
          max-width: 800px;
          margin-left: auto;
          margin-right: auto;
        }
        .cyber-button {
          background: linear-gradient(45deg, #1e40af, #3b82f6);
          color: white;
          text-decoration: none;
          padding: 25px 35px;
          border-radius: 12px;
          font-weight: bold;
          font-size: 1.1em;
          transition: all 0.3s ease;
          box-shadow: 0 8px 25px rgba(59, 130, 246, 0.3);
          border: 2px solid transparent;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 15px;
        }
        .cyber-button:hover {
          background: linear-gradient(45deg, #2563eb, #60a5fa);
          transform: translateY(-5px);
          box-shadow: 0 15px 35px rgba(96, 165, 250, 0.4);
          border-color: #60a5fa;
        }
        .cyber-button.upload {
          background: linear-gradient(45deg, #059669, #10b981);
        }
        .cyber-button.upload:hover {
          background: linear-gradient(45deg, #047857, #059669);
          box-shadow: 0 15px 35px rgba(16, 185, 129, 0.4);
          border-color: #10b981;
        }
        .button-icon {
          font-size: 1.5em;
        }
        .button-text {
          display: flex;
          flex-direction: column;
          align-items: flex-start;
        }
        .button-title {
          font-size: 1.1em;
          margin-bottom: 5px;
        }
        .button-desc {
          font-size: 0.8em;
          color: rgba(255, 255, 255, 0.8);
          font-weight: normal;
        }
        .shield-animation {
          font-size: 4em;
          margin-bottom: 20px;
          animation: pulse 2s infinite;
          color: #3b82f6;
        }
        @keyframes pulse {
          0% { transform: scale(1); }
          50% { transform: scale(1.1); }
          100% { transform: scale(1); }
        }
        .security-stats {
          display: flex;
          justify-content: center;
          gap: 40px;
          margin: 40px 0;
          flex-wrap: wrap;
        }
        .stat-card {
          background: rgba(26, 31, 58, 0.6);
          border: 1px solid #3b82f6;
          border-radius: 10px;
          padding: 20px;
          min-width: 120px;
          backdrop-filter: blur(10px);
        }
        .stat-number {
          font-size: 2em;
          color: #60a5fa;
          font-weight: bold;
        }
        .stat-label {
          color: #94a3b8;
          font-size: 0.9em;
          margin-top: 5px;
        }
      </style>
    </head>
    <body>
      <div class="user-info">
        👤 Welcome, ${req.session.username}
        <a href="/logout" class="logout-btn">🚪 Logout</a>
      </div>
      
      <div class="main-container">
        <div class="cyber-header">
          <div class="shield-animation">🛡️</div>
          <h1 class="main-title">ANDROID MALWARE DETECTION SYSTEM</h1>
          <p class="subtitle">Advanced Security Analysis Platform</p>
        </div>

        <div class="button-grid">
          <a href="/dashboard" class="cyber-button">
            <span class="button-icon">📊</span>
            <div class="button-text">
              <div class="button-title">Security Dashboard</div>
              <div class="button-desc">Real-time threat analysis & monitoring</div>
            </div>
          </a>
          
          <a href="/uploadapp/apps" class="cyber-button upload">
            <span class="button-icon">📱</span>
            <div class="button-text">
              <div class="button-title">App Manager</div>
              <div class="button-desc">Upload & analyze APK files</div>
            </div>
          </a>
        </div>
      </div>
    </body>
    </html>
  `);
});
// Start server and log endpoints
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`🔐 Login at: http://localhost:${PORT}/login`);
  console.log(`📊 Dashboard available at: http://localhost:${PORT}/dashboard`);
  console.log(`📱 Upload manager at: http://localhost:${PORT}/uploadapp/apps`);
  console.log(`🔌 API endpoints:`);
  console.log(`   - Auth Status: http://localhost:${PORT}/api/auth/status`);
  console.log(`   - API Login: http://localhost:${PORT}/api/auth/login`);
  console.log(`   - API Logout: http://localhost:${PORT}/api/auth/logout`);
  console.log(`   - Mobile Upload: http://localhost:${PORT}/uploadapp/upload (No Auth Required)`);
  console.log(`   - Mobile Scan: http://localhost:${PORT}/api/app/upload (No Auth Required)`);
});