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
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        body {
          background: #0a192f;
          color: #94a3b8;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
          min-height: 100vh;
          display: flex;
        }
        .sidebar {
          width: 200px;
          background: #112240;
          height: 100vh;
          padding: 20px 0;
          display: flex;
          flex-direction: column;
          position: fixed;
          left: -200px;
          top: 0;
          transition: left 0.3s ease;
          z-index: 1000;
          box-shadow: 2px 0 10px rgba(0, 0, 0, 0.3);
        }
        .sidebar.open {
          left: 0;
        }
        .logo {
          padding: 0 18px 25px;
          display: flex;
          align-items: center;
          gap: 12px;
          color: white;
          font-weight: 600;
          font-size: 17px;
          border-bottom: 1px solid #1d3557;
          margin-bottom: 20px;
        }
        .logo-icon {
          width: 32px;
          height: 32px;
          background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 16px;
          color: white;
        }
        .nav-item {
          padding: 12px 18px;
          color: #94a3b8;
          text-decoration: none;
          display: flex;
          align-items: center;
          gap: 12px;
          transition: all 0.2s;
          font-size: 14px;
          cursor: pointer;
        }
        .nav-item:hover {
          background: #1d3557;
          color: white;
        }
        .nav-item.active {
          background: #000000;
          color: white;
          border-left: 3px solid #2563eb;
        }
        .nav-icon {
          width: 20px;
          text-align: center;
          font-size: 16px;
        }
        .logout-nav {
          margin-top: auto;
          padding: 12px 18px;
          color: #ef4444;
          text-decoration: none;
          display: flex;
          align-items: center;
          gap: 12px;
          transition: all 0.2s;
          font-size: 14px;
          border-top: 1px solid #1d3557;
        }
        .logout-nav:hover {
          background: #7f1d1d;
          color: white;
        }
        .main-content {
          flex: 1;
          padding: 0;
          transition: margin-left 0.3s ease;
        }
        .sidebar.open ~ .main-content {
          margin-left: 200px;
        }
        .overlay {
          display: none;
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0, 0, 0, 0.5);
          z-index: 999;
        }
        .overlay.show {
          display: block;
        }
        .top-bar {
          background: #112240;
          padding: 8px 20px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid #1d3557;
        }
        .menu-toggle {
          background: transparent;
          border: none;
          color: #94a3b8;
          font-size: 18px;
          cursor: pointer;
          padding: 4px 6px;
          display: flex;
          align-items: center;
          transition: color 0.2s;
        }
        .menu-toggle:hover {
          color: white;
        }
        .user-info {
          display: flex;
          align-items: center;
          gap: 10px;
          color: #e2e8f0;
          font-size: 14px;
          font-weight: 500;
        }
        .user-avatar {
          width: 32px;
          height: 32px;
          background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: 600;
          font-size: 14px;
        }
        .content-area {
          padding: 60px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          min-height: calc(100vh - 49px);
        }
        .hero-section {
          text-align: center;
          max-width: 900px;
        }
        .main-title {
          font-size: 2.2em;
          color: white;
          font-weight: 700;
          letter-spacing: 0.5px;
          margin-bottom: 18px;
          line-height: 1.2;
        }
        .subtitle {
          font-size: 1.1em;
          color: #64748b;
          margin-bottom: 60px;
          font-weight: 400;
        }
        .button-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 24px;
          width: 100%;
          max-width: 700px;
          margin: 0 auto;
        }
        .action-card {
          background: #112240;
          border: 1px solid #1d3557;
          border-radius: 12px;
          padding: 35px;
          text-decoration: none;
          display: flex;
          flex-direction: column;
          align-items: flex-start;
          gap: 14px;
          transition: all 0.3s;
          cursor: pointer;
        }
        .action-card:hover {
          border-color: #2563eb;
          transform: translateY(-3px);
          box-shadow: 0 12px 28px rgba(37, 99, 235, 0.3);
          background: #1d3557;
        }
        .card-icon {
          width: 48px;
          height: 48px;
          background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%);
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 20px;
          color: white;
        }
        .card-title {
          font-size: 1.15em;
          color: white;
          font-weight: 600;
          margin-top: 4px;
        }
        .card-desc {
          font-size: 0.9em;
          color: #64748b;
          line-height: 1.5;
        }
      </style>
    </head>
    <body>
      <div class="sidebar" id="sidebar">
        <div class="logo">
          <div class="logo-icon"><i class="fas fa-shield-alt"></i></div>
          <span>CYBER WOLF</span>
        </div>
        <a href="/" class="nav-item active">
          <i class="fas fa-home nav-icon"></i>
          <span>Home</span>
        </a>
        <a href="/dashboard" class="nav-item">
          <i class="fas fa-chart-line nav-icon"></i>
          <span>Dashboard</span>
        </a>
        <a href="/uploadapp/apps" class="nav-item">
          <i class="fas fa-mobile-alt nav-icon"></i>
          <span>App Manager</span>
        </a>
        <a href="#" class="nav-item">
          <i class="fas fa-cog nav-icon"></i>
          <span>Settings</span>
        </a>
        <a href="/logout" class="logout-nav">
          <i class="fas fa-sign-out-alt nav-icon"></i>
          <span>Logout</span>
        </a>
      </div>
      
      <div class="overlay" id="overlay"></div>
      
      <div class="main-content">
        <div class="top-bar">
          <button class="menu-toggle" id="menuToggle"><i class="fas fa-bars"></i></button>
          <div class="user-info">
            <span>Welcome, ${req.session.username}</span>
            <div class="user-avatar">${req.session.username.charAt(0).toUpperCase()}</div>
          </div>
        </div>
        
        <div class="content-area">
          <div class="hero-section">
            <h1 class="main-title">ANDROID MALWARE DETECTION SYSTEM</h1>
            <p class="subtitle">Advanced Security Analysis Platform</p>
            
            <div class="button-grid">
              <a href="/dashboard" class="action-card">
                <div class="card-icon"><i class="fas fa-chart-line"></i></div>
                <div class="card-title">Security Dashboard</div>
                <div class="card-desc">Real-time threat analysis & monitoring</div>
              </a>
              
              <a href="/uploadapp/apps" class="action-card">
                <div class="card-icon"><i class="fas fa-mobile-alt"></i></div>
                <div class="card-title">App Manager</div>
                <div class="card-desc">Upload & analyze APK files</div>
              </a>
            </div>
          </div>
        </div>
      </div>
      
      <script>
        const menuToggle = document.getElementById('menuToggle');
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('overlay');
        
        menuToggle.addEventListener('click', () => {
          sidebar.classList.toggle('open');
          overlay.classList.toggle('show');
        });
        
        overlay.addEventListener('click', () => {
          sidebar.classList.remove('open');
          overlay.classList.remove('show');
        });
      </script>
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