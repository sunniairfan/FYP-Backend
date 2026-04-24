const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const session = require("express-session");
const { esClient } = require("./elasticsearch");
const appRoutes = require("./routes/appRoutes");
const uploadAppRoutes = require("./routes/uploadAppRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const resultsRoutes = require("./routes/resultsRoutes");
const notificationRoutes = require("./routes/notificationRoutes");
const analysisRequestRoutes = require("./routes/analysisRequestRoutes");
const authRoutes = require("./routes/authRoutes");
const { ensureAdminAuthIndices } = require("./utils/adminAuth");

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
app.set("ensureAdminAuthIndices", ensureAdminAuthIndices);

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
            scan_time: { type: "date", format: "epoch_millis" },
            device_id: { type: "keyword" },
            device_model: { type: "keyword" },
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
  await ensureAdminAuthIndices(esClient);
})();

// Mount routes
app.use("/", authRoutes);
app.use("/api/app", appRoutes); // Mobile API routes 
app.use("/api/notifications", notificationRoutes); // Notifications API
app.use("/api/analysis-requests", analysisRequestRoutes); // Hash-check analysis requests
app.use("/dashboard", dashboardRoutes); // Web dashboard routes
app.use("/uploadapp", uploadAppRoutes); // Upload app routes 
app.use("/results", resultsRoutes); // Analysis results page routes

// Main dashboard page
app.get("/", (req, res) => {
  const displayName = String(req.session?.user?.name || req.session?.username || "User");
  const avatarInitial = displayName.charAt(0).toUpperCase();
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
          background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%); border-radius: 8px;
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
        .top-actions {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .notification-bell {
          position: relative;
          background: transparent;
          border: none;
          color: #94a3b8;
          cursor: pointer;
          font-size: 18px;
          padding: 6px 8px;
          transition: color 0.2s;
        }
        .notification-bell:hover {
          color: white;
        }
        .notification-badge {
          position: absolute;
          top: 2px;
          right: 2px;
          background: #ef4444;
          color: white;
          border-radius: 10px;
          font-size: 10px;
          padding: 2px 5px;
          line-height: 1;
          min-width: 16px;
          text-align: center;
          display: none;
        }
        .notification-panel {
          position: absolute;
          right: 10px;
          top: 50px;
          background: #0f172a;
          border: 1px solid #1d3557;
          border-radius: 8px;
          width: 340px;
          max-height: 400px;
          overflow-y: auto;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
          display: none;
          z-index: 1001;
        }
        .notification-panel.show {
          display: block;
        }
        .notification-item {
          padding: 12px 14px;
          border-bottom: 1px solid #1d3557;
        }
        .notification-item:last-child {
          border-bottom: none;
        }
        .notification-title {
          font-size: 13px;
          color: #f87171;
          font-weight: 600;
          margin-bottom: 4px;
        }
        .notification-meta {
          font-size: 11px;
          color: #94a3b8;
          line-height: 1.4;
        }
        .notification-popup {
          position: fixed;
          right: 20px;
          top: 70px;
          background: #111827;
          border: 1px solid #ef4444;
          border-radius: 10px;
          padding: 14px 16px;
          width: 320px;
          display: none;
          z-index: 2000;
          box-shadow: 0 12px 28px rgba(239, 68, 68, 0.3);
        }
        .notification-popup.show {
          display: block;
        }
        .popup-title {
          color: #f87171;
          font-weight: 700;
          font-size: 14px;
          margin-bottom: 6px;
        }
        .popup-body {
          color: #e2e8f0;
          font-size: 12px;
          line-height: 1.5;
        }
        .popup-close {
          margin-top: 10px;
          background: #1f2937;
          color: #e2e8f0;
          border: 1px solid #374151;
          border-radius: 6px;
          padding: 6px 10px;
          font-size: 12px;
          cursor: pointer;
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
          background: #3a3a3a;
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
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 24px;
          width: 100%;
          max-width: 1000px;
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
          background: #3a3a3a;
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
          <div class="top-actions">
            <button class="notification-bell" id="notificationBell" aria-label="Notifications">
              <i class="fas fa-bell"></i>
              <span class="notification-badge" id="notificationBadge">0</span>
            </button>
            <div class="user-info">
            <span>Welcome, ${displayName}</span>
            <div class="user-avatar">${avatarInitial}</div>
            </div>
          </div>
        </div>

        <div class="notification-panel" id="notificationPanel"></div>
        <div class="notification-popup" id="notificationPopup">
          <div class="popup-title">High malware detection</div>
          <div class="popup-body" id="popupBody">A high-risk app was detected. Uninstall recommended.</div>
          <button class="popup-close" id="popupClose">Close</button>
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
              
              <a href="/results" class="action-card">
                <div class="card-icon"><i class="fas fa-file-alt"></i></div>
                <div class="card-title">Analysis Results</div>
                <div class="card-desc">View detailed app analysis & reports</div>
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

        const notificationBell = document.getElementById('notificationBell');
        const notificationBadge = document.getElementById('notificationBadge');
        const notificationPanel = document.getElementById('notificationPanel');
        const notificationPopup = document.getElementById('notificationPopup');
        const popupBody = document.getElementById('popupBody');
        const popupClose = document.getElementById('popupClose');

        const dismissedKey = 'dismissedNotificationsHome';
        const dismissedSet = new Set(JSON.parse(localStorage.getItem(dismissedKey) || '[]'));
        let latestNotificationId = null;

        function setBadgeCount(count) {
          if (count > 0) {
            notificationBadge.textContent = String(count);
            notificationBadge.style.display = 'inline-block';
          } else {
            notificationBadge.style.display = 'none';
          }
        }

        function renderNotifications(items) {
          if (!items.length) {
            notificationPanel.innerHTML = '<div class="notification-item"><div class="notification-meta">No notifications yet.</div></div>';
            return;
          }
          notificationPanel.innerHTML = items.map((item) => {
            const appLabel = item.appName || item.packageName || 'Unknown app';
            const ratio = item.detectionRatio || 'N/A';
            const when = item.createdAt ? new Date(item.createdAt).toLocaleString() : '';
            return (
              '<div class="notification-item">' +
                '<div class="notification-title">' + (item.title || 'Alert') + '</div>' +
                '<div class="notification-meta">' + appLabel + ' · ' + ratio + ' · ' + when + '</div>' +
                '<div class="notification-meta">' + (item.message || '') + '</div>' +
              '</div>'
            );
          }).join('');
        }

        function deduplicateByPackage(items) {
          const seen = new Map();
          return items.filter((item) => {
            const key = item.packageName || item.sha256 || 'unknown';
            if (seen.has(key)) {
              return false;
            }
            seen.set(key, true);
            return true;
          });
        }

        function maybeShowPopup(items) {
          if (!items.length) return;
          const first = items[0];
          latestNotificationId = first.id || null;
          if (dismissedSet.has(first.id)) return;
          const appLabel = first.appName || first.packageName || 'Unknown app';
          popupBody.textContent = appLabel + ' detected by ' + (first.detectedEngines || 'many') + ' engines. Uninstall recommended.';
          notificationPopup.classList.add('show');
        }

        async function loadNotifications() {
          try {
            const res = await fetch('/api/notifications?limit=10&audience=admin');
            const data = await res.json();
            let items = data.notifications || [];
            items = deduplicateByPackage(items);
            setBadgeCount(items.length > 0 ? items.length : 0);
            renderNotifications(items);
            maybeShowPopup(items);
          } catch (err) {
            console.error('Failed to load notifications', err);
          }
        }

        notificationBell.addEventListener('click', () => {
          notificationPanel.classList.toggle('show');
        });

        popupClose.addEventListener('click', () => {
          notificationPopup.classList.remove('show');
          if (latestNotificationId) {
            dismissedSet.add(latestNotificationId);
            localStorage.setItem(dismissedKey, JSON.stringify(Array.from(dismissedSet)));
          }
        });

        loadNotifications();
        setInterval(loadNotifications, 60000);
      </script>
    </body>
    </html>
  `);
});
// Start server and log endpoints
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`🔐 Login at: http://localhost:${PORT}/login`);
  console.log(`📝 Signup at: http://localhost:${PORT}/signup`);
  console.log(`📊 Dashboard available at: http://localhost:${PORT}/dashboard`);
  console.log(`📱 Upload manager at: http://localhost:${PORT}/uploadapp/apps`);
  console.log(`🔌 API endpoints:`);
  console.log(`   - Auth Status: http://localhost:${PORT}/api/auth/status`);
  console.log(`   - API Login: http://localhost:${PORT}/api/auth/login`);
  console.log(`   - API Logout: http://localhost:${PORT}/api/auth/logout`);
  console.log(`   - Signup Code Request: http://localhost:${PORT}/api/auth/signup/request-code`);
  console.log(`   - Signup Code Verify: http://localhost:${PORT}/api/auth/signup/verify-code`);
  console.log(`   - Admin Users: http://localhost:${PORT}/api/auth/admin/users`);
  console.log(`   - Delete Account Request Code: http://localhost:${PORT}/api/auth/delete/request-code`);
  console.log(`   - Admin Upload: http://localhost:${PORT}/uploadapp/upload`);
  console.log(`   - App Scan: http://localhost:${PORT}/api/app/upload`);
});


