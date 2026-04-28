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

const { requireAdminSession } = require("./middleware/authAccess");
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

// Main homepage (protected – redirect to /login if not authenticated)
app.get("/", requireAdminSession, (req, res) => {
  const displayName = String(req.session?.user?.name || req.jwtUser?.name || "User");
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
          background: #05090f;
          color: #94a3b8;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
          min-height: 100vh;
          display: flex;
        }
        .sidebar {
          width: 240px;
          background: #0b1120;
          height: 100vh;
          padding: 0;
          display: flex;
          flex-direction: column;
          position: fixed;
          left: -240px;
          top: 0;
          transition: left 0.3s cubic-bezier(0.4, 0, 0.2, 1);
          z-index: 1000;
          box-shadow: 4px 0 24px rgba(0, 0, 0, 0.6);
          border-right: 1px solid #1a2332;
        }
        .sidebar.open {
          left: 0;
        }
        .logo {
          padding: 22px 20px;
          display: flex;
          align-items: center;
          gap: 12px;
          color: white;
          font-weight: 700;
          font-size: 16px;
          border-bottom: 1px solid #1a2332;
          letter-spacing: 0.5px;
        }
        .logo-icon {
          width: 38px;
          height: 38px;
          background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 18px;
          color: white;
          box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);
        }
        .nav-section-title {
          padding: 20px 20px 8px;
          color: #475569;
          font-size: 10px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 1.2px;
        }
        .nav-item {
          padding: 11px 20px;
          color: #94a3b8;
          text-decoration: none;
          display: flex;
          align-items: center;
          gap: 14px;
          transition: all 0.2s ease;
          font-size: 14px;
          cursor: pointer;
          border-left: 3px solid transparent;
          margin: 1px 0;
        }
        .nav-item:hover {
          background: rgba(59, 130, 246, 0.08);
          color: #e2e8f0;
          border-left-color: rgba(59, 130, 246, 0.3);
        }
        .nav-item.active {
          background: rgba(59, 130, 246, 0.15);
          color: #60a5fa;
          border-left-color: #3b82f6;
          font-weight: 600;
        }
        .nav-icon {
          width: 20px;
          text-align: center;
          font-size: 16px;
        }
        .logout-nav {
          margin-top: auto;
          padding: 14px 20px;
          color: #f87171;
          text-decoration: none;
          display: flex;
          align-items: center;
          gap: 14px;
          transition: all 0.2s ease;
          font-size: 14px;
          border-top: 1px solid #1a2332;
        }
        .logout-nav:hover {
          background: rgba(239, 68, 68, 0.15);
          color: #fca5a5;
        }
        .main-content {
          flex: 1;
          padding: 0;
          transition: margin-left 0.3s ease;
        }
        .sidebar.open ~ .main-content {
          margin-left: 240px;
        }
        .overlay {
          display: none;
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0, 0, 0, 0.7);
          z-index: 999;
          backdrop-filter: blur(2px);
        }
        .overlay.show {
          display: block;
        }
        .top-bar {
          background: #0b1120;
          padding: 12px 24px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid #1a2332;
          box-shadow: 0 2px 12px rgba(0, 0, 0, 0.4);
          position: sticky;
          top: 0;
          z-index: 100;
        }
        .top-actions {
          display: flex;
          align-items: center;
          gap: 12px;
        }
        .notification-bell {
          position: relative;
          background: transparent;
          border: 1px solid #1a2332;
          color: #94a3b8;
          cursor: pointer;
          font-size: 16px;
          padding: 8px 10px;
          transition: all 0.2s ease;
          border-radius: 8px;
        }
        .notification-bell:hover {
          color: white;
          background: rgba(59, 130, 246, 0.1);
          border-color: rgba(59, 130, 246, 0.3);
        }
        .notification-badge {
          position: absolute;
          top: -4px;
          right: -4px;
          background: #ef4444;
          color: white;
          border-radius: 12px;
          font-size: 10px;
          padding: 3px 6px;
          line-height: 1;
          min-width: 18px;
          text-align: center;
          display: none;
          font-weight: 700;
          box-shadow: 0 2px 8px rgba(239, 68, 68, 0.4);
        }
        .notification-panel {
          position: fixed;
          right: 16px;
          top: 62px;
          background: #0b1120;
          border: 1px solid #1e3a66;
          border-radius: 12px;
          width: 380px;
          max-height: 450px;
          overflow-y: auto;
          box-shadow: 0 16px 48px rgba(0, 0, 0, 0.6);
          display: none;
          z-index: 1001;
        }
        .notification-panel.show {
          display: block;
        }
        .notification-panel-header {
          padding: 14px 18px;
          border-bottom: 1px solid #1a2332;
          font-size: 13px;
          font-weight: 700;
          color: #e2e8f0;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .notification-item {
          padding: 14px 18px;
          border-bottom: 1px solid #1a2332;
          transition: background 0.15s ease;
          cursor: default;
        }
        .notification-item:hover {
          background: rgba(59, 130, 246, 0.05);
        }
        .notification-item:last-child {
          border-bottom: none;
        }
        .notification-title {
          font-size: 13px;
          color: #f87171;
          font-weight: 600;
          margin-bottom: 5px;
          display: flex;
          align-items: center;
          gap: 6px;
        }
        .notification-meta {
          font-size: 12px;
          color: #94a3b8;
          line-height: 1.5;
        }
        .notification-popup {
          position: fixed;
          right: 20px;
          top: 72px;
          background: #0b1120;
          border: 1px solid #ef4444;
          border-radius: 12px;
          padding: 16px 18px;
          width: 360px;
          display: none;
          z-index: 2000;
          box-shadow: 0 16px 40px rgba(239, 68, 68, 0.35);
        }
        .notification-popup.show {
          display: block;
        }
        .popup-title {
          color: #f87171;
          font-weight: 700;
          font-size: 15px;
          margin-bottom: 8px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .popup-body {
          color: #cbd5e1;
          font-size: 13px;
          line-height: 1.6;
        }
        .popup-close {
          margin-top: 12px;
          background: rgba(59, 130, 246, 0.1);
          color: #94a3b8;
          border: 1px solid rgba(59, 130, 246, 0.3);
          border-radius: 8px;
          padding: 8px 14px;
          font-size: 12px;
          cursor: pointer;
          transition: all 0.2s ease;
          font-weight: 600;
        }
        .popup-close:hover {
          background: rgba(59, 130, 246, 0.2);
          color: #e2e8f0;
        }
        .menu-toggle {
          background: transparent;
          border: none;
          color: #94a3b8;
          font-size: 19px;
          cursor: pointer;
          padding: 6px 8px;
          display: flex;
          align-items: center;
          transition: all 0.2s ease;
          border-radius: 8px;
        }
        .menu-toggle:hover {
          color: white;
          background: rgba(59, 130, 246, 0.1);
        }
        .user-info {
          display: flex;
          align-items: center;
          gap: 12px;
          color: #e2e8f0;
          font-size: 13.5px;
          font-weight: 500;
        }
        .user-avatar {
          width: 34px;
          height: 34px;
          background: linear-gradient(135deg, #3b82f6, #2563eb);
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: 700;
          font-size: 14px;
          box-shadow: 0 2px 10px rgba(59, 130, 246, 0.3);
        }
        .content-area {
          padding: 40px 60px 50px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          min-height: calc(100vh - 58px);
        }
        .hero-section {
          text-align: center;
          max-width: 900px;
        }
        .main-title {
          font-size: 2.2em;
          color: #f1f5f9;
          font-weight: 600;
          letter-spacing: -0.3px;
          margin-bottom: 14px;
          line-height: 1.2;
          text-transform: uppercase;
          background: linear-gradient(135deg, #f1f5f9, #94a3b8);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
        }
        .subtitle {
          font-size: 1.05em;
          color: #64748b;
          margin-bottom: 45px;
          font-weight: 500;
          letter-spacing: 0.3px;
        }
        .button-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 20px;
          width: 100%;
          max-width: 1000px;
          margin: 0 auto;
        }
        .action-card {
          background: linear-gradient(135deg, #0f1729 0%, #0b1120 100%);
          border: 1px solid #1a2332;
          border-radius: 14px;
          padding: 32px;
          text-decoration: none;
          display: flex;
          flex-direction: column;
          align-items: flex-start;
          gap: 14px;
          transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
          cursor: pointer;
          position: relative;
          overflow: hidden;
        }
        .action-card::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 3px;
          background: linear-gradient(90deg, #3b82f6, #2563eb);
          opacity: 0;
          transition: opacity 0.3s ease;
        }
        .action-card:hover {
          border-color: rgba(59, 130, 246, 0.5);
          transform: translateY(-5px);
          box-shadow: 0 16px 40px rgba(59, 130, 246, 0.2);
          background: linear-gradient(135deg, #131e35 0%, #0f1729 100%);
        }
        .action-card:hover::before {
          opacity: 1;
        }
        .card-icon {
          width: 54px;
          height: 54px;
          background: linear-gradient(135deg, rgba(59, 130, 246, 0.15), rgba(37, 99, 235, 0.1));
          border: 1px solid rgba(59, 130, 246, 0.3);
          border-radius: 12px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 22px;
          color: #60a5fa;
        }
        .card-title {
          font-size: 1.2em;
          color: #f1f5f9;
          font-weight: 700;
          margin-top: 4px;
          letter-spacing: -0.2px;
          text-align: left;
        }
        .card-desc {
          font-size: 0.92em;
          color: #64748b;
          line-height: 1.6;
          text-align: left;
        }
      </style>
    </head>
    <body>
      <div class="sidebar" id="sidebar">
        <div class="logo">
          <div class="logo-icon"><i class="fas fa-shield-alt"></i></div>
          <span>CYBER WOLF</span>
        </div>
        
        <div class="nav-section-title">NAVIGATION</div>
        <a href="/" class="nav-item active">
          <i class="fas fa-home nav-icon"></i>
          <span>Home</span>
        </a>
        <a href="/dashboard" class="nav-item">
          <i class="fas fa-chart-line nav-icon"></i>
          <span>Security Dashboard</span>
        </a>
        <a href="/uploadapp/apps" class="nav-item">
          <i class="fas fa-mobile-alt nav-icon"></i>
          <span>App Manager</span>
        </a>
        <a href="/results" class="nav-item">
          <i class="fas fa-file-alt nav-icon"></i>
          <span>Analysis Results</span>
        </a>
        
        <div class="nav-section-title" style="margin-top: 12px;">SYSTEM</div>
        <a href="#" class="nav-item">
          <i class="fas fa-cog nav-icon"></i>
          <span>Settings</span>
        </a>
        
        <a href="/logout" class="logout-nav">
          <i class="fas fa-sign-out-alt nav-icon"></i>
          <span>Sign Out</span>
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
          <div class="popup-title"><i class="fas fa-exclamation-triangle"></i>High Risk Detected</div>
          <div class="popup-body" id="popupBody">A high-risk app was detected. Immediate action recommended.</div>
          <button class="popup-close" id="popupClose">Dismiss</button>
        </div>
        
        <div class="content-area">
          <div class="hero-section">
            <h1 class="main-title">ANDROID MALWARE DETECTION SYSTEM</h1>
            <p class="subtitle">Advanced Security Analysis Platform</p>
            
            <div class="button-grid">
              <a href="/dashboard" class="action-card">
                <div class="card-icon"><i class="fas fa-chart-line"></i></div>
                <div class="card-title">Security Dashboard</div>
                <div class="card-desc">Real-time threat monitoring & detection insights</div>
              </a>
              
              <a href="/uploadapp/apps" class="action-card">
                <div class="card-icon"><i class="fas fa-mobile-alt"></i></div>
                <div class="card-title">App Manager</div>
                <div class="card-desc">Upload & analyze Android APK files</div>
              </a>
              
              <a href="/results" class="action-card">
                <div class="card-icon"><i class="fas fa-file-alt"></i></div>
                <div class="card-title">Analysis Results</div>
                <div class="card-desc">Detailed reports & comprehensive analysis</div>
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
          const header = '<div class="notification-panel-header"><i class="fas fa-bell" style="color:#f87171;"></i>Threat Alerts</div>';
          if (!items.length) {
            notificationPanel.innerHTML = header + '<div class="notification-item"><div class="notification-meta">No active alerts.</div></div>';
            return;
          }
          notificationPanel.innerHTML = header + items.map((item) => {
            const appLabel = item.appName || item.packageName || 'Unknown app';
            const ratio = item.detectionRatio || 'N/A';
            const when = item.createdAt ? new Date(item.createdAt).toLocaleString() : '';
            const title = item.title || 'Alert';
            const showIcon = title.toLowerCase().includes('alert') || title.toLowerCase().includes('malicious');
            return (
              '<div class="notification-item">' +
                '<div class="notification-title">' + (showIcon ? '<i class="fas fa-exclamation-triangle" style="color:#ef4444;"></i>' : '') + title + '</div>' +
                '<div class="notification-meta">' + appLabel + ' &middot; ' + ratio + '</div>' +
                '<div class="notification-meta" style="margin-top:3px;">' + when + '</div>' +
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


