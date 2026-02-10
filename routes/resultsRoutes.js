const express = require("express");
const router = express.Router();
const { checkVirusTotal } = require("../utils/virusTotal");

// Middleware to require authentication for web routes
const requireWebAuth = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    return next();
  } else {
    return res.redirect("/login");
  }
};

// Helper function to generate dynamic index name based on date
function getIndexNameForDate(dateString) {
  const date = new Date(dateString);
  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = date.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
}

// GET /results - All analysis results page - REQUIRES WEB AUTH
router.get("/", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);

    console.log(`[Results] Loading apps from index: ${indexName}`);

    let apps = [];
    try {
      const result = await esClient.search({
        index: indexName,
        size: 100,
        query: { term: { uploadedByUser: true } },
        sort: [{ timestamp: { order: "desc" } }],
      });

      apps = result.hits.hits.map((hit) => ({
        ...hit._source,
        id: hit._id,
      }));

      // Fetch VT hash check for apps that don't have it
      for (let i = 0; i < apps.length; i++) {
        if (!apps[i].virusTotalHashCheck && apps[i].sha256) {
          console.log(`[Results] Fetching VT hash check for: ${apps[i].packageName}`);
          try {
            const vtResult = await checkVirusTotal(apps[i].sha256);
            if (vtResult) {
              apps[i].virusTotalHashCheck = {
                detectionRatio: vtResult.detectionRatio,
                totalEngines: vtResult.totalEngines,
                detectedEngines: vtResult.detectedEngines,
                scanTime: vtResult.scanTime
              };
              
              // Update database with VT hash check
              try {
                await esClient.update({
                  index: indexName,
                  id: result.hits.hits[i]._id,
                  body: {
                    doc: {
                      virusTotalHashCheck: apps[i].virusTotalHashCheck,
                      status: vtResult.status,
                      source: "VirusTotal"
                    }
                  }
                });
                console.log(`✅ Updated VT hash check for: ${apps[i].packageName}`);
              } catch (updateErr) {
                console.log(`⚠️ Could not update VT hash in database: ${updateErr.message}`);
              }
            }
          } catch (vtErr) {
            console.log(`ℹ️ Could not fetch VT hash for ${apps[i].packageName}: ${vtErr.message}`);
          }
        }
      }
    } catch (indexError) {
      console.log(`[Results] Index ${indexName} not found`);
    }

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Analysis Results - Android Malware Detector</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a192f;
      color: #94a3b8;
      min-height: 100vh;
      display: flex;
      position: relative;
    }

    /* Sidebar */
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
      z-index: 1000;
      box-shadow: 2px 0 10px rgba(0, 0, 0, 0.3);
      transition: left 0.3s ease;
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
    }

    /* Main content */
    .main-content {
      margin-left: 0;
      flex: 1;
      width: 100%;
      transition: margin-left 0.3s ease;
    }

    .main-content.shifted {
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

    .overlay.active {
      display: block;
    }

    .top-bar {
      background: #112240;
      padding: 8px 15px 8px 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #1d3557;
    }

    .menu-btn {
      background: transparent;
      border: none;
      color: #94a3b8;
      font-size: 18px;
      cursor: pointer;
      padding: 4px 6px;
      transition: color 0.3s;
    }

    .menu-btn:hover {
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
    }

    .container {
      padding: 30px;
      max-width: 1600px;
      margin: 0 auto;
      width: 100%;
    }

    .page-header {
      margin-bottom: 30px;
    }

    .page-title {
      font-size: 28px;
      font-weight: 700;
      color: white;
      margin-bottom: 8px;
    }

    .page-subtitle {
      color: #64748b;
      font-size: 14px;
    }

    /* Summary Cards */
    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 15px;
      margin-bottom: 30px;
    }

    .summary-card {
      background: #112240;
      border: 1px solid #1d3557;
      border-radius: 8px;
      padding: 20px;
      cursor: pointer;
      transition: all 0.3s;
    }

    .summary-card:hover {
      border-color: #2563eb;
      background: #1a2f4a;
      transform: translateY(-2px);
    }

    .summary-label {
      font-size: 11px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 8px;
    }

    .summary-value {
      font-size: 28px;
      font-weight: 700;
      color: #60a5fa;
    }

    .summary-desc {
      font-size: 12px;
      color: #94a3b8;
      margin-top: 8px;
    }

    /* Apps Table */
    .apps-section {
      background: #112240;
      border: 1px solid #1d3557;
      border-radius: 8px;
      overflow: hidden;
    }

    .apps-header {
      background: linear-gradient(135deg, #1d3557 0%, #234567 100%);
      padding: 20px;
      border-bottom: 1px solid #1d3557;
    }

    .apps-header-title {
      font-size: 16px;
      font-weight: 600;
      color: white;
    }

    .apps-list {
      max-height: 800px;
      overflow-y: auto;
    }

    .app-item {
      border-bottom: 1px solid #1d3557;
      padding: 20px;
      transition: all 0.2s;
    }

    .app-item:hover {
      background: #1a2f4a;
    }

    .app-item:last-child {
      border-bottom: none;
    }

    .app-header {
      display: grid;
      grid-template-columns: 1fr 1fr 1.5fr auto;
      gap: 20px;
      margin-bottom: 15px;
      align-items: center;
    }

    .app-info {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .app-name {
      font-size: 14px;
      font-weight: 600;
      color: white;
    }

    .app-package {
      font-size: 12px;
      color: #64748b;
      font-family: monospace;
    }

    .app-status-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      width: fit-content;
    }

    .status-safe {
      background: rgba(16, 185, 129, 0.2);
      color: #10b981;
      border: 1px solid #10b981;
    }

    .status-suspicious {
      background: rgba(245, 158, 11, 0.2);
      color: #f59e0b;
      border: 1px solid #f59e0b;
    }

    .status-malicious {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
      border: 1px solid #ef4444;
    }

    .final-status {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .final-status-label {
      font-size: 11px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .final-status-field {
      background: #0a192f;
      border: 1px solid #1d3557;
      border-radius: 6px;
      padding: 8px 12px;
      font-size: 12px;
      color: #e2e8f0;
      text-align: center;
      font-weight: 500;
    }

    .app-actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }

    .btn {
      padding: 6px 12px;
      border: none;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      white-space: nowrap;
    }

    .btn-algorithm {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
    }

    .btn-algorithm:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
    }

    .btn-block {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
      border: 1px solid #ef4444;
    }

    .btn-block:hover {
      background: rgba(239, 68, 68, 0.3);
    }

    .btn-notify {
      background: rgba(59, 130, 246, 0.2);
      color: #3b82f6;
      border: 1px solid #3b82f6;
    }

    .btn-notify:hover {
      background: rgba(59, 130, 246, 0.3);
    }

    .btn-uninstall {
      background: rgba(139, 92, 246, 0.2);
      color: #8b5cf6;
      border: 1px solid #8b5cf6;
    }

    .btn-uninstall:hover {
      background: rgba(139, 92, 246, 0.3);
    }

    .results-summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 12px;
      margin-top: 15px;
      padding-top: 15px;
      border-top: 1px solid #1d3557;
    }

    .result-field {
      background: #0a192f;
      border: 1px solid #1d3557;
      border-radius: 6px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .result-field:hover {
      border-color: #2563eb;
      background: #1a2f4a;
      transform: translateY(-2px);
    }

    .result-label {
      font-size: 10px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .result-value {
      font-size: 16px;
      font-weight: 700;
      color: #60a5fa;
    }

    .no-apps {
      text-align: center;
      padding: 60px 20px;
      color: #64748b;
    }

    .no-apps-icon {
      font-size: 48px;
      margin-bottom: 15px;
      opacity: 0.5;
    }

    /* Detailed Results Modal */
    .modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.7);
      z-index: 2000;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }

    .modal.active {
      display: flex;
    }

    .modal-content {
      background: #112240;
      border: 1px solid #1d3557;
      border-radius: 10px;
      padding: 30px;
      max-width: 600px;
      width: 100%;
      max-height: 80vh;
      overflow-y: auto;
    }

    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 15px;
      border-bottom: 1px solid #1d3557;
    }

    .modal-title {
      font-size: 18px;
      font-weight: 600;
      color: white;
    }

    .modal-close {
      background: none;
      border: none;
      color: #94a3b8;
      font-size: 20px;
      cursor: pointer;
      transition: color 0.2s;
    }

    .modal-close:hover {
      color: white;
    }

    .detail-row {
      display: grid;
      grid-template-columns: 150px 1fr;
      gap: 20px;
      padding: 12px 0;
      border-bottom: 1px solid #1d3557;
    }

    .detail-row:last-child {
      border-bottom: none;
    }

    .detail-label {
      font-size: 12px;
      color: #64748b;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.5px;
    }

    .detail-value {
      font-size: 13px;
      color: #e2e8f0;
      word-break: break-all;
    }
  </style>
</head>
<body>
  <!-- Sidebar -->
  <div class="sidebar" id="sidebar">
    <div class="logo">
      <div class="logo-icon">🛡️</div>
      <span>CYBER WOLF</span>
    </div>
    <a href="/" class="nav-item">
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
    <a href="/results" class="nav-item active">
      <i class="fas fa-file-alt nav-icon"></i>
      <span>Results</span>
    </a>
    <a href="/logout" class="logout-nav">
      <i class="fas fa-sign-out-alt nav-icon"></i>
      <span>Logout</span>
    </a>
  </div>

  <div class="overlay" id="overlay"></div>

  <!-- Main Content -->
  <div class="main-content" id="mainContent">
    <div class="top-bar">
      <button class="menu-btn" id="menuBtn"><i class="fas fa-bars"></i></button>
      <div class="user-info">
        <span>Welcome to Results</span>
        <div class="user-avatar">📊</div>
      </div>
    </div>

    <div class="container">
      <div class="page-header">
        <h1 class="page-title">📊 Analysis Results</h1>
        <p class="page-subtitle">View all app analysis results and security assessments</p>
      </div>

      <!-- Summary Cards -->
      <div class="summary-cards">
        <div class="summary-card" onclick="showDetailedSummary('total')">
          <div class="summary-label">Total Apps</div>
          <div class="summary-value">${apps.length}</div>
          <div class="summary-desc">Analyzed applications</div>
        </div>
        <div class="summary-card" onclick="showDetailedSummary('safe')">
          <div class="summary-label">Safe</div>
          <div class="summary-value" style="color: #10b981;">${apps.filter(a => a.status === 'safe').length}</div>
          <div class="summary-desc">No threats detected</div>
        </div>
        <div class="summary-card" onclick="showDetailedSummary('suspicious')">
          <div class="summary-label">Suspicious</div>
          <div class="summary-value" style="color: #f59e0b;">${apps.filter(a => a.status === 'suspicious').length}</div>
          <div class="summary-desc">Requires review</div>
        </div>
        <div class="summary-card" onclick="showDetailedSummary('malicious')">
          <div class="summary-label">Malicious</div>
          <div class="summary-value" style="color: #ef4444;">${apps.filter(a => a.status === 'malicious').length}</div>
          <div class="summary-desc">High risk apps</div>
        </div>
      </div>

      <!-- Apps List -->
      <div class="apps-section">
        <div class="apps-header">
          <div class="apps-header-title">
            <i class="fas fa-list"></i> Detailed Analysis Results
          </div>
        </div>

        <div class="apps-list">
          ${apps.length > 0 ? apps.map(app => `
            <div class="app-item">
              <div class="app-header">
                <div class="app-info">
                  <div class="app-name">${app.appName || 'Unknown App'}</div>
                  <div class="app-package">${app.packageName || 'N/A'}</div>
                </div>
                
                <div>
                  <div class="app-status-badge status-${app.status || 'safe'}">
                    ${(app.status || 'unknown').toUpperCase()}
                  </div>
                </div>

                <div class="final-status">
                  <div class="final-status-label">Final Status</div>
                  <div class="final-status-field" id="final-${app.sha256}">
                    PENDING
                  </div>
                </div>


              </div>

              <!-- Results Summary -->
              <div class="results-summary">
                <div class="result-field" onclick="showAppDetails('${app.sha256}', 'ml')">
                  <div class="result-label">🤖 ML Model</div>
                  <div class="result-value" style="color: ${app.mlPredictionLabel === 'safe' ? '#10b981' : app.mlPredictionLabel === 'risky' ? '#f59e0b' : '#ef4444'};">
                    ${(app.mlPredictionLabel || 'N/A').toUpperCase()}
                  </div>
                  <div class="summary-desc">${(app.mlPredictionScore ?? 0).toFixed(3)} confidence</div>
                </div>

                <div class="result-field" onclick="showAppDetails('${app.sha256}', 'mobsf')">
                  <div class="result-label">🔍 MobSF Score</div>
                  <div class="result-value" style="color: ${app.mobsfAnalysis?.security_score >= 70 ? '#10b981' : app.mobsfAnalysis?.security_score >= 40 ? '#f59e0b' : '#ef4444'};">
                    ${app.mobsfAnalysis?.security_score || 'N/A'}/100
                  </div>
                  <div class="summary-desc">${app.mobsfAnalysis?.high_risk_findings || 0} high risk findings</div>
                </div>

                <div class="result-field" onclick="showAppDetails('${app.sha256}', 'vtmulti')">
                  <div class="result-label">⚙️ VT Multi</div>
                  <div class="result-value" style="color: ${app.virusTotalAnalysis?.status === 'malicious' ? '#ef4444' : app.virusTotalAnalysis?.status === 'suspicious' ? '#f59e0b' : '#10b981'};">
                    ${app.virusTotalAnalysis?.detectionRatio || 'N/A'}
                  </div>
                  <div class="summary-desc">${(app.virusTotalAnalysis?.status || 'unknown').toUpperCase()}</div>
                </div>
              </div>

              <!-- Admin Actions -->
              <div class="app-actions" style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #1d3557;">
                <button class="btn btn-block" onclick="blockApp('${app.sha256}', '${app.packageName}')">
                  🚫 Block
                </button>
                <button class="btn btn-notify" onclick="sendNotification('${app.sha256}', '${app.packageName}')">
                  📢 Notify
                </button>
                <button class="btn btn-uninstall" onclick="uninstallApp('${app.sha256}', '${app.packageName}')">
                  ❌ Uninstall
                </button>
              </div>


            </div>
          `).join('') : `
            <div class="no-apps">
              <div class="no-apps-icon">📱</div>
              <p>No apps analyzed yet. Upload apps from <a href="/uploadapp/apps" style="color: #2563eb; text-decoration: none;">App Manager</a></p>
            </div>
          `}
        </div>
      </div>
    </div>
  </div>

  <!-- Detailed Results Modal -->
  <div class="modal" id="detailsModal">
    <div class="modal-content">
      <div class="modal-header">
        <div class="modal-title" id="modalTitle">Details</div>
        <button class="modal-close" onclick="closeModal()">✕</button>
      </div>
      <div id="modalBody"></div>
    </div>
  </div>

  <script>
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('overlay');
    const mainContent = document.getElementById('mainContent');
    const menuBtn = document.getElementById('menuBtn');
    const detailsModal = document.getElementById('detailsModal');

    menuBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      overlay.classList.toggle('active');
    });

    overlay.addEventListener('click', () => {
      sidebar.classList.remove('open');
      overlay.classList.remove('active');
    });

    function showAppDetails(sha256, type) {
      // This will be expanded to show full details
      alert('Showing details for ' + type + ' - ' + sha256);
    }

    function showDetailedSummary(type) {
      const modal = document.getElementById('detailsModal');
      const title = document.getElementById('modalTitle');
      const body = document.getElementById('modalBody');

      const summaries = {
        total: {
          title: 'Total Applications',
          content: '<div class="detail-row"><div class="detail-label">Total Apps</div><div class="detail-value">${apps.length}</div></div>'
        },
        safe: {
          title: 'Safe Applications',
          content: '<div class="detail-row"><div class="detail-label">Safe Apps</div><div class="detail-value">${apps.filter(a => a.status === 'safe').length}</div></div>'
        },
        suspicious: {
          title: 'Suspicious Applications',
          content: '<div class="detail-row"><div class="detail-label">Suspicious Apps</div><div class="detail-value">${apps.filter(a => a.status === 'suspicious').length}</div></div>'
        },
        malicious: {
          title: 'Malicious Applications',
          content: '<div class="detail-row"><div class="detail-label">Malicious Apps</div><div class="detail-value">${apps.filter(a => a.status === 'malicious').length}</div></div>'
        }
      };

      title.textContent = summaries[type].title;
      body.innerHTML = summaries[type].content;
      modal.classList.add('active');
    }

    function closeModal() {
      document.getElementById('detailsModal').classList.remove('active');
    }



    function blockApp(sha256, packageName) {
      alert('Blocking app: ' + packageName);
    }

    function sendNotification(sha256, packageName) {
      alert('Sending notification for: ' + packageName);
    }

    function uninstallApp(sha256, packageName) {
      alert('Uninstalling app: ' + packageName);
    }
  </script>
</body>
</html>
    `;

    res.send(html);
  } catch (err) {
    console.error("Failed to load results:", err.message);
    res.status(500).send(`<html><body style="background:#0d1b2a;color:white;text-align:center;padding:50px"><h1>❌ Error</h1><p>${err.message}</p><a href="/" style="color:#90e0ef">← Back</a></body></html>`);
  }
});

module.exports = router;
