const express = require("express");
const router = express.Router();
const { calculateWeightedRiskScore } = require("../utils/riskAlgorithm");
const { checkVirusTotal } = require("../utils/virusTotal");

const requireWebAuth = (req, res, next) => {
  if (req.session && req.session.authenticated) {
    return next();
  }
  return res.redirect("/login");
};

function getIndexNameForDate(dateString) {
  const date = new Date(dateString);
  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = date.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
}

function buildAppItemHTML(app) {
  const vtStatus = app.virusTotalAnalysis?.status || "unknown";
  const vtRatio = app.virusTotalAnalysis?.detectionRatio || "N/A";
  const mobsfScore = app.mobsfAnalysis?.security_score || "N/A";
  const mobsfRisks = app.mobsfAnalysis?.high_risk_findings || 0;
  const mlLabel = (app.mlPredictionLabel || "N/A").toUpperCase();
  const mlScore = (app.mlPredictionScore ?? 0).toFixed(3);
  const appStatus = (app.status || "unknown").toUpperCase();
  const appName = app.appName || "Unknown App";
  const packageName = app.packageName || "N/A";
  const sha256 = app.sha256 || "";
  
  const vtColor = vtStatus === "malicious" ? "#ef4444" : vtStatus === "suspicious" ? "#f59e0b" : "#10b981";
  const mobsfColor = (app.mobsfAnalysis?.security_score || 0) >= 70 ? "#10b981" : (app.mobsfAnalysis?.security_score || 0) >= 40 ? "#f59e0b" : "#ef4444";
  const mlColor = app.mlPredictionLabel === "safe" ? "#10b981" : app.mlPredictionLabel === "risky" ? "#f59e0b" : "#ef4444";
  const statusColor = app.status === "malicious" ? "#ef4444" : app.status === "suspicious" ? "#f59e0b" : app.status === "safe" ? "#10b981" : "#94a3b8";

  return `
    <div class="app-item">
      <div class="app-header">
        <div class="app-info">
          <div class="app-name">${appName}</div>
          <div class="app-package">${packageName}</div>
          <div class="app-status-badge status-${app.status || "safe"}">
            ${appStatus}
          </div>
        </div>
        <div class="final-status-section">
          <div class="final-status-label">FINAL STATUS</div>
          <div class="final-status-value" style="color: ${statusColor};">
            ${appStatus}
          </div>
        </div>
      </div>

      <div class="analysis-grid">
        <div class="analysis-box vt">
          <div class="analysis-label">Multi-Engine Detection</div>
          <div class="analysis-value" style="color: ${vtColor};">
            ${vtRatio}
          </div>
          <div class="analysis-detail">${vtStatus.toUpperCase()}</div>
        </div>

        <div class="analysis-box static">
          <div class="analysis-label">STATIC ANALYSIS</div>
          <div class="analysis-value" style="color: ${mobsfColor};">
            ${mobsfScore}/100
          </div>
          <div class="analysis-detail">${mobsfRisks} high risks</div>
        </div>

        <div class="analysis-box dynamic">
          <div class="analysis-label">DYNAMIC ANALYSIS</div>
          <div class="analysis-value" style="color: #94a3b8;">N/A</div>
          <div class="analysis-detail">Not Available</div>
        </div>

        <div class="analysis-box ml">
          <div class="analysis-label">ML PREDICTION</div>
          <div class="analysis-value" style="color: ${mlColor};">
            ${mlLabel}
          </div>
          <div class="analysis-detail">${mlScore} conf</div>
        </div>

        <div class="analysis-box soc">
          <div class="analysis-label">SOC REMARKS</div>
          <select class="soc-select" id="soc-${sha256}" onchange="updateSOCStatus('${sha256}', this.value)">
            <option value="pending" ${(app.status || "pending") === "pending" ? "selected" : ""}>PENDING</option>
            <option value="safe" ${app.status === "safe" ? "selected" : ""}>SAFE</option>
            <option value="suspicious" ${app.status === "suspicious" ? "selected" : ""}>SUSPICIOUS</option>
            <option value="malicious" ${app.status === "malicious" ? "selected" : ""}>MALICIOUS</option>
          </select>
        </div>
      </div>

      <div class="action-buttons">
        <button class="btn btn-notify" onclick="sendNotification('${sha256}', '${packageName}')">Notify</button>
        <button class="btn btn-block" onclick="blockApp('${sha256}')">Block</button>
        <button class="btn btn-uninstall" onclick="uninstallApp('${sha256}')">Uninstall</button>
      </div>

      <button class="btn btn-algo" onclick="runAlgorithm('${sha256}')">RUN WEIGHTED RISK ALGORITHM</button>

      <div class="algo-results" id="algo-${sha256}">
        <div id="algo-loading-${sha256}">
          <i class="fas fa-spinner fa-spin"></i> Running algorithm...
        </div>
        <div id="algo-content-${sha256}" style="display: none;">
          <div class="algo-metrics">
            <div class="metric">
              <div class="metric-label">Final Score</div>
              <div class="metric-value" id="score-${sha256}" style="color: #667eea;">--</div>
            </div>
            <div class="metric">
              <div class="metric-label">Status</div>
              <div class="metric-value" id="status-${sha256}">--</div>
            </div>
            <div class="metric">
              <div class="metric-label">Confidence</div>
              <div class="metric-value" id="conf-${sha256}" style="color: #10b981;">--</div>
            </div>
            <div class="metric">
              <div class="metric-label">Data Sources</div>
              <div class="metric-value" id="sources-${sha256}" style="color: #3b82f6;">--</div>
            </div>
          </div>
          <button class="toggle-details" onclick="toggleDetails('${sha256}')"><span id="toggle-text-${sha256}">SHOW DETAILS</span></button>
          <div class="details-section" id="details-${sha256}">
            <div style="margin-bottom: 20px;">
              <h3 style="color: white; margin-bottom: 10px; font-size: 14px;">Score Breakdown:</h3>
              <table class="breakdown-table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th style="text-align: right;">Score</th>
                  </tr>
                </thead>
                <tbody id="breakdown-${sha256}"></tbody>
              </table>
            </div>
            <div>
              <h3 style="color: white; margin-bottom: 10px; font-size: 14px;">Weights Used:</h3>
              <table class="breakdown-table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th style="text-align: right;">Weight %</th>
                  </tr>
                </thead>
                <tbody id="weights-${sha256}"></tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

router.get("/", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const selectedDate = req.query.date || new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(selectedDate);

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

      for (let i = 0; i < apps.length; i++) {
        if (!apps[i].virusTotalHashCheck && apps[i].sha256) {
          try {
            const vtResult = await checkVirusTotal(apps[i].sha256);
            if (vtResult) {
              apps[i].virusTotalAnalysis = {
                detectionRatio: vtResult.detectionRatio,
                totalEngines: vtResult.totalEngines,
                detectedEngines: vtResult.detectedEngines,
                status: vtResult.status,
              };
              await esClient.update({
                index: indexName,
                id: result.hits.hits[i]._id,
                body: { doc: { virusTotalAnalysis: apps[i].virusTotalAnalysis } },
              });
            }
          } catch (vtErr) {
            console.log("VT check failed:", vtErr.message);
          }
        }
      }
    } catch (e) {
      console.log(`Index not found: ${indexName}`);
    }

    const appItemsHTML = apps.length > 0 ? apps.map(buildAppItemHTML).join("") : "<div class=\"no-apps\"><p>No apps analyzed. Upload from App Manager.</p></div>";

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Analysis Results - Android Malware Detector</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a192f; color: #94a3b8; min-height: 100vh; }
    .sidebar { width: 250px; background: #112240; height: 100vh; position: fixed; right: -250px; top: 0; padding: 20px 0; overflow-y: auto; z-index: 1000; box-shadow: -2px 0 10px rgba(0,0,0,0.3); transition: right 0.3s ease; }
    .sidebar.open { right: 0; }
    .overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 999; }
    .overlay.open { display: block; }
    .top-bar { background: #112240; padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; gap: 10px; border-bottom: 1px solid #1d3557; position: sticky; top: 0; z-index: 100; }
    .menu-btn { background: none; border: none; color: #94a3b8; font-size: 18px; cursor: pointer; padding: 6px 12px; transition: color 0.2s; }
    .menu-btn:hover { color: white; }
    .logo { padding: 0 20px 25px; display: flex; align-items: center; gap: 12px; color: white; font-weight: 600; font-size: 16px; border-bottom: 1px solid #1d3557; margin-bottom: 20px; }
    .logo-icon { width: 32px; height: 32px; background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: white; font-weight: 600; }
    .nav-item { padding: 12px 20px; color: #94a3b8; text-decoration: none; display: flex; align-items: center; gap: 12px; font-size: 14px; cursor: pointer; transition: all 0.2s; }
    .nav-item:hover { background: #1d3557; color: white; }
    .nav-item.active { background: #000000; color: white; border-left: 3px solid #2563eb; }
    .logout-nav { margin-top: auto; padding: 12px 20px; color: #ef4444; border-top: 1px solid #1d3557; text-decoration: none; display: flex; align-items: center; gap: 12px; font-size: 14px; }
    .logout-nav:hover { background: #7f1d1d; }
    .main-content { margin-right: 0; padding: 0; }
    .container { max-width: 1600px; margin: 0 auto; }
    .page-header { margin-bottom: 30px; }
    .page-title { font-size: 28px; font-weight: 700; color: white; margin-bottom: 8px; }
    .page-subtitle { color: #64748b; font-size: 14px; }
    .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
    .summary-card { background: #112240; border: 1px solid #1d3557; border-radius: 8px; padding: 20px; cursor: pointer; transition: all 0.3s; }
    .summary-card:hover { border-color: #2563eb; background: #1a2f4a; transform: translateY(-2px); }
    .summary-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
    .summary-value { font-size: 28px; font-weight: 700; color: #60a5fa; }
    .summary-desc { font-size: 12px; color: #94a3b8; margin-top: 8px; }
    .apps-section { background: #112240; border: 1px solid #1d3557; border-radius: 8px; overflow: hidden; }
    .apps-header { background: #3a3a3a; padding: 20px; border-bottom: 1px solid #1d3557; font-size: 16px; font-weight: 600; color: white; }
    .app-item { border-bottom: 1px solid #1d3557; padding: 25px; transition: all 0.2s; }
    .app-item:hover { background: #1a2f4a; }
    .app-item:last-child { border-bottom: none; }
    .app-header { display: grid; grid-template-columns: 1fr auto; gap: 40px; margin-bottom: 20px; align-items: center; }
    .app-info { display: flex; flex-direction: column; gap: 4px; }
    .app-name { font-size: 14px; font-weight: 600; color: white; }
    .app-package { font-size: 12px; color: #64748b; font-family: monospace; }
    .app-status-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 600; text-transform: uppercase; width: fit-content; margin-top: 8px; }
    .status-safe { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }
    .status-suspicious { background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #f59e0b; }
    .status-malicious { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .final-status-section { display: flex; flex-direction: column; gap: 4px; }
    .final-status-label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
    .final-status-value { background: #0a192f; border: 1px solid #1d3557; border-radius: 6px; padding: 8px 16px; font-size: 14px; font-weight: 600; text-align: center; }
    .analysis-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-top: 20px; }
    .analysis-box { background: #0a192f; padding: 15px; border-radius: 6px; border-left: 3px solid; display: flex; flex-direction: column; gap: 6px; }
    .analysis-box.vt { border-left-color: #3b82f6; }
    .analysis-box.static { border-left-color: #f59e0b; }
    .analysis-box.dynamic { border-left-color: #667eea; }
    .analysis-box.ml { border-left-color: #10b981; }
    .analysis-box.soc { border-left-color: #a855f7; }
    .analysis-label { font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
    .analysis-value { font-size: 14px; font-weight: 600; }
    .analysis-detail { font-size: 9px; color: #94a3b8; }
    .soc-select { background: #112240; border: 1px solid #1d3557; color: #e2e8f0; padding: 6px 10px; border-radius: 4px; font-size: 12px; cursor: pointer; }
    .action-buttons { display: flex; gap: 8px; margin-top: 15px; flex-wrap: wrap; }
    .btn { padding: 8px 12px; border: none; border-radius: 6px; font-size: 11px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
    .btn-algo { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; font-size: 13px; width: 100%; margin-top: 15px; }
    .btn-algo:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3); }
    .btn-notify { background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid #3b82f6; }
    .btn-notify:hover { background: rgba(59, 130, 246, 0.3); }
    .btn-block { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .btn-block:hover { background: rgba(239, 68, 68, 0.3); }
    .btn-uninstall { background: rgba(139, 92, 246, 0.2); color: #8b5cf6; border: 1px solid #8b5cf6; }
    .btn-uninstall:hover { background: rgba(139, 92, 246, 0.3); }
    .algo-results { display: none; margin-top: 20px; padding: 20px; background: #1a1a1a; border: 2px solid #667eea; border-radius: 8px; }
    .algo-results.active { display: block; }
    .algo-metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 15px; }
    .metric { background: #0a192f; padding: 12px; border-radius: 6px; border-left: 3px solid #667eea; display: flex; flex-direction: column; gap: 4px; }
    .metric-label { font-size: 11px; color: #64748b; text-transform: uppercase; }
    .metric-value { font-size: 24px; font-weight: bold; }
    .breakdown-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }
    .toggle-details { background: #667eea; color: white; padding: 10px 16px; border: none; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; margin-top: 15px; width: 100%; transition: all 0.2s; }
    .toggle-details:hover { background: #764ba2; }
    .details-section { display: none; margin-top: 15px; background: #0a192f; border: 1px solid #1d3557; border-radius: 6px; padding: 15px; max-height: 600px; overflow-y: auto; }
    .details-section.show { display: block; }
    .breakdown-table tr { border-bottom: 1px solid #1d3557; }
    .breakdown-table td { padding: 10px 8px; color: #94a3b8; }
    .breakdown-table th { text-align: left; font-weight: 600; color: #64748b; text-transform: uppercase; font-size: 10px; padding: 10px 8px; border-bottom: 2px solid #1d3557; }
    .no-apps { text-align: center; padding: 80px 20px; color: #64748b; }
  </style>
</head>
<body>
  <div class="overlay" id="overlay"></div>
  <div class="sidebar" id="sidebar">
    <div class="logo">
      <div class="logo-icon">🔒</div>
      <span>CYBER WOLF</span>
    </div>
    <a href="/" class="nav-item">
      <i class="fas fa-home"></i>
      <span>Home</span>
    </a>
    <a href="/dashboard" class="nav-item">
      <i class="fas fa-chart-line"></i>
      <span>Dashboard</span>
    </a>
    <a href="/uploadapp/apps" class="nav-item">
      <i class="fas fa-mobile-alt"></i>
      <span>App Manager</span>
    </a>
    <a href="/results" class="nav-item active">
      <i class="fas fa-file-alt"></i>
      <span>Results</span>
    </a>
    <a href="/logout" class="logout-nav">
      <i class="fas fa-sign-out-alt"></i>
      <span>Logout</span>
    </a>
  </div>

  <div class="main-content">
    <div class="top-bar">
      <button class="menu-btn" id="menuBtn" onclick="toggleSidebar()" style="font-size: 20px;">☰</button>
    </div>
    <div class="container" style="padding: 20px;">
      <div class="page-header">
        <h1 class="page-title">ANALYSIS RESULTS</h1>
        <p class="page-subtitle">View all app analysis results and security assessments</p>
      </div>

      <div class="summary-cards">
        <div class="summary-card">
          <div class="summary-label">Total Apps</div>
          <div class="summary-value">${apps.length}</div>
          <div class="summary-desc">Analyzed applications</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Safe</div>
          <div class="summary-value" style="color: #10b981;">${apps.filter(a => a.status === "safe").length}</div>
          <div class="summary-desc">No threats detected</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Suspicious</div>
          <div class="summary-value" style="color: #f59e0b;">${apps.filter(a => a.status === "suspicious").length}</div>
          <div class="summary-desc">Requires review</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Malicious</div>
          <div class="summary-value" style="color: #ef4444;">${apps.filter(a => a.status === "malicious").length}</div>
          <div class="summary-desc">High risk apps</div>
        </div>
      </div>

      <div class="apps-section">
        <div class="apps-header">
          <i class="fas fa-list"></i> Detailed Analysis Results
        </div>
        ${appItemsHTML}
      </div>
    </div>
  </div>

  <script>
    function toggleSidebar() {
      const sidebar = document.getElementById('sidebar');
      const overlay = document.getElementById('overlay');
      sidebar.classList.toggle('open');
      overlay.classList.toggle('open');
    }
    
    document.getElementById('overlay').addEventListener('click', toggleSidebar);
    
    function toggleDetails(sha256) {
      const detailsDiv = document.getElementById("details-" + sha256);
      const toggleText = document.getElementById("toggle-text-" + sha256);
      
      if (detailsDiv.classList.contains("show")) {
        detailsDiv.classList.remove("show");
        toggleText.textContent = "SHOW DETAILS";
      } else {
        detailsDiv.classList.add("show");
        toggleText.textContent = "HIDE DETAILS";
      }
    }
    
    async function runAlgorithm(sha256) {
      const algoDiv = document.getElementById("algo-" + sha256);
      const loadingDiv = document.getElementById("algo-loading-" + sha256);
      const contentDiv = document.getElementById("algo-content-" + sha256);
      
      algoDiv.classList.add("active");
      loadingDiv.style.display = "block";
      contentDiv.style.display = "none";
      
      try {
        const res = await fetch("/results/run-algorithm/" + sha256, { method: "POST" });
        const data = await res.json();
        
        if (data.success) {
          const score = Math.round(data.finalScore);
          const scoreEl = document.getElementById("score-" + sha256);
          scoreEl.textContent = score;
          scoreEl.style.color = score >= 60 ? "#ef4444" : score >= 35 ? "#f59e0b" : "#10b981";
          
          document.getElementById("status-" + sha256).textContent = data.finalStatus;
          document.getElementById("status-" + sha256).style.color = 
            data.finalStatus === "MALICIOUS" ? "#ef4444" : 
            data.finalStatus === "SUSPICIOUS" ? "#f59e0b" : "#10b981";
          
          document.getElementById("conf-" + sha256).textContent = Math.round(data.confidence) + "%";
          document.getElementById("sources-" + sha256).textContent = Object.values(data.breakdown?.sources || {}).filter(v => v).length + "/4";
          
          let html = "";
          if (data.breakdown?.sources) {
            Object.entries(data.breakdown.sources).forEach(([k, v]) => {
              if (v !== null && v !== "N/A") {
                html += "<tr><td>" + k + "</td><td style='text-align: right; color: #10b981;'>" + (typeof v === "number" ? v.toFixed(2) : v) + "</td></tr>";
              }
            });
          }
          document.getElementById("breakdown-" + sha256).innerHTML = html;
          
          let weightsHtml = "";
          if (data.weights) {
            Object.entries(data.weights).forEach(([k, v]) => {
              if (v !== null && v !== undefined) {
                const percentage = typeof v === "number" ? (v * 100).toFixed(1) : 0;
                weightsHtml += "<tr><td>" + k + "</td><td style='text-align: right; color: #667eea;'>" + percentage + "%</td></tr>";
              }
            });
          }
          document.getElementById("weights-" + sha256).innerHTML = weightsHtml;
          
          loadingDiv.style.display = "none";
          contentDiv.style.display = "block";
        }
      } catch (e) {
        alert("Error: " + e.message);
        algoDiv.classList.remove("active");
      }
    }
    
    function updateSOCStatus(sha256, status) {
      fetch("/results/update-soc-status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sha256, status })
      })
        .then(r => r.json())
        .then(d => {
          if (d.success) {
            alert("Status updated!");
            setTimeout(() => location.reload(), 300);
          } else {
            alert("Error: " + d.message);
          }
        })
        .catch(e => alert("Error: " + e.message));
    }
    
    function sendNotification(sha256, pkg) {
      fetch("/results/send-notification", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sha256, packageName: pkg })
      })
        .then(r => r.json())
        .then(d => alert(d.success ? "Notification sent!" : "Error: " + d.message))
        .catch(e => alert("Error: " + e.message));
    }
    
    function blockApp(sha256) {
      alert("Blocking: " + sha256);
    }
    
    function uninstallApp(sha256) {
      alert("Uninstalling: " + sha256);
    }
  </script>
</body>
</html>`;

    res.send(html);
  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).send("Error: " + err.message);
  }
});

router.post("/run-algorithm/:sha256", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { sha256 } = req.params;

  try {
    let appData = null;
    const today = new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(today);

    try {
      const result = await esClient.search({
        index: indexName,
        query: { term: { sha256 } },
      });
      if (result.hits.hits.length > 0) {
        appData = result.hits.hits[0]._source;
        appData.id = result.hits.hits[0]._id;
      }
    } catch (e) {
      const allResult = await esClient.search({
        index: "mobile_apps_*",
        query: { term: { sha256 } },
        size: 1,
        sort: [{ timestamp: { order: "desc" } }],
      });
      if (allResult.hits.hits.length > 0) {
        appData = allResult.hits.hits[0]._source;
        appData.id = allResult.hits.hits[0]._id;
      }
    }

    if (!appData) {
      return res.json({ success: false, message: "App not found" });
    }

    const algorithmResult = calculateWeightedRiskScore(appData);

    return res.json({
      success: true,
      finalScore: algorithmResult.finalScore,
      finalStatus: algorithmResult.finalStatus,
      confidence: algorithmResult.confidence,
      breakdown: algorithmResult.breakdown,
      weights: algorithmResult.breakdown.weights,
    });
  } catch (err) {
    console.error("Error:", err.message);
    return res.json({ success: false, message: err.message });
  }
});

router.post("/update-soc-status", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { sha256, status } = req.body;

  try {
    const allowedStatuses = ["safe", "malicious", "suspicious", "pending"];
    if (!allowedStatuses.includes(status)) {
      return res.json({ success: false, message: "Invalid status" });
    }
    
    // Only SOC analyst can update non-pending statuses
    if (status === "pending") {
      return res.json({ success: false, message: "Cannot set status to pending from SOC analyst" });
    }

    let appData = null;
    let foundIndex = null;
    const today = new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(today);

    try {
      const result = await esClient.search({
        index: indexName,
        query: { term: { sha256 } },
      });
      if (result.hits.hits.length > 0) {
        appData = result.hits.hits[0]._source;
        appData.id = result.hits.hits[0]._id;
        foundIndex = indexName;
      }
    } catch (e) {
      const allResult = await esClient.search({
        index: "mobile_apps_*",
        query: { term: { sha256 } },
        size: 1,
        sort: [{ timestamp: { order: "desc" } }],
      });
      if (allResult.hits.hits.length > 0) {
        appData = allResult.hits.hits[0]._source;
        appData.id = allResult.hits.hits[0]._id;
        foundIndex = allResult.hits.hits[0]._index;
      }
    }

    if (!appData) {
      return res.json({ success: false, message: "App not found" });
    }

    const indexNameForDate = foundIndex || getIndexNameForDate(appData.timestamp || new Date().toISOString());
    
    await esClient.update({
      index: indexNameForDate,
      id: appData.id || sha256,
      body: {
        doc: {
          status: status,
          statusSource: "SOC Analyst",
          socUpdatedAt: new Date().toISOString(),
          lastModified: new Date().toISOString(),
        },
      },
      retry_on_conflict: 3,
    });

    return res.json({ success: true, message: "Status updated successfully by SOC Analyst" });
  } catch (err) {
    console.error("Error:", err.message);
    return res.json({ success: false, message: err.message });
  }
});

router.post("/send-notification", async (req, res) => {
  try {
    const { sha256, packageName } = req.body;
    const esClient = req.app.get("esClient");

    await esClient.index({
      index: `notifications_${new Date().toISOString().split("T")[0]}`,
      body: {
        sha256,
        packageName,
        timestamp: new Date().toISOString(),
      },
    });

    return res.json({ success: true, message: "Notification sent" });
  } catch (err) {
    console.error("Error:", err.message);
    return res.json({ success: false, message: err.message });
  }
});

module.exports = router;