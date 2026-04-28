const express = require("express");
const router = express.Router();
const { calculateWeightedRiskScore } = require("../utils/riskAlgorithm");
const { checkVirusTotal } = require("../utils/virusTotal");

const requireWebAuth = (req, res, next) => {
  if (req.session && req.session.authenticated) return next();
  return res.redirect("/login");
};

function getIndexNameForDate(dateString) {
  const date = new Date(dateString);
  const day   = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year  = date.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
}

// ── small HTML escape helper ──────────────────────────────────────────────────
const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

function buildAppCardHTML(app, index) {
  const sha256      = app.sha256 || '';
  const appName     = esc(app.appName || 'Unknown App');
  const pkgName     = esc(app.packageName || 'N/A');
  const uploadedAt  = app.timestamp ? new Date(app.timestamp).toLocaleString() : 'N/A';
  const appStatus   = (app.status || 'unknown').toLowerCase();
  const fileSize    = app.sizeMB ? `${Number(app.sizeMB).toFixed(2)} MB` : 'N/A';

  // Status colors
  const sColor = appStatus === 'malicious' ? '#ef4444' : appStatus === 'suspicious' ? '#f59e0b' : appStatus === 'safe' ? '#22c55e' : '#94a3b8';
  const sBg    = appStatus === 'malicious' ? '#450a0a' : appStatus === 'suspicious' ? '#451a03' : appStatus === 'safe' ? '#052e16' : '#1e293b';
  const sBorder= appStatus === 'malicious' ? '#7f1d1d' : appStatus === 'suspicious' ? '#92400e' : appStatus === 'safe' ? '#166534' : '#334155';

  // VT
  const vt        = app.virusTotalAnalysis || {};
  const vtStatus  = (vt.status || 'unknown').toLowerCase();
  const vtRatio   = vt.detectionRatio || 'N/A';
  const vtColor   = vtStatus === 'malicious' ? '#ef4444' : vtStatus === 'suspicious' ? '#f59e0b' : vtStatus === 'safe' ? '#22c55e' : '#94a3b8';

  // Static
  const ms        = app.mobsfAnalysis || {};
  const secScore  = ms.security_score ?? null;
  const highRisk  = ms.high_risk_findings || 0;
  const danPerms  = Array.isArray(ms.dangerous_permissions) ? ms.dangerous_permissions.length : 0;
  const stColor   = secScore === null ? '#94a3b8' : secScore >= 70 ? '#22c55e' : secScore >= 40 ? '#f59e0b' : '#ef4444';

  // Dynamic
  const da         = app.dynamicAnalysis || {};
  const daCompleted= da.status === 'completed';
  const daTrackers = da.trackers || 0;
  const daNetIssues= da.network_security_issues || 0;
  const daRisky    = daTrackers > 0 || daNetIssues > 0;
  const daColor    = !daCompleted ? '#64748b' : daRisky ? '#f59e0b' : '#22c55e';
  const daLabel    = !daCompleted ? 'Not Run' : daRisky ? 'RISKY' : 'CLEAN';

  // ML
  const mlProb  = app.mlPredictionScore ?? null;
  const mlLabel = (app.mlPredictionLabel || 'N/A').toUpperCase();
  const mlColor = mlLabel === 'SAFE' ? '#22c55e' : mlLabel === 'RISKY' || mlLabel === 'MALICIOUS' ? '#ef4444' : '#f59e0b';

  return `
<div class="app-card" id="card-${sha256}" data-status="${appStatus}">
  <!-- Card Header -->
  <div class="card-header">
    <div class="card-num">#${index}</div>
    <div class="card-identity">
      <div class="card-name">${appName}</div>
      <div class="card-pkg">${pkgName}</div>
      <div class="card-meta">${fileSize} &nbsp;&middot;&nbsp; Uploaded: ${uploadedAt}</div>
    </div>
    <div class="card-verdict" style="background:${sBg};border-color:${sBorder}">
      <div class="verdict-dot" style="background:${sColor}"></div>
      <div class="verdict-text" style="color:${sColor}">${appStatus.toUpperCase()}</div>
      <div class="verdict-sub">Current Status</div>
    </div>
  </div>

  <!-- 4-Source Grid -->
  <div class="sources-grid">
    <div class="source-box">
      <div class="src-label">VirusTotal</div>
      <div class="src-val" style="color:${vtColor}">${vtRatio}</div>
      <div class="src-sub">${vtStatus.toUpperCase()}</div>
    </div>
    <div class="source-box">
      <div class="src-label">Static Analysis</div>
      <div class="src-val" style="color:${stColor}">${secScore !== null ? secScore + '/100' : 'N/A'}</div>
      <div class="src-sub">${highRisk} high-risk &middot; ${danPerms} permission${danPerms !== 1 ? 's' : ''}</div>
    </div>
    <div class="source-box">
      <div class="src-label">Dynamic Analysis</div>
      <div class="src-val" style="color:${daColor}">${daLabel}</div>
      <div class="src-sub">${daCompleted ? `${daTrackers} trackers &middot; ${daNetIssues} net issues` : 'Not yet executed'}</div>
    </div>
    <div class="source-box">
      <div class="src-label">ML Prediction</div>
      <div class="src-val" style="color:${mlColor}">${mlLabel}</div>
      <div class="src-sub">${mlProb !== null ? `Probability: ${(mlProb*100).toFixed(1)}%` : 'N/A'}</div>
    </div>
  </div>

  <!-- SOC Section -->
  <div class="soc-row">
    <div class="soc-left">
      <span class="soc-label">SOC Analyst Verdict:</span>
      <select class="soc-select" id="soc-${sha256}" onchange="updateSOCStatus('${sha256}', this.value)">
        <option value="pending"    ${appStatus === 'pending'    ? 'selected' : ''}>PENDING REVIEW</option>
        <option value="safe"       ${appStatus === 'safe'       ? 'selected' : ''}>SAFE</option>
        <option value="suspicious" ${appStatus === 'suspicious' ? 'selected' : ''}>SUSPICIOUS</option>
        <option value="malicious"  ${appStatus === 'malicious'  ? 'selected' : ''}>MALICIOUS</option>
      </select>
      <span class="soc-hint" id="soc-hint-${sha256}"></span>
    </div>
    <div class="card-actions">
      <button class="btn-action btn-notify" id="notify-btn-${sha256}" onclick="sendNotification('${sha256}')">Send Notification</button>
    </div>
  </div>

  <!-- Algorithm Section -->
  <div class="algo-section">
    <button class="btn-algo" onclick="runAlgorithm('${sha256}')">
      RUN WEIGHTED RISK ALGORITHM
    </button>
    <div class="algo-result" id="algo-${sha256}" style="display:none">
      <div class="algo-loading" id="algo-loading-${sha256}">
        <div class="spinner"></div> <span>Calculating risk score…</span>
      </div>
      <div id="algo-content-${sha256}" style="display:none">
        <!-- Score Banner -->
        <div class="algo-banner" id="algo-banner-${sha256}">
          <div class="algo-score-wrap">
            <div class="algo-score-label">RISK SCORE</div>
            <div class="algo-score-value" id="algo-score-${sha256}">—</div>
            <div class="algo-score-max">/100</div>
          </div>
          <div class="algo-status-wrap">
            <div class="algo-status-label">ALGORITHM STATUS</div>
            <div class="algo-status-value" id="algo-status-${sha256}">—</div>
          </div>
          <div class="algo-conf-wrap">
            <div class="algo-conf-label">CONFIDENCE</div>
            <div class="algo-conf-bar-bg"><div class="algo-conf-bar-fill" id="algo-conf-bar-${sha256}"></div></div>
            <div class="algo-conf-pct" id="algo-conf-${sha256}">—</div>
          </div>
          <div class="algo-src-wrap">
            <div class="algo-src-label">DATA SOURCES</div>
            <div class="algo-src-value" id="algo-sources-${sha256}">—</div>
          </div>
        </div>

        <!-- Explanation -->
        <div class="algo-explanation" id="algo-explanation-${sha256}"></div>

        <!-- Risk / Positive Factors -->
        <div class="algo-factors" id="algo-factors-${sha256}"></div>

        <!-- Toggle Details -->
        <button class="btn-toggle-details" onclick="toggleAlgoDetails('${sha256}')">
          <span id="algo-toggle-text-${sha256}">▼ Show Score Breakdown</span>
        </button>
        <div class="algo-details" id="algo-details-${sha256}" style="display:none">
          <div class="breakdown-grid" id="algo-breakdown-${sha256}"></div>
        </div>
      </div>
    </div>
  </div>
</div>`;
}

// ─────────────────────────────────────────────────────────────────────────────
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
      apps = result.hits.hits.map((hit) => ({ ...hit._source, id: hit._id }));

      // Quick VT hash check for any app missing analysis
      for (let i = 0; i < apps.length; i++) {
        if (!apps[i].virusTotalHashCheck && apps[i].sha256) {
          try {
            const vtResult = await checkVirusTotal(apps[i].sha256);
            if (vtResult) {
              apps[i].virusTotalAnalysis = {
                detectionRatio: vtResult.detectionRatio,
                totalEngines:   vtResult.totalEngines,
                detectedEngines:vtResult.detectedEngines,
                status:         vtResult.status,
              };
              await esClient.update({
                index: indexName, id: result.hits.hits[i]._id,
                body: { doc: { virusTotalAnalysis: apps[i].virusTotalAnalysis } },
              });
            }
          } catch (_) { /* skip */ }
        }
      }
    } catch (_) { /* index may not exist yet */ }

    const totalApps    = apps.length;
    const safeCount    = apps.filter(a => a.status === 'safe').length;
    const suspCount    = apps.filter(a => a.status === 'suspicious').length;
    const malCount     = apps.filter(a => a.status === 'malicious').length;
    const pendingCount = apps.filter(a => !a.status || a.status === 'pending' || a.status === 'unknown').length;

    const appCardsHTML = apps.length > 0
      ? apps.map((app, i) => buildAppCardHTML(app, i + 1)).join('')
      : `<div class="empty-state">
          <div style="font-size:48px;margin-bottom:12px">📭</div>
          <div style="font-size:16px;color:#e2e8f0;margin-bottom:8px">No apps analyzed yet</div>
          <div style="font-size:13px;color:#475569">Upload apps from App Manager, then run analysis.</div>
         </div>`;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Analysis Results — Android Malware Detector</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"/>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#05090f;color:#cbd5e1;min-height:100vh}
    a{color:#3b82f6;text-decoration:none}a:hover{text-decoration:underline}

    /* ── Sidebar ── */
    .sidebar{width:240px;background:#0b1120;height:100vh;position:fixed;left:-240px;top:0;padding:0;display:flex;flex-direction:column;overflow-y:auto;z-index:1000;transition:left .3s cubic-bezier(0.4, 0, 0.2, 1);box-shadow:4px 0 24px rgba(0, 0, 0, 0.6);border-right:1px solid #1a2332}
    .sidebar.open{left:0}
    .overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:999;backdrop-filter:blur(2px)}
    .overlay.open{display:block}
    .logo{padding:22px 20px;display:flex;align-items:center;gap:12px;color:white;font-weight:700;font-size:16px;border-bottom:1px solid #1a2332;letter-spacing:0.5px}
    .logo-icon{width:38px;height:38px;background:linear-gradient(135deg,#3b82f6,#2563eb);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;color:white;box-shadow:0 4px 14px rgba(59, 130, 246, 0.4)}
    .nav-section-title{padding:20px 20px 8px;color:#475569;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px}
    .nav-item{padding:11px 20px;color:#94a3b8;text-decoration:none;display:flex;align-items:center;gap:14px;font-size:14px;cursor:pointer;transition:all .2s ease;border-left:3px solid transparent;margin:1px 0}
    .nav-item:hover{background:rgba(59, 130, 246, 0.08);color:#e2e8f0;text-decoration:none;border-left-color:rgba(59, 130, 246, 0.3)}
    .nav-item.active{background:rgba(59, 130, 246, 0.15);color:#60a5fa;border-left-color:#3b82f6;font-weight:600}
    .nav-icon{width:20px;text-align:center;font-size:16px}
    .logout-nav{margin-top:auto;padding:14px 20px;color:#f87171;text-decoration:none;display:flex;align-items:center;gap:14px;transition:all .2s ease;font-size:14px;border-top:1px solid #1a2332}
    .logout-nav:hover{background:rgba(239, 68, 68, 0.15);color:#fca5a5}

    /* ── Top bar ── */
    .topbar{background:#0b1120;padding:12px 20px;display:flex;align-items:center;gap:14px;border-bottom:1px solid #1a2332;position:sticky;top:0;z-index:100}
    .menu-btn{background:none;border:none;color:#94a3b8;font-size:20px;cursor:pointer;padding:4px 8px;line-height:1}
    .menu-btn:hover{color:#f1f5f9}
    .topbar-title{font-size:15px;font-weight:600;color:#e2e8f0}
    .topbar-date{margin-left:auto;display:flex;align-items:center;gap:8px;font-size:12px;color:#64748b}
    .date-input{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:5px 10px;border-radius:6px;font-size:12px;cursor:pointer}

    /* ── Page layout ── */
    .page{padding:20px;max-width:1200px;margin:0 auto}
    .page-hdr{margin-bottom:22px}
    .page-title{font-size:26px;font-weight:800;color:#f1f5f9;margin-bottom:4px}
    .page-sub{font-size:13px;color:#475569}

    /* ── Summary cards ── */
    .summary-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:22px}
    .sum-card{background:#0b1120;border:1px solid #1a2332;border-radius:10px;padding:16px 18px;cursor:pointer;transition:border-color .2s}
    .sum-card:hover{border-color:#334155}
    .sum-lbl{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
    .sum-val{font-size:30px;font-weight:800;line-height:1}
    .sum-desc{font-size:11px;color:#475569;margin-top:4px}

    /* ── Filter bar ── */
    .filter-bar{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
    .filter-btn{padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid #334155;background:#1e293b;color:#94a3b8;transition:.15s}
    .filter-btn.active{background:#1d4ed8;color:#fff;border-color:#1d4ed8}
    .filter-btn:hover{background:#263248;color:#e2e8f0}
    .apps-count{margin-left:auto;font-size:12px;color:#64748b}

    /* ── App Card ── */
    .app-card{background:#0b1120;border:1px solid #1a2332;border-radius:12px;margin-bottom:14px;overflow:hidden;transition:border-color .2s}
    .app-card:hover{border-color:#334155}
    .card-header{display:flex;align-items:flex-start;gap:14px;padding:16px 18px 14px;border-bottom:1px solid #0f1e33}
    .card-num{font-size:11px;font-weight:700;color:#475569;background:#0b1422;border:1px solid #1e293b;border-radius:6px;padding:4px 8px;min-width:36px;text-align:center;flex-shrink:0;margin-top:2px}
    .card-identity{flex:1}
    .card-name{font-size:15px;font-weight:700;color:#f1f5f9;margin-bottom:3px}
    .card-pkg{font-size:11px;color:#475569;font-family:monospace;margin-bottom:4px}
    .card-meta{font-size:11px;color:#334155}
    .card-verdict{border:1px solid #334155;border-radius:10px;padding:10px 16px;text-align:center;min-width:130px;flex-shrink:0}
    .verdict-dot{width:10px;height:10px;border-radius:50%;margin:0 auto 6px}
    .verdict-text{font-size:13px;font-weight:700;letter-spacing:.06em}
    .verdict-sub{font-size:10px;color:#475569;margin-top:3px}

    /* ── 4-Source Grid ── */
    .sources-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:14px 18px;border-bottom:1px solid #0f1e33}
    .source-box{background:#05090f;border:1px solid #1a2332;border-top:2px solid #1a2332;border-radius:8px;padding:12px}
    .src-label{font-size:10px;color:#475569;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
    .src-val{font-size:16px;font-weight:700;line-height:1;margin-bottom:4px}
    .src-sub{font-size:10px;color:#334155}

    /* ── SOC Row ── */
    .soc-row{display:flex;align-items:center;gap:14px;padding:12px 18px;border-bottom:1px solid #0f1e33;flex-wrap:wrap}
    .soc-left{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
    .soc-label{font-size:12px;color:#64748b;font-weight:600}
    .soc-select{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:7px 12px;border-radius:7px;font-size:12px;cursor:pointer;min-width:180px}
    .soc-select:focus{outline:none;border-color:#3b82f6}
    .soc-hint{font-size:11px;color:#22c55e}
    .card-actions{display:flex;gap:7px;margin-left:auto;flex-wrap:wrap}
    .btn-action{padding:6px 12px;border-radius:7px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid;transition:.15s;text-decoration:none;display:inline-flex;align-items:center;gap:4px}
    .btn-notify{background:#131f35;color:#94a3b8;border-color:#1e3a5f}.btn-notify:hover{background:#1a2d48;color:#e2e8f0}

    /* ── Algorithm Section ── */
    .algo-section{padding:14px 18px}
    .btn-algo{width:100%;background:linear-gradient(135deg,#1d4ed8,#6d28d9);color:#fff;border:none;border-radius:9px;padding:12px;font-size:13px;font-weight:700;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;letter-spacing:.04em;transition:opacity .2s}
    .btn-algo:hover{opacity:.88}
    .algo-btn-icon{font-size:14px}
    .algo-result{margin-top:12px;background:#05090f;border:1px solid #1a2332;border-radius:10px;overflow:hidden}
    .algo-loading{display:flex;align-items:center;gap:10px;padding:16px 18px;color:#64748b;font-size:13px}
    .spinner{width:18px;height:18px;border:2px solid #334155;border-top-color:#3b82f6;border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}
    @keyframes spin{to{transform:rotate(360deg)}}

    /* Score Banner */
    .algo-banner{display:grid;grid-template-columns:auto auto 1fr auto;gap:0;border-bottom:1px solid #1e293b}
    .algo-score-wrap,.algo-status-wrap,.algo-conf-wrap,.algo-src-wrap{padding:14px 18px}
    .algo-score-wrap{border-right:1px solid #1e293b;display:flex;align-items:baseline;gap:4px}
    .algo-status-wrap{border-right:1px solid #1e293b}
    .algo-conf-wrap{border-right:1px solid #1e293b}
    .algo-score-label,.algo-status-label,.algo-conf-label,.algo-src-label{font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px}
    .algo-score-value{font-size:36px;font-weight:900;line-height:1}
    .algo-score-max{font-size:14px;color:#475569;align-self:flex-end;padding-bottom:4px}
    .algo-status-value{font-size:20px;font-weight:800;letter-spacing:.05em}
    .algo-conf-bar-bg{height:8px;background:#1e293b;border-radius:99px;overflow:hidden;margin-top:8px;margin-bottom:4px}
    .algo-conf-bar-fill{height:100%;border-radius:99px;background:#22c55e;transition:width .4s}
    .algo-conf-pct{font-size:14px;font-weight:700;color:#94a3b8}
    .algo-src-value{font-size:20px;font-weight:800;color:#60a5fa}

    /* Explanation & Factors */
    .algo-explanation{padding:12px 18px;font-size:12px;color:#94a3b8;line-height:1.6;border-bottom:1px solid #0f1e33}
    .algo-factors{display:flex;flex-direction:column;gap:4px;padding:10px 18px;border-bottom:1px solid #0f1e33}
    .factor-risk{font-size:11px;color:#fca5a5;padding:3px 0}
    .factor-ok  {font-size:11px;color:#4ade80;padding:3px 0}

    /* Details */
    .btn-toggle-details{width:100%;background:none;border:none;border-top:1px solid #1e293b;color:#475569;font-size:12px;padding:10px;cursor:pointer;transition:color .15s}
    .btn-toggle-details:hover{color:#94a3b8}
    .algo-details{padding:14px 18px}
    .breakdown-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}
    .bk-card{background:#0b1422;border:1px solid #1e293b;border-radius:8px;padding:12px}
    .bk-title{font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px;display:flex;align-items:center;gap:6px}
    .bk-row{display:flex;justify-content:space-between;font-size:11px;padding:3px 0;border-bottom:1px solid #0f1e33}
    .bk-row:last-child{border-bottom:none}
    .bk-lbl{color:#475569}.bk-val{font-weight:600}

    /* Empty / misc */
    .empty-state{text-align:center;padding:80px 20px;color:#475569}
    .hidden-card{display:none}
    @media(max-width:768px){
      .sources-grid{grid-template-columns:repeat(2,1fr)}
      .algo-banner{grid-template-columns:1fr 1fr}
      .soc-row{flex-direction:column;align-items:flex-start}
      .card-actions{margin-left:0}
    }
    @media(max-width:480px){
      .sources-grid{grid-template-columns:1fr 1fr}
      .card-header{flex-direction:column}
      .card-verdict{width:100%}
    }
  </style>
</head>
<body>
<div class="overlay" id="overlay" onclick="toggleSidebar()"></div>
<div class="sidebar" id="sidebar">
  <div class="logo">
    <div class="logo-icon"><i class="fas fa-shield-alt"></i></div>
    <span>CYBER WOLF</span>
  </div>
  
  <div class="nav-section-title">NAVIGATION</div>
  <a href="/" class="nav-item">
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
  <a href="/results" class="nav-item active">
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

<div class="topbar">
  <button class="menu-btn" onclick="toggleSidebar()">☰</button>
  <span class="topbar-title">Analysis Results</span>
  <div class="topbar-date">
    <label for="dateFilter" style="color:#475569">Date:</label>
    <input type="date" id="dateFilter" class="date-input" value="${selectedDate}"
      onchange="window.location.href='/results?date='+this.value"/>
  </div>
</div>

<div class="page">
  <div class="page-hdr">
    <h1 class="page-title">Analysis Results</h1>
    <p class="page-sub">Security assessment results for all analyzed applications — SOC analyst review panel</p>
  </div>

  <!-- Summary Stats -->
  <div class="summary-row">
    <div class="sum-card" onclick="filterCards('all')">
      <div class="sum-lbl">Total Apps</div>
      <div class="sum-val" style="color:#e2e8f0">${totalApps}</div>
      <div class="sum-desc">Analyzed</div>
    </div>
    <div class="sum-card" onclick="filterCards('malicious')">
      <div class="sum-lbl">Malicious</div>
      <div class="sum-val" style="color:#ef4444">${malCount}</div>
      <div class="sum-desc">High-risk APKs</div>
    </div>
    <div class="sum-card" onclick="filterCards('suspicious')">
      <div class="sum-lbl">Suspicious</div>
      <div class="sum-val" style="color:#f59e0b">${suspCount}</div>
      <div class="sum-desc">Needs review</div>
    </div>
    <div class="sum-card" onclick="filterCards('safe')">
      <div class="sum-lbl">Safe</div>
      <div class="sum-val" style="color:#22c55e">${safeCount}</div>
      <div class="sum-desc">No threats found</div>
    </div>
    <div class="sum-card" onclick="filterCards('pending')">
      <div class="sum-lbl">Pending</div>
      <div class="sum-val" style="color:#64748b">${pendingCount}</div>
      <div class="sum-desc">Awaiting SOC review</div>
    </div>
  </div>

  <!-- Filter Bar -->
  <div class="filter-bar">
    <button class="filter-btn active" id="fb-all"        onclick="filterCards('all')">All (${totalApps})</button>
    <button class="filter-btn"        id="fb-malicious"  onclick="filterCards('malicious')">Malicious (${malCount})</button>
    <button class="filter-btn"        id="fb-suspicious" onclick="filterCards('suspicious')">Suspicious (${suspCount})</button>
    <button class="filter-btn"        id="fb-safe"       onclick="filterCards('safe')">Safe (${safeCount})</button>
    <button class="filter-btn"        id="fb-pending"    onclick="filterCards('pending')">Pending (${pendingCount})</button>
    <span class="apps-count" id="visible-count">${totalApps} of ${totalApps} shown</span>
  </div>

  <!-- App Cards -->
  <div id="cards-container">
    ${appCardsHTML}
  </div>
</div>

<script>
// ── Sidebar ───────────────────────────────────────────────────────────────────
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('overlay').classList.toggle('open');
}

// ── Filter ────────────────────────────────────────────────────────────────────
function filterCards(status) {
  const cards = document.querySelectorAll('.app-card');
  let shown = 0;
  cards.forEach(c => {
    const cs = c.dataset.status || 'unknown';
    const match = status === 'all'
      || cs === status
      || (status === 'pending' && (cs === 'pending' || cs === 'unknown' || cs === ''));
    c.classList.toggle('hidden-card', !match);
    if (match) shown++;
  });
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('fb-' + status)?.classList.add('active');
  document.getElementById('visible-count').textContent = shown + ' of ${totalApps} shown';
}

// ── SOC Status Update ─────────────────────────────────────────────────────────
async function updateSOCStatus(sha256, status) {
  const hint = document.getElementById('soc-hint-' + sha256);
  hint.textContent = 'Saving…'; hint.style.color = '#94a3b8';
  try {
    const r = await fetch('/results/update-soc-status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sha256, status })
    });
    const d = await r.json();
    if (d.success) {
      hint.textContent = '✓ Saved'; hint.style.color = '#22c55e';
      // Update the verdict badge in the card header
      const card = document.getElementById('card-' + sha256);
      if (card) {
        card.dataset.status = status;
        const vt = card.querySelector('.verdict-text');
        const vd = card.querySelector('.verdict-dot');
        if (vt) { vt.textContent = status.toUpperCase(); vt.style.color = statusColor(status); }
        if (vd) vd.style.background = statusColor(status);
        card.querySelector('.card-verdict').style.background = statusBg(status);
        card.querySelector('.card-verdict').style.borderColor = statusBorder(status);
        // Update the SOC select to match
        const sel = document.getElementById('soc-' + sha256);
        if (sel) sel.value = status;
      }
      setTimeout(() => { hint.textContent = ''; }, 3000);
    } else {
      hint.textContent = '✗ ' + d.message; hint.style.color = '#ef4444';
    }
  } catch (e) {
    hint.textContent = '✗ Error'; hint.style.color = '#ef4444';
  }
}

function statusColor(s)  { return s==='malicious'?'#ef4444':s==='suspicious'?'#f59e0b':s==='safe'?'#22c55e':'#64748b'; }
function statusBg(s)     { return s==='malicious'?'#450a0a':s==='suspicious'?'#451a03':s==='safe'?'#052e16':'#1e293b'; }
function statusBorder(s) { return s==='malicious'?'#7f1d1d':s==='suspicious'?'#92400e':s==='safe'?'#166534':'#334155'; }

// ── Run Algorithm ─────────────────────────────────────────────────────────────
async function runAlgorithm(sha256) {
  const wrapper = document.getElementById('algo-' + sha256);
  const loading = document.getElementById('algo-loading-' + sha256);
  const content = document.getElementById('algo-content-' + sha256);
  wrapper.style.display = 'block';
  loading.style.display = 'flex';
  content.style.display = 'none';

  try {
    const r = await fetch('/results/run-algorithm/' + sha256, { method: 'POST' });
    const d = await r.json();
    if (!d.success) { loading.innerHTML = '✗ Error: ' + d.message; return; }

    const score = d.finalScore;
    const status = d.finalStatus;
    const conf   = Math.round(d.confidence);
    const sColor = score >= 55 ? '#ef4444' : score >= 30 ? '#f59e0b' : '#22c55e';

    // Banner
    const scoreEl = document.getElementById('algo-score-' + sha256);
    scoreEl.textContent = score;
    scoreEl.style.color = sColor;
    const statusEl = document.getElementById('algo-status-' + sha256);
    statusEl.textContent = status;
    statusEl.style.color = sColor;
    const confBar = document.getElementById('algo-conf-bar-' + sha256);
    confBar.style.width = conf + '%';
    confBar.style.background = conf >= 75 ? '#22c55e' : conf >= 50 ? '#f59e0b' : '#ef4444';
    document.getElementById('algo-conf-' + sha256).textContent = conf + '%';
    const sourcesAvail = Object.values(d.breakdown?.sources || {}).filter(v => v !== null).length;
    document.getElementById('algo-sources-' + sha256).textContent = sourcesAvail + '/4';

    // Explanation
    const expEl = document.getElementById('algo-explanation-' + sha256);
    expEl.textContent = d.finalExplanation || '';

    // Risk / positive factors
    const facEl = document.getElementById('algo-factors-' + sha256);
    let facHTML = '';
    (d.riskFactors || []).forEach(f => { facHTML += '<div class="factor-risk">' + f + '</div>'; });
    (d.positiveFactors || []).forEach(f => { facHTML += '<div class="factor-ok">' + f + '</div>'; });
    facEl.innerHTML = facHTML;

    // Breakdown cards
    const bk = d.breakdown || {};
    const srcNames = { virustotal: '🛡 VirusTotal', mobsfStatic: '🔎 Static Analysis', mobsfDynamic: '⚡ Dynamic Analysis', ml: '🤖 ML Prediction' };
    let bkHTML = '';
    for (const [key, srcName] of Object.entries(srcNames)) {
      const score = bk.sources?.[key];
      const weight = bk.weights?.[key];
      const expl  = bk.explanations?.[key];
      const details = bk.details?.[key] || {};
      if (score === null || score === undefined) {
        bkHTML += '<div class="bk-card"><div class="bk-title">' + srcName + '</div>'
          + '<div class="bk-row"><span class="bk-lbl">Status</span><span class="bk-val" style="color:#475569">Not available</span></div>'
          + '<div class="bk-row"><span class="bk-lbl">Weight redistributed</span><span class="bk-val" style="color:#334155">—</span></div>'
          + '</div>';
        continue;
      }
      const sc2 = Math.round(score * 10) / 10;
      const sc2Color = sc2 >= 55 ? '#ef4444' : sc2 >= 30 ? '#f59e0b' : '#22c55e';
      const wPct = weight ? (weight * 100).toFixed(1) + '%' : '—';
      let detailRows = '';
      if (key === 'virustotal' && details.detectedCount !== undefined) {
        detailRows += row('Detected', details.detectedCount + ' / ' + details.totalEngines);
        detailRows += row('Detection Rate', details.detectionRate || '—');
        detailRows += row('Malicious', details.maliciousCount || 0);
        detailRows += row('Suspicious', details.suspiciousCount || 0);
      } else if (key === 'mobsfStatic' && details.securityScore !== undefined) {
        detailRows += row('MobSF Score', details.securityScore + '/100');
        detailRows += row('High-Risk Findings', details.highRiskFindings || 0);
        detailRows += row('Dangerous Permissions', details.dangerousPermissions || 0);
      } else if (key === 'mobsfDynamic' && details.trackers !== undefined) {
        detailRows += row('Trackers', details.trackers || 0);
        detailRows += row('Net Security Issues', details.networkSecurityIssues || 0);
        detailRows += row('Open Redirects', details.openRedirects || 0);
        detailRows += row('High Manifest Issues', details.highManifestIssues || 0);
      } else if (key === 'ml' && details.probability !== undefined) {
        detailRows += row('ML Probability', (details.probability * 100).toFixed(1) + '%');
        detailRows += row('Label', details.label || '—');
      }
      bkHTML += '<div class="bk-card">'
        + '<div class="bk-title">' + srcName + '</div>'
        + '<div class="bk-row"><span class="bk-lbl">Risk Score</span><span class="bk-val" style="color:' + sc2Color + '">' + sc2 + ' / 100</span></div>'
        + '<div class="bk-row"><span class="bk-lbl">Weight Applied</span><span class="bk-val" style="color:#60a5fa">' + wPct + '</span></div>'
        + '<div class="bk-row"><span class="bk-lbl">Contribution</span><span class="bk-val" style="color:#94a3b8">' + (weight ? (sc2 * weight).toFixed(1) : '—') + ' pts</span></div>'
        + detailRows
        + (expl ? '<div style="font-size:10px;color:#475569;margin-top:6px;line-height:1.5;border-top:1px solid #1e293b;padding-top:6px">' + expl + '</div>' : '')
        + '</div>';
    }
    document.getElementById('algo-breakdown-' + sha256).innerHTML = bkHTML;

    loading.style.display = 'none';
    content.style.display = 'block';
  } catch (e) {
    loading.innerHTML = '<span style="color:#ef4444">✗ Error: ' + e.message + '</span>';
  }
}

function row(lbl, val) {
  return '<div class="bk-row"><span class="bk-lbl">' + lbl + '</span><span class="bk-val" style="color:#94a3b8">' + val + '</span></div>';
}

function toggleAlgoDetails(sha256) {
  const det = document.getElementById('algo-details-' + sha256);
  const txt = document.getElementById('algo-toggle-text-' + sha256);
  const open = det.style.display === 'block';
  det.style.display = open ? 'none' : 'block';
  txt.textContent = open ? '▼ Show Score Breakdown' : '▲ Hide Score Breakdown';
}

// ── Notify ────────────────────────────────────────────────────────────────────
async function sendNotification(sha256) {
  const btn = document.getElementById('notify-btn-' + sha256);
  if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
  try {
    const r = await fetch('/results/send-notification', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sha256 })
    });
    const d = await r.json();
    if (btn) {
      if (d.success) {
        btn.textContent = 'Notification Sent';
        btn.style.color = '#22c55e';
        btn.style.borderColor = '#166534';
      } else {
        btn.disabled = false;
        btn.textContent = 'Send Notification';
        alert('Error: ' + d.message);
      }
    }
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = 'Send Notification'; }
    alert('Error: ' + e.message);
  }
}
</script>
</body>
</html>`;

    res.send(html);
  } catch (err) {
    console.error("Results route error:", err.message);
    res.status(500).send("Error: " + err.message);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
router.post("/run-algorithm/:sha256", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { sha256 } = req.params;
  try {
    let appData = null;
    const today = new Date().toISOString().split("T")[0];
    const indexName = getIndexNameForDate(today);
    try {
      const result = await esClient.search({ index: indexName, query: { term: { sha256 } } });
      if (result.hits.hits.length > 0) { appData = result.hits.hits[0]._source; appData.id = result.hits.hits[0]._id; }
    } catch (_) {
      const allResult = await esClient.search({
        index: "mobile_apps_*", query: { term: { sha256 } }, size: 1, sort: [{ timestamp: { order: "desc" } }],
      });
      if (allResult.hits.hits.length > 0) { appData = allResult.hits.hits[0]._source; appData.id = allResult.hits.hits[0]._id; }
    }
    if (!appData) return res.json({ success: false, message: "App not found" });

    const r = calculateWeightedRiskScore(appData);
    return res.json({
      success: true,
      finalScore:      r.finalScore,
      finalStatus:     r.finalStatus,
      confidence:      r.confidence,
      finalExplanation:r.finalExplanation,
      riskFactors:     r.riskFactors,
      positiveFactors: r.positiveFactors,
      breakdown:       r.breakdown,
    });
  } catch (err) {
    return res.json({ success: false, message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
router.post("/update-soc-status", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { sha256, status } = req.body;
  const allowed = ["safe", "malicious", "suspicious", "pending"];
  if (!allowed.includes(status)) return res.json({ success: false, message: "Invalid status" });

  try {
    let foundIndex = null;
    let docId      = null;
    const today    = new Date().toISOString().split("T")[0];
    try {
      const result = await esClient.search({ index: getIndexNameForDate(today), query: { term: { sha256 } } });
      if (result.hits.hits.length > 0) { foundIndex = result.hits.hits[0]._index; docId = result.hits.hits[0]._id; }
    } catch (_) { /* fall through */ }

    if (!docId) {
      const allResult = await esClient.search({
        index: "mobile_apps_*", query: { term: { sha256 } }, size: 1, sort: [{ timestamp: { order: "desc" } }],
      });
      if (allResult.hits.hits.length > 0) { foundIndex = allResult.hits.hits[0]._index; docId = allResult.hits.hits[0]._id; }
    }

    if (!docId) return res.json({ success: false, message: "App not found" });

    await esClient.update({
      index: foundIndex, id: docId, retry_on_conflict: 3,
      body: { doc: {
        status,
        statusSource:  "SOC Analyst",
        socUpdatedAt:  new Date().toISOString(),
        lastModified:  new Date().toISOString(),
      }},
    });
    return res.json({ success: true, message: "Status updated by SOC Analyst" });
  } catch (err) {
    return res.json({ success: false, message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
router.post("/send-notification", requireWebAuth, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { sha256 } = req.body;
  if (!sha256) return res.json({ success: false, message: "sha256 is required" });

  try {
    // Look up app data so notification is accurate
    let appDoc = null;
    try {
      const searchResult = await esClient.search({
        index: "mobile_apps_*",
        size: 1,
        query: { term: { sha256 } },
        sort: [{ timestamp: { order: "desc" } }],
      });
      if (searchResult.hits.hits.length > 0) appDoc = searchResult.hits.hits[0]._source;
    } catch (_) {}

    const appName    = appDoc?.appName || appDoc?.packageName || "Unknown App";
    const pkgName    = appDoc?.packageName || "N/A";
    const socStatus  = (appDoc?.status || "pending").toLowerCase();
    const vtRatio    = appDoc?.virusTotalAnalysis?.detectionRatio || appDoc?.virusTotalHashCheck?.detectionRatio || "N/A";
    const secScore   = appDoc?.mobsfAnalysis?.security_score ?? null;
    const now        = new Date();
    const ts         = now.toISOString();
    const dateStr    = `${String(now.getDate()).padStart(2,'0')}/${String(now.getMonth()+1).padStart(2,'0')}/${now.getFullYear()} ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;

    let type, severity, title, message;

    if (socStatus === "malicious") {
      type     = "malicious";
      severity = "high";
      title    = `Malicious App Detected: ${appName}`;
      message  = `${appName} has been marked MALICIOUS by SOC Analyst. Detection: ${vtRatio}. Reviewed on ${dateStr}.`;
    } else if (socStatus === "suspicious") {
      type     = "suspicious";
      severity = "medium";
      title    = `Suspicious App Flagged: ${appName}`;
      message  = `${appName} has been flagged as SUSPICIOUS by SOC Analyst. Detection: ${vtRatio}. Reviewed on ${dateStr}.`;
    } else if (socStatus === "safe") {
      type     = "info";
      severity = "low";
      title    = `App Cleared: ${appName}`;
      message  = `${appName} has been reviewed and marked SAFE by SOC Analyst. Detection: ${vtRatio}. Reviewed on ${dateStr}.`;
    } else {
      type     = "info";
      severity = "low";
      title    = `Pending Review: ${appName}`;
      message  = `${appName} is pending SOC Analyst review. Detection: ${vtRatio}.`;
    }

    const notifId = `soc_${sha256}_${Date.now()}`;
    await esClient.index({
      index: `notifications_${now.toISOString().split("T")[0]}`,
      id: notifId,
      document: {
        id: notifId,
        type,
        severity,
        title,
        message,
        appName,
        packageName: pkgName,
        sha256,
        detectionRatio: vtRatio,
        socStatus,
        createdAt: ts,
        timestamp: ts,
        source: "soc-analyst",
      },
    });

    return res.json({ success: true, message: "Notification sent" });
  } catch (err) {
    return res.json({ success: false, message: err.message });
  }
});

module.exports = router;
