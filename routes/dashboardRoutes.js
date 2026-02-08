const express = require('express');
const router = express.Router();
const { esClient } = require('../elasticsearch');

// Helper function to get dynamic index name
const getIndexName = () => {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, '0');
  const month = String(today.getMonth() + 1).padStart(2, '0');
  const year = today.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
};

// Dashboard route
router.get('/', async (req, res) => {  // Changed from '/dashboard' to '/'
  const esClient = req.app.get('esClient');
  const username = req.session?.username || 'User';
  let indexName = getIndexName();
  let currentDate = new Date().toISOString().split('T')[0];

  if (req.query.date) {
    const dateParts = req.query.date.split('-');
    if (dateParts.length === 3) {
      const [year, month, day] = dateParts;
      indexName = `mobile_apps_${day}-${month}-${year}`;
      currentDate = req.query.date;
    }
  }
  
  try {
    // Fetch all apps from the specified index
    const result = await esClient.search({
      index: indexName,
      size: 1000,
      query: { match_all: {} },
      sort: [{ timestamp: { order: "desc" } }],
    });

    console.log('🔍 RAW ELASTICSEARCH RESPONSE - Total hits:', result.hits.total.value);
    console.log('🔍 RAW ELASTICSEARCH - First 3 raw hits:');
    result.hits.hits.slice(0, 3).forEach((hit, idx) => {
      console.log(`   Hit ${idx}:`, JSON.stringify({
        packageName: hit._source.packageName,
        appType: hit._source.appType,
        appType_type: typeof hit._source.appType,
        status: hit._source.status
      }));
    });

    const apps = result.hits.hits.map((hit) => {
      const app = hit._source;
      
      // Extract VirusTotal analysis data
      const virusTotalData = app.virusTotalHashCheck || app.virusTotalAnalysis || {};
      
      const mappedApp = {
        ...app,
        _id: hit._id,
        id: hit._id,
        // Map VirusTotal data to flat properties for easy access
        detectionRatio: virusTotalData.detectionRatio || 'N/A',
        totalEngines: virusTotalData.totalEngines || 'N/A',
        detectedEngines: virusTotalData.detectedEngines || 'N/A',
        scanTime: virusTotalData.scanTime || app.scanTime || null,
        // Ensure status is never "NOT FOUND" or "not_found" - convert to "unknown"
        status: (app.status === 'NOT FOUND' || app.status === 'not_found') ? 'unknown' : (app.status || 'unknown'),
        // Default to 'system' if appType is not defined (for backward compatibility)
        appType: app.appType || 'system'
      };
      
      return mappedApp;
    });
    
    console.log('🔍 AFTER MAPPING - First 3 mapped apps:');
    apps.slice(0, 3).forEach((app, idx) => {
      console.log(`   App ${idx}:`, JSON.stringify({
        packageName: app.packageName,
        appType: app.appType,
        appType_type: typeof app.appType,
        appType_value: JSON.stringify(app.appType),
        status: app.status
      }));
    });

    // Debug: Log all apps and their appType
    console.log('📊 DEBUG - All apps count:', apps.length);
    console.log('📊 DEBUG - Apps sample (first 5):', apps.slice(0, 5).map(a => ({ 
      packageName: a.packageName, 
      appType: a.appType,
      appType_type: typeof a.appType
    })));

    // Separate apps by type - with detailed logging
    console.log('🔍 FILTERING APPS:');
    const userApps = apps.filter(app => {
      const isUser = app.appType === 'user';
      console.log(`   ${app.packageName}: appType="${app.appType}" === "user" ? ${isUser}`);
      return isUser;
    });
    const systemApps = apps.filter(app => app.appType === 'system');

    console.log('📊 DEBUG - User Apps count:', userApps.length);
    console.log('📊 DEBUG - System Apps count:', systemApps.length);
    console.log('📊 DEBUG - User apps packageNames:', userApps.map(a => a.packageName).slice(0, 5));
    if (userApps.length > 0) {
      console.log('📊 DEBUG - Sample User App:', userApps[0].packageName, 'appType:', userApps[0].appType);
    }
    if (systemApps.length > 0) {
      console.log('📊 DEBUG - Sample System App:', systemApps[0].packageName, 'appType:', systemApps[0].appType);
    }

    // Calculate statistics for all apps
    const stats = {
      total: apps.length,
      safe: apps.filter(app => app.status === 'safe').length,
      malicious: apps.filter(app => app.status === 'malicious').length,
      suspicious: apps.filter(app => app.status === 'suspicious').length,
      unknown: apps.filter(app => app.status === 'unknown' || !app.status).length,
    };

    // Calculate statistics for user apps
    const userStats = {
      total: userApps.length,
      safe: userApps.filter(app => app.status === 'safe').length,
      malicious: userApps.filter(app => app.status === 'malicious').length,
      suspicious: userApps.filter(app => app.status === 'suspicious').length,
      unknown: userApps.filter(app => app.status === 'unknown' || !app.status).length,
    };

    // Calculate statistics for system apps
    const systemStats = {
      total: systemApps.length,
      safe: systemApps.filter(app => app.status === 'safe').length,
      malicious: systemApps.filter(app => app.status === 'malicious').length,
      suspicious: systemApps.filter(app => app.status === 'suspicious').length,
      unknown: systemApps.filter(app => app.status === 'unknown' || !app.status).length,
    };

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Android Malware Detection Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: #0a192f;
            color: #94a3b8;
            min-height: 100vh;
            display: flex;
        }

        /* Sidebar styles */
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
            color: white;
        }

        /* Main content styles */
        .main-content {
            margin-left: 0;
            flex: 1;
            padding: 0;
            width: 100%;
            transition: margin-left 0.3s ease;
        }

        .main-content.shifted {
            margin-left: 200px;
        }

        .menu-btn {
            background: transparent;
            border: none;
            color: #94a3b8;
            font-size: 18px;
            cursor: pointer;
            padding: 4px 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: color 0.3s;
        }

        .menu-btn:hover {
            color: white;
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
            padding: 8px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1d3557;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 10px;
            color: #e2e8f0;
            font-size: 14px;
            font-weight: 500;
            margin-left: auto;
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

        .container {
            padding: 30px;
            max-width: 1400px;
            margin: 0 auto;
            width: 100%;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
        }

        h1 {
            color: white;
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .subtitle {
            color: #64748b;
            font-size: 14px;
        }

        .controls {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            gap: 15px;
        }

        .date-selector {
            display: flex;
            gap: 10px;
            padding: 10px 15px;
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 8px;
            align-items: center;
        }

        .date-selector input {
            background: transparent;
            border: none;
            color: #94a3b8;
            padding: 5px;
            font-size: 14px;
        }

        .date-selector input:focus {
            outline: none;
        }

        .clear-btn {
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid #7f1d1d;
            color: #ef4444;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .clear-btn:hover {
            background: #7f1d1d;
            color: white;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }

        .stat-label {
            color: #94a3b8;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }

        .stat-value {
            font-size: 32px;
            font-weight: bold;
        }

        .stat-card.total .stat-value { color: #3b82f6; }
        .stat-card.malicious .stat-value { color: #ef4444; }
        .stat-card.safe .stat-value { color: #10b981; }
        .stat-card.suspicious .stat-value { color: #f59e0b; }
        .stat-card.unknown .stat-value { color: #6b7280; }

        /* App Type Filter Styles */
        .app-type-filter {
            display: flex;
            gap: 15px;
            margin-bottom: 25px;
            margin-top: 15px;
        }

        .filter-btn {
            flex: 1;
            padding: 12px 20px;
            background: #1d3557;
            border: 2px solid #1d3557;
            color: #94a3b8;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.3s ease;
        }

        .filter-btn:hover {
            background: #112240;
            border-color: #2563eb;
            color: #60a5fa;
        }

        .filter-btn.active {
            background: #2563eb;
            border-color: #2563eb;
            color: white;
        }

        .app-type-stats {
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
        }

        .app-type-stats.hidden {
            display: none;
        }

        .app-type-stats.visible {
            display: block;
        }

        .app-type-title {
            color: #60a5fa;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .mini-stats {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
        }

        .mini-stat {
            background: #0a192f;
            border: 1px solid #1d3557;
            border-radius: 6px;
            padding: 10px 12px;
            text-align: center;
            font-size: 13px;
            color: #cbd5e1;
        }

        .mini-stat strong {
            color: #e2e8f0;
            display: block;
            margin-bottom: 4px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }

        .mini-stat.safe {
            color: #10b981;
        }

        .mini-stat.malicious {
            color: #ef4444;
        }

        .mini-stat.suspicious {
            color: #f59e0b;
        }

        .mini-stat.unknown {
            color: #6b7280;
        }

        .app-row.hidden {
            display: none;
        }

        .table-header {
            display: grid;
            grid-template-columns: 1.5fr 1.5fr 1.5fr 1.2fr 0.8fr;
            padding: 10px 15px;
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 8px 8px 0 0;
            margin-top: 20px;
            gap: 10px;
        }

        .table-header div {
            color: #94a3b8;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .app-list {
            display: flex;
            flex-direction: column;
        }

        .app-row {
            display: grid;
            grid-template-columns: 1.5fr 1.5fr 1.5fr 1.2fr 0.8fr;
            padding: 12px 15px;
            background: #112240;
            border: 1px solid #1d3557;
            border-top: none;
            align-items: center;
            transition: all 0.3s;
            gap: 10px;
        }

        .app-row:last-child {
            border-radius: 0 0 8px 8px;
        }

        .app-row:hover {
            background: #1d3557;
            border-color: #2563eb;
        }

        .app-name {
            color: #e2e8f0;
            font-weight: 600;
            font-size: 14px;
            margin-bottom: 4px;
        }

        .app-meta {
            color: #cbd5e1;
            font-size: 12px;
        }

        .status-badge {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            display: inline-block;
        }

        .status-safe {
            background: rgba(16, 185, 129, 0.2);
            color: #10b981;
        }

        .status-malicious {
            background: rgba(239, 68, 68, 0.2);
            color: #ef4444;
        }

        .status-suspicious {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
        }

        .status-unknown {
            background: rgba(107, 114, 128, 0.2);
            color: #6b7280;
        }

        .status-uploaded {
            background: rgba(148, 163, 184, 0.2);
            color: #94a3b4;
        }

        .actions {
            display: flex;
            gap: 6px;
            align-items: center;
        }

        .view-btn {
            background: #2563eb;
            border: none;
            color: white;
            padding: 6px 10px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.3s;
        }

        .view-btn:hover {
            background: #1e40af;
        }

        .delete-icon {
            width: 28px;
            height: 28px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #7f1d1d;
            border-radius: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ef4444;
            cursor: pointer;
            transition: all 0.3s;
            font-size: 12px;
        }

        .delete-icon:hover {
            background: #7f1d1d;
            color: white;
        }

        .no-data {
            text-align: center;
            padding: 60px;
            color: #64748b;
            font-size: 16px;
        }

        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
            padding: 20px;
        }

        .modal-content {
            background: #112240;
            border: 1px solid #1d3557;
            border-radius: 12px;
            padding: 30px;
            max-width: 700px;
            width: 100%;
            max-height: 80vh;
            overflow-y: auto;
        }

        .modal-content h2 {
            color: white;
            margin-bottom: 20px;
            font-size: 20px;
        }

        .detail-row {
            display: flex;
            padding: 12px 0;
            border-bottom: 1px solid #1d3557;
        }

        .detail-label {
            color: #64748b;
            font-size: 13px;
            min-width: 150px;
            font-weight: 600;
        }

        .detail-value {
            color: #e2e8f0;
            font-size: 13px;
            flex: 1;
            word-break: break-all;
        }

        .permissions-list {
            list-style: none;
            padding: 0;
            margin: 15px 0;
        }

        .permissions-list li {
            padding: 10px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid #7f1d1d;
            border-radius: 6px;
            margin-bottom: 6px;
            color: #ef4444;
            font-size: 12px;
        }

        .close-btn {
            background: #2563eb;
            border: none;
            color: white;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 20px;
            font-weight: 600;
            float: right;
        }

        .close-btn:hover {
            background: #1e40af;
        }

        @media (max-width: 1200px) {
            .stats-grid {
                grid-template-columns: repeat(3, 1fr);
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                left: -200px;
                transition: left 0.3s;
            }
            .sidebar.open {
                left: 0;
            }
            .main-content {
                margin-left: 0;
            }
            .stats-grid {
                grid-template-columns: 1fr 1fr;
            }
            .table-header, .app-row {
                grid-template-columns: 1fr;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <!-- Sidebar -->
    <div class="sidebar">
        <div class="logo">
            <div class="logo-icon">
                <i class="fas fa-shield-alt"></i>
            </div>
            <span>CYBER WOLF</span>
        </div>
        
        <a href="/" class="nav-item">
            <i class="fas fa-home nav-icon"></i>
            <span>Home</span>
        </a>
        
        <a href="/dashboard" class="nav-item active">
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

    <!-- Overlay for closing sidebar -->
    <div class="overlay" id="overlay"></div>

    <!-- Main Content -->
    <div class="main-content">
        <div class="top-bar">
            <button class="menu-btn" id="menuBtn">
                <i class="fas fa-bars"></i>
            </button>
            <div class="user-info">
                <div class="user-avatar">${username.charAt(0).toUpperCase()}</div>
                <span>${username}</span>
            </div>
        </div>

        <div class="container">
            <div class="header">
                <h1>Security Dashboard</h1>
                <p class="subtitle">Real-time Android malware detection insights</p>
            </div>

            <div class="controls">
                <div class="date-selector">
                    <i class="fas fa-calendar-alt" style="color: #64748b;"></i>
                    <input type="date" id="dateFilter" value="${currentDate}">
                </div>
                <div class="date-selector">
                    <i class="fas fa-search" style="color: #64748b;"></i>
                    <input type="text" id="searchInput" placeholder="Search by app name..." style="background: transparent; border: none; color: #94a3b8; padding: 5px; font-size: 14px; width: 250px;" onkeyup="searchApps()">
                </div>
                <button class="clear-btn" onclick="clearIndex()">
                    <i class="fas fa-trash-alt"></i>
                    Clear Today's Data
                </button>
            </div>

            <div class="stats-grid">
                <div class="stat-card total">
                    <div class="stat-label">Total Apps</div>
                    <div class="stat-value">${stats.total}</div>
                </div>
                <div class="stat-card malicious">
                    <div class="stat-label">Malicious</div>
                    <div class="stat-value">${stats.malicious}</div>
                </div>
                <div class="stat-card safe">
                    <div class="stat-label">Safe</div>
                    <div class="stat-value">${stats.safe}</div>
                </div>
                <div class="stat-card suspicious">
                    <div class="stat-label">Suspicious</div>
                    <div class="stat-value">${stats.suspicious}</div>
                </div>
                <div class="stat-card unknown">
                    <div class="stat-label">Unknown</div>
                    <div class="stat-value">${stats.unknown}</div>
                </div>
            </div>

            <!-- App Type Filter -->
            <div class="app-type-filter">
                <button id="userAppsBtn" class="filter-btn active" onclick="filterByAppType('user')">
                    <i class="fas fa-user"></i> User Apps (${userStats.total})
                </button>
                <button id="systemAppsBtn" class="filter-btn" onclick="filterByAppType('system')">
                    <i class="fas fa-cog"></i> System Apps (${systemStats.total})
                </button>
            </div>

            <!-- User Apps Stats -->
            <div id="userAppsStatsContainer" class="app-type-stats visible">
                <div class="app-type-title">User Applications</div>
                <div class="mini-stats">
                    <div class="mini-stat"><strong>Total:</strong> ${userStats.total}</div>
                    <div class="mini-stat safe"><strong>Safe:</strong> ${userStats.safe}</div>
                    <div class="mini-stat malicious"><strong>Malicious:</strong> ${userStats.malicious}</div>
                    <div class="mini-stat suspicious"><strong>Suspicious:</strong> ${userStats.suspicious}</div>
                    <div class="mini-stat unknown"><strong>Unknown:</strong> ${userStats.unknown}</div>
                </div>
            </div>

            <!-- System Apps Stats -->
            <div id="systemAppsStatsContainer" class="app-type-stats hidden">
                <div class="app-type-title">System Applications</div>
                <div class="mini-stats">
                    <div class="mini-stat"><strong>Total:</strong> ${systemStats.total}</div>
                    <div class="mini-stat safe"><strong>Safe:</strong> ${systemStats.safe}</div>
                    <div class="mini-stat malicious"><strong>Malicious:</strong> ${systemStats.malicious}</div>
                    <div class="mini-stat suspicious"><strong>Suspicious:</strong> ${systemStats.suspicious}</div>
                    <div class="mini-stat unknown"><strong>Unknown:</strong> ${systemStats.unknown}</div>
                </div>
            </div>

            ${apps.length > 0 ? `
                <div class="table-header">
                    <div>APP DETAILS</div>
                    <div>PACKAGE INFO</div>
                    <div>FILE INFORMATION</div>
                    <div>STATUS & ANALYSIS</div>
                    <div>ACTIONS</div>
                </div>
                <div class="app-list" id="appList">
                    ${userApps.map(app => `
                        <div class="app-row user-app" data-app-type="user">
                            <div>
                                <div class="app-name">${app.appName || 'Unknown'}</div>
                                <div class="app-meta">Uploaded: ${new Date(app.uploadedAt || app.timestamp).toLocaleDateString()}</div>
                            </div>
                            <div>
                                <div class="app-meta">Package: ${app.packageName || 'N/A'}</div>
                            </div>
                            <div>
                                <div class="app-meta">Size: ${app.sizeMB ? app.sizeMB.toFixed(2) + ' MB' : (app.fileSize ? (app.fileSize / (1024 * 1024)).toFixed(2) + ' MB' : 'N/A')}</div>
                                <div class="app-meta">Hash: ${app.sha256 ? app.sha256.substring(0, 16) + '...' : 'N/A'}</div>
                            </div>
                            <div>
                                <span class="status-badge status-${app.uploadedByUser ? 'uploaded' : (app.status?.toLowerCase() || 'unknown')}">${app.uploadedByUser ? 'Uploaded' : (app.status || 'Unknown')}</span>
                                <div class="app-meta" style="margin-top: 5px;">Score: ${app.mobsfAnalysis?.security_score || app.virusTotalHashCheck?.detectionRatio || app.virusTotalAnalysis?.detectionRatio || 'N/A'}</div>
                            </div>
                            <div class="actions">
                                <button class="view-btn" onclick='showDetails(${JSON.stringify(app).replace(/'/g, "\\'")})'>View Details</button>
                                <div class="delete-icon" onclick="deleteApp('${app._id}')">
                                    <i class="fas fa-trash-alt"></i>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                    ${systemApps.map(app => `
                        <div class="app-row system-app hidden" data-app-type="system">
                            <div>
                                <div class="app-name">${app.appName || 'Unknown'}</div>
                                <div class="app-meta">Uploaded: ${new Date(app.uploadedAt || app.timestamp).toLocaleDateString()}</div>
                            </div>
                            <div>
                                <div class="app-meta">Package: ${app.packageName || 'N/A'}</div>
                            </div>
                            <div>
                                <div class="app-meta">Size: ${app.sizeMB ? app.sizeMB.toFixed(2) + ' MB' : (app.fileSize ? (app.fileSize / (1024 * 1024)).toFixed(2) + ' MB' : 'N/A')}</div>
                                <div class="app-meta">Hash: ${app.sha256 ? app.sha256.substring(0, 16) + '...' : 'N/A'}</div>
                            </div>
                            <div>
                                <span class="status-badge status-${app.uploadedByUser ? 'uploaded' : (app.status?.toLowerCase() || 'unknown')}">${app.uploadedByUser ? 'Uploaded' : (app.status || 'Unknown')}</span>
                                <div class="app-meta" style="margin-top: 5px;">Score: ${app.mobsfAnalysis?.security_score || app.virusTotalHashCheck?.detectionRatio || app.virusTotalAnalysis?.detectionRatio || 'N/A'}</div>
                            </div>
                            <div class="actions">
                                <button class="view-btn" onclick='showDetails(${JSON.stringify(app).replace(/'/g, "\\'")})'>View Details</button>
                                <div class="delete-icon" onclick="deleteApp('${app._id}')">
                                    <i class="fas fa-trash-alt"></i>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            ` : `
                <div class="no-data">
                    <i class="fas fa-inbox" style="font-size: 48px; margin-bottom: 15px; display: block; opacity: 0.5;"></i>
                    No applications scanned for selected date
                </div>
            `}
        </div>
    </div>

    <!-- Modal for App Details -->
    <div class="modal" id="detailsModal">
        <div class="modal-content">
            <h2>Application Details</h2>
            <div id="modalDetails"></div>
            <button class="close-btn" onclick="closeModal()">Close</button>
        </div>
    </div>

    <script>
        // Sidebar toggle
        const sidebar = document.querySelector('.sidebar');
        const overlay = document.getElementById('overlay');
        const menuBtn = document.getElementById('menuBtn');
        const mainContent = document.querySelector('.main-content');

        menuBtn.addEventListener('click', function() {
            sidebar.classList.toggle('open');
            overlay.classList.toggle('active');
            mainContent.classList.toggle('shifted');
        });

        overlay.addEventListener('click', function() {
            sidebar.classList.remove('open');
            overlay.classList.remove('active');
            mainContent.classList.remove('shifted');
        });

        // Filter apps by date
        document.getElementById('dateFilter').addEventListener('change', function() {
            const selectedDate = this.value;
            window.location.href = '/dashboard?date=' + selectedDate;
        });

        // Filter apps by type (User/System)
        function filterByAppType(appType) {
            // Update active button
            document.getElementById('userAppsBtn').classList.toggle('active', appType === 'user');
            document.getElementById('systemAppsBtn').classList.toggle('active', appType === 'system');

            // Show/hide stats containers
            const userStatsContainer = document.getElementById('userAppsStatsContainer');
            const systemStatsContainer = document.getElementById('systemAppsStatsContainer');
            
            if (appType === 'user') {
                userStatsContainer.classList.remove('hidden');
                userStatsContainer.classList.add('visible');
                systemStatsContainer.classList.remove('visible');
                systemStatsContainer.classList.add('hidden');
            } else {
                systemStatsContainer.classList.remove('hidden');
                systemStatsContainer.classList.add('visible');
                userStatsContainer.classList.remove('visible');
                userStatsContainer.classList.add('hidden');
            }

            // Show/hide app rows
            const appRows = document.querySelectorAll('.app-row');
            appRows.forEach(row => {
                const rowAppType = row.getAttribute('data-app-type');
                if (rowAppType === appType) {
                    row.classList.remove('hidden');
                } else {
                    row.classList.add('hidden');
                }
            });
        }

        // Search apps by name (works with current filter)
        function searchApps() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const appRows = document.querySelectorAll('.app-row');
            let visibleCount = 0;
            
            appRows.forEach(row => {
                const appName = row.querySelector('.app-name')?.textContent.toLowerCase() || '';
                const isHidden = row.classList.contains('hidden');
                
                // Only search within visible app type
                if (!isHidden && appName.includes(searchTerm)) {
                    row.style.display = '';
                    visibleCount++;
                } else if (!isHidden) {
                    row.style.display = 'none';
                } else {
                    row.style.display = 'none';
                }
            });
        }

        // Show app details in modal
        function showDetails(app) {
            const modal = document.getElementById('detailsModal');
            const detailsDiv = document.getElementById('modalDetails');
            
            let html = '<div style="display: grid; gap: 15px;">';
            
            // Basic App Information
            html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-bottom: 10px;">Basic Information</h3>';
            html += '<div class="detail-row"><div class="detail-label">App Name:</div><div class="detail-value">' + (app.appName || 'N/A') + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Package Name:</div><div class="detail-value">' + (app.packageName || 'N/A') + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Size:</div><div class="detail-value">' + (app.fileSize ? (app.fileSize / (1024 * 1024)).toFixed(2) + ' MB' : (app.sizeMB ? app.sizeMB.toFixed(2) + ' MB' : 'N/A')) + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Source:</div><div class="detail-value">' + (app.source || app.uploadSource || 'N/A') + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Uploaded By User:</div><div class="detail-value">' + (app.uploadedByUser ? 'Yes' : 'No') + '</div></div>';
            
            // File Hashes
            html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">File Hashes</h3>';
            html += '<div class="detail-row"><div class="detail-label">SHA-256:</div><div class="detail-value" style="word-break: break-all; font-family: monospace; font-size: 11px;">' + (app.sha256 || 'N/A') + '</div></div>';
            
            // Status Information
            html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Security Status</h3>';
            const displayStatus = app.uploadedByUser ? 'Uploaded' : (app.status || 'Unknown');
            const statusClass = app.uploadedByUser ? 'uploaded' : (app.status?.toLowerCase() || 'unknown');
            html += '<div class="detail-row"><div class="detail-label">Overall Status:</div><div class="detail-value"><span class="status-badge status-' + statusClass + '">' + displayStatus + '</span></div></div>';
            
            // VirusTotal Analysis
            const vtData = app.virusTotalHashCheck || app.virusTotalAnalysis;
            if (vtData) {
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">VirusTotal Analysis</h3>';
                html += '<div class="detail-row"><div class="detail-label">Detection Ratio:</div><div class="detail-value">' + (vtData.detectionRatio || app.detectionRatio || 'N/A') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Detected Engines:</div><div class="detail-value">' + (vtData.detectedEngines || app.detectedEngines || '0') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Total Engines:</div><div class="detail-value">' + (vtData.totalEngines || app.totalEngines || '0') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Scan Time:</div><div class="detail-value">' + (vtData.scanTime ? new Date(vtData.scanTime).toLocaleString() : 'N/A') + '</div></div>';
            }
            
            // MobSF Analysis
            if (app.mobsfAnalysis) {
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">MobSF Security Analysis</h3>';
                html += '<div class="detail-row"><div class="detail-label">Security Score:</div><div class="detail-value"><strong style="font-size: 18px; color: ' + (app.mobsfAnalysis.security_score >= 70 ? '#10b981' : app.mobsfAnalysis.security_score < 40 ? '#ef4444' : '#f59e0b') + ';">' + (app.mobsfAnalysis.security_score || 'N/A') + '/100</strong></div></div>';
                html += '<div class="detail-row"><div class="detail-label">Scan Type:</div><div class="detail-value">' + (app.mobsfAnalysis.scan_type || app.mobsfScanType || 'N/A') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">File Name:</div><div class="detail-value">' + (app.mobsfAnalysis.file_name || app.apkFileName || 'N/A') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">High Risk Findings:</div><div class="detail-value">' + (app.mobsfAnalysis.high_risk_findings || '0') + '</div></div>';
                
                // Dangerous Permissions from MobSF
                if (app.mobsfAnalysis.dangerous_permissions && app.mobsfAnalysis.dangerous_permissions.length > 0) {
                    html += '<div class="detail-row"><div class="detail-label">Dangerous Permissions (' + app.mobsfAnalysis.dangerous_permissions.length + '):</div><div class="detail-value"><ul class="permissions-list">';
                    app.mobsfAnalysis.dangerous_permissions.forEach(perm => {
                        html += '<li>' + perm + '</li>';
                    });
                    html += '</ul></div></div>';
                }
                
                // Legacy permissions field support
                if (app.mobsfAnalysis.permissions && app.mobsfAnalysis.permissions.length > 0) {
                    html += '<div class="detail-row"><div class="detail-label">Permissions (' + app.mobsfAnalysis.permissions.length + '):</div><div class="detail-value"><ul class="permissions-list">';
                    app.mobsfAnalysis.permissions.forEach(perm => {
                        html += '<li>' + perm + '</li>';
                    });
                    html += '</ul></div></div>';
                }
            }
            
            // Dangerous Permissions from original data (if not covered by MobSF)
            const hasDangerousPerms = Object.keys(app).some(key => key.startsWith('dangerousPermission') && app[key]);
            if (hasDangerousPerms) {
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Detected Dangerous Permissions</h3>';
                html += '<ul class="permissions-list">';
                for (let i = 1; i <= 20; i++) {
                    const permKey = 'dangerousPermission' + i;
                    if (app[permKey]) {
                        html += '<li>' + app[permKey] + '</li>';
                    }
                }
                html += '</ul>';
            }
            
            // File Paths
            if (app.apkFilePath || app.apkFileName) {
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">File Information</h3>';
                if (app.apkFilePath) {
                    html += '<div class="detail-row"><div class="detail-label">APK Path:</div><div class="detail-value" style="word-break: break-all; font-size: 11px;">' + app.apkFilePath + '</div></div>';
                }
                if (app.apkFileName) {
                    html += '<div class="detail-row"><div class="detail-label">APK Filename:</div><div class="detail-value">' + app.apkFileName + '</div></div>';
                }
            }
            
            // Timestamps
            html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Timestamps</h3>';
            html += '<div class="detail-row"><div class="detail-label">Uploaded:</div><div class="detail-value">' + new Date(app.uploadedAt || app.timestamp).toLocaleString() + '</div></div>';
            if (app.scanTime) {
                html += '<div class="detail-row"><div class="detail-label">Scan Time:</div><div class="detail-value">' + new Date(app.scanTime).toLocaleString() + '</div></div>';
            }
            
            // Error Information (if any)
            const vtErrorData = app.virusTotalHashCheck || app.virusTotalAnalysis;
            if (app.mobsfError || (vtErrorData && vtErrorData.error)) {
                html += '<h3 style="color: #ef4444; border-bottom: 1px solid #7f1d1d; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Errors</h3>';
                if (app.mobsfError) {
                    html += '<div class="detail-row"><div class="detail-label">MobSF Error:</div><div class="detail-value" style="color: #ef4444;">' + app.mobsfError + '</div></div>';
                }
                if (vtErrorData && vtErrorData.error) {
                    html += '<div class="detail-row"><div class="detail-label">VirusTotal Error:</div><div class="detail-value" style="color: #ef4444;">' + vtErrorData.error + '</div></div>';
                }
            }
            
            html += '</div>';
            
            detailsDiv.innerHTML = html;
            modal.style.display = 'flex';
        }

        // Close modal
        function closeModal() {
            document.getElementById('detailsModal').style.display = 'none';
        }

        // Close modal on outside click
        document.getElementById('detailsModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeModal();
            }
        });

        // Delete app
        function deleteApp(appId) {
            if (confirm('Are you sure you want to delete this app?')) {
                fetch('/dashboard/delete-app/' + appId, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        alert('App deleted successfully!');
                        location.reload();
                    } else {
                        alert('Failed to delete app: ' + (data.error || 'Unknown error'));
                    }
                })
                .catch(err => {
                    console.error('Error:', err);
                    alert('Failed to delete app');
                });
            }
        }

        // Clear today's data
        function clearIndex() {
            if (confirm('Are you sure you want to delete all scanned apps from today\\'s index?')) {
                fetch('/dashboard/delete-index', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                })
                .then(res => res.json())
                .then(data => {
                    alert(data.message);
                    location.reload();
                })
                .catch(err => {
                    console.error('Error:', err);
                    alert('Failed to delete index');
                });
            }
        }
    </script>
</body>
</html>
`;
    
    res.send(html);
  } catch (err) {
    console.error('Error fetching dashboard data:', err);
    res.status(500).send(`
      <html>
      <head>
        <style>
          body {
            background: #0a192f;
            color: #ef4444;
            font-family: Arial;
            text-align: center;
            padding: 50px;
          }
          button {
            background: #2563eb;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
          }
        </style>
      </head>
      <body>
        <h1>🚨 Dashboard Error</h1>
        <p>Failed to load apps data: ${err.message}</p>
        <p>Index: ${indexName}</p>
        <button onclick="location.reload()">Try Again</button>
      </body>
      </html>
    `);
  }
});

// Route to delete all data from a specific index
router.post('/delete-index', async (req, res) => {
  try {
    const indexName = getIndexName();
    
    console.log(`Attempting to delete all documents from index: ${indexName}`);

    // Delete all documents in the index
    const deleteResponse = await esClient.deleteByQuery({
      index: indexName,
      body: {
        query: {
          match_all: {}
        }
      }
    });

    console.log('Delete response:', deleteResponse);

    res.json({ 
      success: true, 
      deletedCount: deleteResponse.deleted,
      message: `Successfully deleted ${deleteResponse.deleted} documents from index ${indexName}`
    });

  } catch (err) {
    console.error('Error deleting index data:', err);
    
    // Handle case where index doesn't exist
    if (err.meta && err.meta.statusCode === 404) {
      return res.json({ 
        success: true, 
        deletedCount: 0,
        message: 'Index does not exist or is already empty'
      });
    }

    res.status(500).json({ 
      error: 'Failed to delete index data: ' + err.message 
    });
  }
});

// Route to delete a single app
router.delete('/delete-app/:id', async (req, res) => {
  try {
    const appId = req.params.id;
    const indexName = getIndexName();
    
    console.log(`Attempting to delete app with ID: ${appId} from index: ${indexName}`);

    // Delete the document by ID
    const deleteResponse = await esClient.delete({
      index: indexName,
      id: appId
    });

    console.log('Delete response:', deleteResponse);

    res.json({ 
      success: true,
      message: `Successfully deleted app with ID: ${appId}`
    });

  } catch (err) {
    console.error('Error deleting app:', err);
    
    // Handle case where document doesn't exist
    if (err.meta && err.meta.statusCode === 404) {
      return res.status(404).json({ 
        success: false,
        error: 'App not found'
      });
    }

    res.status(500).json({ 
      success: false,
      error: 'Failed to delete app: ' + err.message 
    });
  }
});

module.exports = router;