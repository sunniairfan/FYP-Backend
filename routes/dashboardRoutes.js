const express = require('express');
const router = express.Router();
const { esClient } = require('../elasticsearch');
const { requireAdminSession } = require('../middleware/authAccess');

// Helper function to get dynamic index name
const getIndexName = () => {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, '0');
  const month = String(today.getMonth() + 1).padStart(2, '0');
  const year = today.getFullYear();
  return `mobile_apps_${day}-${month}-${year}`;
};

// Dashboard route
router.get('/', requireAdminSession, async (req, res) => {  // Changed from '/dashboard' to '/'
  const esClient = req.app.get('esClient');
  const username = req.session?.user?.name || req.jwtUser?.name || 'User';
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
      
      // Extract ML Prediction data
      const mlPredictionData = {
        mlPredictionScore: app.mlPredictionScore || null,
        mlPredictionLabel: app.mlPredictionLabel || null,
        mlAnalysisTimestamp: app.mlAnalysisTimestamp || null
      };
      
      const mappedApp = {
        ...app,
        _id: hit._id,
        id: hit._id,
        // Map VirusTotal data to flat properties for easy access
        detectionRatio: virusTotalData.detectionRatio || 'N/A',
        totalEngines: virusTotalData.totalEngines || 'N/A',
        detectedEngines: virusTotalData.detectedEngines || 'N/A',
        scanTime: virusTotalData.scanTime || app.scanTime || null,
        // Device information
        scan_time: app.scan_time || null,
        device_id: app.device_id || null,
        device_model: app.device_model || null,
        // Map ML Prediction data
        mlPredictionScore: mlPredictionData.mlPredictionScore,
        mlPredictionLabel: mlPredictionData.mlPredictionLabel,
        mlAnalysisTimestamp: mlPredictionData.mlAnalysisTimestamp,
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

        const escapeHtmlAttr = (value) => String(value)
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        const deviceIds = Array.from(new Set(
            apps
                .map(app => (app.device_id == null ? '' : String(app.device_id).trim()))
                .filter(Boolean)
        )).sort((a, b) => a.localeCompare(b));

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
            background: #05090f;
            color: #94a3b8;
            min-height: 100vh;
            display: flex;
        }

        /* Sidebar styles */
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
            color: #94a3b8;
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

        /* Main content styles */
        .main-content {
            margin-left: 0;
            flex: 1;
            padding: 0;
            width: 100%;
            transition: margin-left 0.3s ease;
        }

        .sidebar.open ~ .main-content {
            margin-left: 240px;
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
            background: rgba(0, 0, 0, 0.7);
            z-index: 999;
            backdrop-filter: blur(2px);
        }

        .overlay.show {
            display: block;
        }
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
            background: #0b1120;
            padding: 8px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #1a2332;
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
            background: #0b1120;
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
            background: #3a3a3a;
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

        .date-selector select {
            background: transparent;
            border: none;
            color: #94a3b8;
            padding: 5px;
            font-size: 14px;
            min-width: 170px;
            appearance: none;
            cursor: pointer;
        }

        .date-selector select option {
            background: #112240;
            color: #e2e8f0;
        }

        .date-selector input:focus {
            outline: none;
        }

        .date-selector select:focus {
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
            background: #112240;
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
            background: #1d3557;
            border-color: #3b82f6;
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
            background: #112240;
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
            grid-template-columns: 1.45fr 1.45fr 1.35fr 1.25fr 1fr;
            padding: 10px 15px;
            background: #1d3557;
            border: 1px solid #1d3557;
            border-radius: 8px 8px 0 0;
            margin-top: 20px;
            gap: 10px;
        }

        .table-header div {
            color: #e2e8f0;
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.7px;
            font-family: 'Segoe UI', 'Roboto', sans-serif;
        }

        .app-list {
            display: flex;
            flex-direction: column;
        }

        .app-row {
            display: grid;
            grid-template-columns: 1.45fr 1.45fr 1.35fr 1.25fr 1fr;
            padding: 12px 15px;
            background: #1d3557;
            border: 1px solid #1d3557;
            border-top: none;
            align-items: center;
            transition: all 0.3s;
            gap: 10px;
        }

        .app-row > div {
            min-width: 0;
            overflow: hidden;
            padding-right: 8px;
        }

        .app-row:last-child {
            border-radius: 0 0 8px 8px;
        }

        .app-row:hover {
            background: #2a4a7f;
            border-color: #3b82f6;
        }

        .app-name {
            color: #e2e8f0;
            font-weight: 600;
            font-size: 15px;
            margin-bottom: 4px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .app-meta {
            color: #cbd5e1;
            font-size: 13px;
            line-height: 1.4;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            word-break: break-word;
        }

        .status-badge {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            display: inline-block;
            white-space: nowrap;
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
            gap: 8px;
            align-items: center;
            justify-content: flex-start;
            width: 100%;
            min-width: 0;
            overflow: hidden;
        }

        .view-btn {
            background: #2563eb;
            border: none;
            color: white;
            padding: 8px 14px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.3s;
            white-space: nowrap;
            flex-shrink: 0;
        }

        .view-btn:hover {
            background: #1e40af;
        }

        .delete-icon {
            width: 32px;
            height: 32px;
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
            flex-shrink: 0;
        }

        .status-analysis-cell {
            min-width: 0;
            padding-right: 6px;
            overflow: hidden;
        }

        .ml-model-badge {
            margin-top: 6px;
            padding: 5px 8px;
            background: rgba(99, 102, 241, 0.12);
            border: 1px solid rgba(99, 102, 241, 0.35);
            border-radius: 5px;
            color: #8b93ff;
            font-size: 12px;
            font-weight: 600;
            line-height: 1.35;
            display: inline-block;
            max-width: 100%;
            white-space: normal;
            overflow-wrap: break-word;
            word-break: break-word;
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
            background: rgba(0, 0, 0, 0.85);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
            padding: 20px;
            backdrop-filter: blur(4px);
        }

        .modal-content {
            background: #0b1120;
            border: 1px solid #1d3557;
            border-radius: 16px;
            padding: 36px 40px;
            max-width: 780px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: 0 24px 60px rgba(0, 0, 0, 0.7);
        }

        .modal-content::-webkit-scrollbar {
            width: 6px;
        }
        .modal-content::-webkit-scrollbar-track {
            background: #0b1120;
        }
        .modal-content::-webkit-scrollbar-thumb {
            background: #1d3557;
            border-radius: 3px;
        }

        .modal-content h2 {
            color: white;
            margin-bottom: 24px;
            font-size: 22px;
            font-weight: 700;
            letter-spacing: 0.4px;
        }

        .modal-content h3 {
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.8px;
            text-transform: uppercase;
        }

        .detail-row {
            display: flex;
            padding: 13px 0;
            border-bottom: 1px solid rgba(29, 53, 87, 0.7);
            gap: 16px;
        }

        .detail-label {
            color: #64748b;
            font-size: 13px;
            min-width: 170px;
            font-weight: 600;
            padding-top: 1px;
            flex-shrink: 0;
            letter-spacing: 0.2px;
        }

        .detail-value {
            color: #e2e8f0;
            font-size: 14px;
            flex: 1;
            word-break: break-word;
            line-height: 1.55;
            font-weight: 400;
        }

        .permissions-list {
            list-style: none;
            padding: 0;
            margin: 10px 0 0 0;
        }

        .permissions-list li {
            padding: 8px 12px;
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(127, 29, 29, 0.6);
            border-radius: 6px;
            margin-bottom: 5px;
            color: #fca5a5;
            font-size: 12px;
            line-height: 1.4;
        }

        .close-btn {
            background: #2563eb;
            border: none;
            color: white;
            padding: 11px 28px;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 24px;
            font-weight: 600;
            font-size: 14px;
            float: right;
            transition: background 0.2s;
        }

        .close-btn:hover {
            background: #1e40af;
        }

        :root {
            --theme-bg: #05090f;
            --theme-surface: #0b1120;
            --theme-surface-soft: #112240;
            --theme-border: #1a2332;
            --theme-border-strong: #1d3557;
            --theme-text: #e2e8f0;
            --theme-text-secondary: #94a3b8;
            --theme-text-muted: #64748b;
        }

        body {
            background: var(--theme-bg);
            color: var(--theme-text-secondary);
        }

        .sidebar,
        .top-bar,
        .notification-panel,
        .modal-content,
        .app-type-stats,
        .table-header,
        .app-row,
        .date-selector,
        .stat-card {
            background: var(--theme-surface);
            border-color: var(--theme-border);
        }

        .app-row:hover,
        .app-type-filter button:hover,
        .date-selector input:focus,
        .date-selector select:focus {
            background: var(--theme-surface-soft);
            border-color: var(--theme-border-strong);
        }

        .app-name,
        .table-header div,
        .modal-content h2 {
            color: var(--theme-text);
        }

        .detail-label,
        .notification-message,
        .nav-section-title,
        .date-selector i,
        .search-icon {
            color: var(--theme-text-muted);
        }

        .app-meta {
            color: #cbd5e1;
        }

        .detail-value,
        .nav-item,
        .menu-btn,
        .date-selector input,
        .date-selector select {
            color: var(--theme-text-secondary);
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
    <div class="sidebar" id="sidebar">
        <div class="logo">
            <div class="logo-icon">
                <i class="fas fa-shield-alt"></i>
            </div>
            <span>CYBER WOLF</span>
        </div>
        
        <div class="nav-section-title">NAVIGATION</div>
        <a href="/" class="nav-item">
            <i class="fas fa-home nav-icon"></i>
            <span>Home</span>
        </a>
        <a href="/dashboard" class="nav-item active">
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

    <!-- Overlay for closing sidebar -->
    <div class="overlay" id="overlay"></div>

    <!-- Main Content -->
    <div class="main-content">
        <div class="top-bar">
            <button class="menu-btn" id="menuBtn">
                <i class="fas fa-bars"></i>
            </button>
            <div class="top-actions">
                <button class="notification-bell" id="notificationBell" aria-label="Notifications">
                    <i class="fas fa-bell"></i>
                    <span class="notification-badge" id="notificationBadge">0</span>
                </button>
                <div class="user-info">
                    <div class="user-avatar">${username.charAt(0).toUpperCase()}</div>
                    <span>${username}</span>
                </div>
            </div>
        </div>

        <div class="notification-panel" id="notificationPanel"></div>
        <div class="notification-popup" id="notificationPopup">
            <div class="popup-title">High malware detection</div>
            <div class="popup-body" id="popupBody">A high-risk app was detected. Uninstall recommended.</div>
            <button class="popup-close" id="popupClose">Close</button>
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
                <div class="date-selector">
                    <i class="fas fa-mobile-alt" style="color: #64748b;"></i>
                    <select id="deviceIdFilter" onchange="filterByDeviceId()">
                        <option value="all">All Devices</option>
                        ${deviceIds.map(deviceId => `<option value="${escapeHtmlAttr(deviceId)}">${deviceId}</option>`).join('')}
                    </select>
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
                        <div class="app-row user-app" data-app-type="user" data-device-id="${escapeHtmlAttr(app.device_id || '')}">
                            <div>
                                <div class="app-name">${app.appName || 'Unknown'}</div>
                                <div class="app-meta">Uploaded: ${new Date(app.uploadedAt || app.timestamp).toLocaleDateString()}</div>
                            </div>
                            <div>
                                <div class="app-meta">Package: ${app.packageName || 'N/A'}</div>
                                <div class="app-meta">Device: ${app.device_id || 'N/A'}</div>
                            </div>
                            <div>
                                <div class="app-meta">Size: ${app.sizeMB ? app.sizeMB.toFixed(2) + ' MB' : (app.fileSize ? (app.fileSize / (1024 * 1024)).toFixed(2) + ' MB' : 'N/A')}</div>
                                <div class="app-meta">Hash: ${app.sha256 ? app.sha256.substring(0, 16) + '...' : 'N/A'}</div>
                            </div>
                                                        <div class="status-analysis-cell">
                                <span class="status-badge status-${app.uploadedByUser ? 'uploaded' : (app.status?.toLowerCase() || 'unknown')}">${app.uploadedByUser ? 'Uploaded' : (app.status || 'Unknown')}</span>
                                <div class="app-meta" style="margin-top: 5px;">Score: ${app.mobsfAnalysis?.security_score || app.virusTotalHashCheck?.detectionRatio || app.virusTotalAnalysis?.detectionRatio || 'N/A'}</div>
                                ${app.mlPredictionScore !== undefined && app.mlPredictionScore !== null && app.status !== 'safe' ? `
                                                                    <div class="ml-model-badge">
                                    🤖 ML Model: ${app.mlPredictionLabel} (${(app.mlPredictionScore ?? 0).toFixed(3)})
                                  </div>
                                ` : ""}
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
                        <div class="app-row system-app hidden" data-app-type="system" data-device-id="${escapeHtmlAttr(app.device_id || '')}">
                            <div>
                                <div class="app-name">${app.appName || 'Unknown'}</div>
                                <div class="app-meta">Uploaded: ${new Date(app.uploadedAt || app.timestamp).toLocaleDateString()}</div>
                            </div>
                            <div>
                                <div class="app-meta">Package: ${app.packageName || 'N/A'}</div>
                                <div class="app-meta">Device: ${app.device_id || 'N/A'}</div>
                            </div>
                            <div>
                                <div class="app-meta">Size: ${app.sizeMB ? app.sizeMB.toFixed(2) + ' MB' : (app.fileSize ? (app.fileSize / (1024 * 1024)).toFixed(2) + ' MB' : 'N/A')}</div>
                                <div class="app-meta">Hash: ${app.sha256 ? app.sha256.substring(0, 16) + '...' : 'N/A'}</div>
                            </div>
                                                        <div class="status-analysis-cell">
                                <span class="status-badge status-${app.uploadedByUser ? 'uploaded' : (app.status?.toLowerCase() || 'unknown')}">${app.uploadedByUser ? 'Uploaded' : (app.status || 'Unknown')}</span>
                                <div class="app-meta" style="margin-top: 5px;">Score: ${app.mobsfAnalysis?.security_score || app.virusTotalHashCheck?.detectionRatio || app.virusTotalAnalysis?.detectionRatio || 'N/A'}</div>
                                ${app.mlPredictionScore !== undefined && app.mlPredictionScore !== null && app.status !== 'safe' ? `
                                                                    <div class="ml-model-badge">
                                    🤖 ML Model: ${app.mlPredictionLabel} (${(app.mlPredictionScore ?? 0).toFixed(3)})
                                  </div>
                                ` : ""}
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

        const notificationBell = document.getElementById('notificationBell');
        const notificationBadge = document.getElementById('notificationBadge');
        const notificationPanel = document.getElementById('notificationPanel');
        const notificationPopup = document.getElementById('notificationPopup');
        const popupBody = document.getElementById('popupBody');
        const popupClose = document.getElementById('popupClose');

        const dismissedKey = 'dismissedNotifications';
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

        // Filter apps by date
        document.getElementById('dateFilter').addEventListener('change', function() {
            const selectedDate = this.value;
            window.location.href = '/dashboard?date=' + selectedDate;
        });

        let currentAppType = 'user';
        let currentDeviceId = 'all';

        function applyCombinedFilters() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase().trim();
            const appRows = document.querySelectorAll('.app-row');

            appRows.forEach(row => {
                const rowAppType = row.getAttribute('data-app-type');
                const rowDeviceId = row.getAttribute('data-device-id') || '';
                const appName = row.querySelector('.app-name')?.textContent.toLowerCase() || '';

                const matchesType = rowAppType === currentAppType;
                const matchesDevice = currentDeviceId === 'all' || rowDeviceId === currentDeviceId;
                const matchesSearch = appName.includes(searchTerm);
                const shouldShow = matchesType && matchesDevice && matchesSearch;

                row.classList.toggle('hidden', !matchesType);
                row.style.display = shouldShow ? '' : 'none';
            });
        }

        // Filter apps by type (User/System)
        function filterByAppType(appType) {
            currentAppType = appType;

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

            applyCombinedFilters();
        }

        function filterByDeviceId() {
            currentDeviceId = document.getElementById('deviceIdFilter').value || 'all';
            applyCombinedFilters();
        }

        // Search apps by name (works with current filter)
        function searchApps() {
            applyCombinedFilters();
        }

        // Show app details in modal
        function showDetails(app) {
            const modal = document.getElementById('detailsModal');
            const detailsDiv = document.getElementById('modalDetails');
            const formatDate = (value) => {
                if (!value) return 'N/A';
                const dt = new Date(value);
                return Number.isNaN(dt.getTime()) ? 'N/A' : dt.toLocaleString();
            };
            const toNumberOrNull = (value) => {
                if (value === undefined || value === null || value === '') return null;
                const num = Number(value);
                return Number.isFinite(num) ? num : null;
            };
            const vtData = app.virusTotalHashCheck || app.virusTotalAnalysis || {};
            const hasVtData = Object.keys(vtData).length > 0;
            const detectedEngines = toNumberOrNull(vtData.detectedEngines ?? app.detectedEngines);
            const totalEngines = toNumberOrNull(vtData.totalEngines ?? app.totalEngines);
            const mlScore = toNumberOrNull(app.mlPredictionScore);
            const riskyPermissionCount = Object.keys(app)
                .filter((key) => key.startsWith('dangerousPermission') && app[key])
                .length;
            const mobsfDangerousPermissionCount = Array.isArray(app.mobsfAnalysis?.dangerous_permissions)
                ? app.mobsfAnalysis.dangerous_permissions.length
                : 0;
            const effectiveDangerousPermissionCount = Math.max(riskyPermissionCount, mobsfDangerousPermissionCount);
            const highRiskFindings = toNumberOrNull(app.mobsfAnalysis?.high_risk_findings) ?? 0;
            const totalManifestFindings = toNumberOrNull(app.mobsfAnalysis?.dynamic_analysis?.total_manifest_findings) ?? 0;
            const totalNetworkFindings = toNumberOrNull(app.mobsfAnalysis?.dynamic_analysis?.total_network_findings) ?? 0;
            
            let html = '<div style="display: grid; gap: 15px;">';
            
            // Basic App Information
            html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-bottom: 10px;">Basic Information</h3>';
            html += '<div class="detail-row"><div class="detail-label">App Name:</div><div class="detail-value">' + (app.appName || 'N/A') + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Package Name:</div><div class="detail-value">' + (app.packageName || 'N/A') + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">App Type:</div><div class="detail-value">' + (app.appType || 'N/A') + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Size:</div><div class="detail-value">' + (app.fileSize ? (app.fileSize / (1024 * 1024)).toFixed(2) + ' MB' : (app.sizeMB ? app.sizeMB.toFixed(2) + ' MB' : 'N/A')) + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Source:</div><div class="detail-value">' + (app.source || app.uploadSource || 'N/A') + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Uploaded By User:</div><div class="detail-value">' + (app.uploadedByUser ? 'Yes' : 'No') + '</div></div>';
            html += '<div class="detail-row"><div class="detail-label">Upload ID:</div><div class="detail-value">' + (app.uploadId || 'N/A') + '</div></div>';
            
            // File Hashes
            html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">File Hashes</h3>';
            html += '<div class="detail-row"><div class="detail-label">SHA-256:</div><div class="detail-value" style="word-break: break-all; font-family: monospace; font-size: 11px;">' + (app.sha256 || 'N/A') + '</div></div>';

            if (app.device_id || app.device_model || app.scan_time) {
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Device Context</h3>';
                html += '<div class="detail-row"><div class="detail-label">Device ID:</div><div class="detail-value">' + (app.device_id || 'N/A') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Device Model:</div><div class="detail-value">' + (app.device_model || 'N/A') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Device Scan Time:</div><div class="detail-value">' + formatDate(app.scan_time) + '</div></div>';
            }
            
            // Status Information
            html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Security Status</h3>';
            const displayStatus = app.uploadedByUser ? 'Uploaded' : (app.status || 'Unknown');
            const statusClass = app.uploadedByUser ? 'uploaded' : (app.status?.toLowerCase() || 'unknown');
            html += '<div class="detail-row"><div class="detail-label">Overall Status:</div><div class="detail-value"><span class="status-badge status-' + statusClass + '">' + displayStatus + '</span></div></div>';
            
            // Multi-Engine Analysis (VirusTotal)
            if (hasVtData) {
                const malCount   = vtData.maliciousCount   ?? null;
                const suspCount  = vtData.suspiciousCount  ?? null;
                const harmCount  = vtData.harmlessCount    ?? null;
                const undetCount = vtData.undetectedCount  ?? null;
                const scoreColor = (detectedEngines !== null && totalEngines !== null && totalEngines > 0)
                    ? (detectedEngines === 0 ? '#10b981' : detectedEngines <= 2 ? '#f59e0b' : '#ef4444')
                    : '#94a3b8';
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Multi-Engine Analysis</h3>';
                html += '<div class="detail-row"><div class="detail-label">Detection Ratio:</div><div class="detail-value"><strong style="font-size:16px;color:' + scoreColor + ';">' + (vtData.detectionRatio || app.detectionRatio || 'N/A') + '</strong></div></div>';
                if (malCount !== null)   html += '<div class="detail-row"><div class="detail-label">Malicious Engines:</div><div class="detail-value" style="color:' + (malCount > 0 ? '#ef4444' : '#10b981') + ';">' + malCount + '</div></div>';
                if (suspCount !== null)  html += '<div class="detail-row"><div class="detail-label">Suspicious Engines:</div><div class="detail-value" style="color:' + (suspCount > 0 ? '#f59e0b' : '#10b981') + ';">' + suspCount + '</div></div>';
                if (harmCount !== null)  html += '<div class="detail-row"><div class="detail-label">Clean / Harmless:</div><div class="detail-value" style="color:#10b981;">' + harmCount + '</div></div>';
                if (undetCount !== null) html += '<div class="detail-row"><div class="detail-label">Undetected:</div><div class="detail-value" style="color:#94a3b8;">' + undetCount + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Total Engines:</div><div class="detail-value">' + (vtData.totalEngines || app.totalEngines || 'N/A') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Scan Time:</div><div class="detail-value">' + formatDate(vtData.scanTime || app.scanTime) + '</div></div>';
            }

            // Static Analysis (MobSF)
            if (app.mobsfAnalysis) {
                const ms = app.mobsfAnalysis;
                const ssColor = ms.security_score >= 70 ? '#10b981' : ms.security_score < 40 ? '#ef4444' : '#f59e0b';
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Static Analysis</h3>';
                html += '<div class="detail-row"><div class="detail-label">Security Score:</div><div class="detail-value"><strong style="font-size:18px;color:' + ssColor + ';">' + (ms.security_score ?? 'N/A') + '/100</strong></div></div>';
                html += '<div class="detail-row"><div class="detail-label">Scan Type:</div><div class="detail-value">' + (ms.scan_type || app.mobsfScanType || 'N/A') + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">High Risk Findings:</div><div class="detail-value" style="color:' + (highRiskFindings > 0 ? '#ef4444' : '#10b981') + ';">' + highRiskFindings + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Manifest Findings:</div><div class="detail-value">' + totalManifestFindings + ' total &mdash; High: <span style="color:' + (ms.dynamic_analysis?.high_manifest_issues > 0 ? '#ef4444' : '#10b981') + ';">' + (ms.dynamic_analysis?.high_manifest_issues ?? 0) + '</span>, Warning: ' + (ms.dynamic_analysis?.warn_manifest_issues ?? 0) + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Network Findings:</div><div class="detail-value">' + totalNetworkFindings + ' total &mdash; High: <span style="color:' + (ms.dynamic_analysis?.high_network_issues > 0 ? '#ef4444' : '#10b981') + ';">' + (ms.dynamic_analysis?.high_network_issues ?? 0) + '</span></div></div>';
                html += '<div class="detail-row"><div class="detail-label">Dangerous Permissions:</div><div class="detail-value" style="color:' + (effectiveDangerousPermissionCount > 0 ? '#f59e0b' : '#10b981') + ';">' + effectiveDangerousPermissionCount + '</div></div>';
                if (Array.isArray(ms.dangerous_permissions) && ms.dangerous_permissions.length > 0) {
                    html += '<div class="detail-row"><div class="detail-label">Permission List:</div><div class="detail-value"><ul class="permissions-list">';
                    ms.dangerous_permissions.forEach(p => { html += '<li>' + p + '</li>'; });
                    html += '</ul></div></div>';
                }
            }

            // Dynamic Analysis (runtime)
            const dynData = app.dynamicAnalysis;
            const hasDynamic = dynData && dynData.status === 'completed';
            if (hasDynamic) {
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Dynamic Analysis</h3>';
                html += '<div class="detail-row"><div class="detail-label">Status:</div><div class="detail-value" style="color:#10b981;">Completed</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Trackers Detected:</div><div class="detail-value" style="color:' + (dynData.trackers > 0 ? '#f59e0b' : '#10b981') + ';">' + (dynData.trackers ?? 0) + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Network Security Issues:</div><div class="detail-value" style="color:' + (dynData.network_security_issues > 0 ? '#ef4444' : '#10b981') + ';">' + (dynData.network_security_issues ?? 0) + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Domains Contacted:</div><div class="detail-value">' + (dynData.domains_count ?? 0) + '</div></div>';
                html += '<div class="detail-row"><div class="detail-label">Open Redirects:</div><div class="detail-value" style="color:' + (dynData.open_redirects > 0 ? '#f59e0b' : '#10b981') + ';">' + (dynData.open_redirects ?? 0) + '</div></div>';
                if (dynData.analysisTimestamp) html += '<div class="detail-row"><div class="detail-label">Analysis Time:</div><div class="detail-value">' + formatDate(dynData.analysisTimestamp) + '</div></div>';
            }

            // Weighted Risk Algorithm
            const algoResult = app.algorithmResult;
            if (algoResult && algoResult.finalScore !== undefined) {
                const fsColor = algoResult.finalScore < 30 ? '#10b981' : algoResult.finalScore < 55 ? '#f59e0b' : '#ef4444';
                const stColor = algoResult.finalStatus === 'SAFE' ? '#10b981' : algoResult.finalStatus === 'SUSPICIOUS' ? '#f59e0b' : '#ef4444';
                html += '<h3 style="color: #60a5fa; border-bottom: 1px solid #1d3557; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">Weighted Risk Algorithm</h3>';
                html += '<div class="detail-row"><div class="detail-label">Risk Score:</div><div class="detail-value"><strong style="font-size:20px;color:' + fsColor + ';">' + algoResult.finalScore + '/100</strong></div></div>';
                html += '<div class="detail-row"><div class="detail-label">Risk Status:</div><div class="detail-value"><strong style="color:' + stColor + ';">' + (algoResult.finalStatus || 'N/A') + '</strong></div></div>';
                html += '<div class="detail-row"><div class="detail-label">Confidence:</div><div class="detail-value">' + (algoResult.confidence ?? 'N/A') + '% &nbsp;<span style="color:#64748b;font-size:11px;">(' + (algoResult.dataSourcesCount ?? 0) + '/4 sources)</span></div></div>';
                if (algoResult.finalExplanation) {
                    html += '<div class="detail-row"><div class="detail-label">Summary:</div><div class="detail-value" style="color:#e2e8f0;">' + algoResult.finalExplanation + '</div></div>';
                }
                // Per-source breakdown
                const bk = algoResult.breakdown;
                if (bk && bk.sources) {
                    html += '<div class="detail-row" style="margin-top:8px;"><div class="detail-label">Source Scores:</div><div class="detail-value"><table style="width:100%;border-collapse:collapse;font-size:12px;">' +
                        '<tr style="color:#64748b;"><th style="text-align:left;padding:2px 6px;">Source</th><th style="text-align:center;padding:2px 6px;">Score</th><th style="text-align:center;padding:2px 6px;">Weight</th></tr>';
                    const srcMap = [
                        ['Multi-Engine (VT)', bk.sources.virustotal,   bk.weights?.virustotal],
                        ['Static (MobSF)',    bk.sources.mobsfStatic,  bk.weights?.mobsfStatic],
                        ['Dynamic',          bk.sources.mobsfDynamic, bk.weights?.mobsfDynamic],
                        ['ML Model',         bk.sources.ml,           bk.weights?.ml],
                    ];
                    srcMap.forEach(([name, score, weight]) => {
                        if (score !== null && score !== undefined) {
                            const sc = algoResult.finalScore < 30 ? '#10b981' : algoResult.finalScore < 55 ? '#f59e0b' : '#ef4444';
                            const rowColor = score < 30 ? '#10b981' : score < 55 ? '#f59e0b' : '#ef4444';
                            html += '<tr style="border-top:1px solid #1d3557;">'
                                + '<td style="padding:3px 6px;color:#94a3b8;">' + name + '</td>'
                                + '<td style="padding:3px 6px;text-align:center;color:' + rowColor + ';font-weight:600;">' + score + '</td>'
                                + '<td style="padding:3px 6px;text-align:center;color:#64748b;">' + (weight !== undefined ? Math.round(weight * 100) + '%' : '—') + '</td>'
                                + '</tr>';
                        }
                    });
                    html += '</table></div></div>';
                }
                // Risk factors
                if (Array.isArray(algoResult.riskFactors) && algoResult.riskFactors.length > 0) {
                    html += '<div class="detail-row"><div class="detail-label">Risk Factors:</div><div class="detail-value"><ul class="permissions-list" style="color:#fca5a5;">';
                    algoResult.riskFactors.forEach(f => { html += '<li>' + f + '</li>'; });
                    html += '</ul></div></div>';
                }
                if (Array.isArray(algoResult.positiveFactors) && algoResult.positiveFactors.length > 0) {
                    html += '<div class="detail-row"><div class="detail-label">Positive Factors:</div><div class="detail-value"><ul class="permissions-list" style="color:#6ee7b7;">';
                    algoResult.positiveFactors.forEach(f => { html += '<li>' + f + '</li>'; });
                    html += '</ul></div></div>';
                }
            }

            // ML Prediction Analysis (only shown for non-safe apps)
            if (app.mlPredictionScore !== undefined && app.mlPredictionScore !== null && app.status !== 'safe') {
                html += '<h3 style="color: #6366f1; border-bottom: 1px solid #4f46e5; padding-bottom: 8px; margin-top: 20px; margin-bottom: 10px;">🤖 Machine Learning Model</h3>';
                html += '<div class="detail-row"><div class="detail-label">Prediction Label:</div><div class="detail-value"><strong style="color: #6366f1; font-size: 16px;">' + (app.mlPredictionLabel || 'N/A') + '</strong></div></div>';
                html += '<div class="detail-row"><div class="detail-label">ML Score:</div><div class="detail-value"><strong style="color: #6366f1; font-size: 18px;">' + (app.mlPredictionScore ?? 0).toFixed(3) + '</strong></div></div>';
                if (app.mlAnalysisTimestamp) {
                    html += '<div class="detail-row"><div class="detail-label">Analysis Time:</div><div class="detail-value">' + formatDate(app.mlAnalysisTimestamp) + '</div></div>';
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
            html += '<div class="detail-row"><div class="detail-label">Uploaded:</div><div class="detail-value">' + formatDate(app.uploadedAt || app.timestamp) + '</div></div>';
            if (app.scanTime) {
                html += '<div class="detail-row"><div class="detail-label">Scan Time:</div><div class="detail-value">' + formatDate(app.scanTime) + '</div></div>';
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

        applyCombinedFilters();
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
router.post('/delete-index', requireAdminSession, async (req, res) => {
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
router.delete('/delete-app/:id', requireAdminSession, async (req, res) => {
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


