const express = require('express');
const router = express.Router();

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
      size: 100,
      query: { match_all: {} },
      sort: [{ timestamp: { order: "desc" } }],
    });

    const apps = result.hits.hits.map((hit) => ({
      ...hit._source,
      id: hit._id
    }));

    // Calculate statistics
    const stats = {
      total: apps.length,
      safe: apps.filter(app => app.status === 'safe').length,
      malicious: apps.filter(app => app.status === 'malicious').length,
      suspicious: apps.filter(app => app.status === 'suspicious').length,
      unknown: apps.filter(app => app.status === 'unknown' || !app.status).length,
    };

    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Android Malware Detection Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0f1c 0%, #1a1f3a 50%, #0d1421 100%);
            color: #e1e8f0;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 20px;
        }

        h1 {
            color: #60a5fa;
            font-size: 28px;
            font-weight: 700;
            text-shadow: 0 2px 10px rgba(96, 165, 250, 0.3);
        }

        .subtitle {
            color: #94a3b8;
            font-size: 16px;
            margin-top: 5px;
        }

        .current-index {
            color: #60a5fa;
            font-size: 14px;
            margin-top: 10px;
        }

        .date-selector {
            margin: 20px 0;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
        }

        .date-selector label {
            color: #94a3b8;
        }

        .date-selector input {
            background: rgba(15, 25, 50, 0.8);
            border: 1px solid #1e3a8a;
            border-radius: 8px;
            padding: 8px 12px;
            color: #e1e8f0;
            cursor: pointer;
        }

        .stats-grid {
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 30px;
        }

        .stat-card {
            background: rgba(15, 25, 50, 0.8);
            border: 1px solid #1e3a8a;
            border-radius: 12px;
            padding: 15px 25px;
            text-align: center;
            min-width: 120px;
            transition: all 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(37, 99, 235, 0.2);
            border-color: #2563eb;
        }

        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #60a5fa;
        }

        .stat-label {
            color: #94a3b8;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0 10px;
        }

        th {
            background: rgba(15, 25, 50, 0.9);
            padding: 12px;
            text-align: left;
            color: #94a3b8;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 2px solid #2563eb;
        }

        td {
            background: rgba(15, 25, 50, 0.8);
            padding: 12px;
            vertical-align: top;
            border: 1px solid #1e3a8a;
        }

        td:first-child {
            border-top-left-radius: 8px;
            border-bottom-left-radius: 8px;
        }

        td:last-child {
            border-top-right-radius: 8px;
            border-bottom-right-radius: 8px;
        }

        .app-name {
            font-weight: 600;
            color: #60a5fa;
        }

        .status-badge {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
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

        .action-btn {
            background: linear-gradient(45deg, #2563eb, #3b82f6);
            border: none;
            border-radius: 6px;
            padding: 6px 12px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            margin-right: 5px;
            transition: all 0.3s ease;
        }

        .action-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 3px 10px rgba(37, 99, 235, 0.3);
        }

        .action-btn.secondary {
            background: linear-gradient(45deg, #10b981, #34d399);
        }

        .action-btn.danger {
            background: linear-gradient(45deg, #ef4444, #f56565);
        }

        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }

        .modal-content {
            background: rgba(15, 25, 50, 0.95);
            border: 1px solid #2563eb;
            border-radius: 12px;
            padding: 25px;
            max-width: 700px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 10px 30px rgba(37, 99, 235, 0.3);
        }

        .modal-content h2 {
            color: #60a5fa;
            margin-bottom: 15px;
            border-bottom: 1px solid #1e3a8a;
            padding-bottom: 10px;
        }

        .modal-content p {
            margin: 8px 0;
            font-size: 14px;
        }

        .modal-content strong {
            color: #94a3b8;
        }

        .modal-content ul {
            list-style-type: disc;
            padding-left: 20px;
            margin: 10px 0;
        }

        .modal-content li {
            margin: 5px 0;
            color: #ef4444;
        }

        .close-btn {
            background: #ef4444;
            border: none;
            color: white;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            margin-top: 20px;
            float: right;
        }

        .no-data {
            text-align: center;
            padding: 40px;
            color: #94a3b8;
            font-size: 18px;
        }

        @media (max-width: 768px) {
            table {
                font-size: 12px;
            }
            th, td {
                padding: 8px;
            }
            .stats-grid {
                gap: 10px;
            }
            .stat-card {
                min-width: 100px;
                padding: 10px 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>All Scanned Apps</h1>
            <div class="subtitle">Android Malware Detection System</div>
            <div class="current-index">Current Index: ${indexName}</div>
        </div>

        <div class="date-selector">
            <label for="dateSelect">Select Date Index:</label>
            <input type="date" id="dateSelect" value="${currentDate}" onchange="changeDate(this.value)">
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">${stats.total}</div>
                <div class="stat-label">Total Apps</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.malicious}</div>
                <div class="stat-label">Malicious</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.safe}</div>
                <div class="stat-label">Safe</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.suspicious}</div>
                <div class="stat-label">Suspicious</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.unknown}</div>
                <div class="stat-label">Unknown</div>
            </div>
        </div>

        ${apps.length === 0 ? `
        <div class="no-data">
            No apps found in index: ${indexName}
        </div>
        ` : `
        <table>
            <thead>
                <tr>
                    <th>App Details</th>
                    <th>Package Info</th>
                    <th>File Information</th>
                    <th>Status & Analysis</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${apps.map(app => `
                <tr>
                    <td>
                        <div class="app-name">${app.appName || 'Unknown App'}</div>
                        Uploaded: ${new Date(app.timestamp).toLocaleString()}<br>
                        Source: ${app.source || 'Unknown'}
                    </td>
                    <td>
                        ${app.packageName || 'unknown.package'}
                    </td>
                    <td>
                        Size: ${app.sizeMB ? app.sizeMB.toFixed(2) + ' MB' : 'Unknown'}<br>
                        SHA256: ${app.sha256 ? app.sha256.substring(0, 8) + '...' + app.sha256.substring(app.sha256.length - 8) : 'N/A'}
                    </td>
                    <td>
                        <span class="status-badge status-${app.status || 'unknown'}">${app.status || 'Unknown'}</span><br>
                        Detection: ${app.detectionRatio || 'N/A'}<br>
                        Scanned: ${app.scanTime ? new Date(app.scanTime).toLocaleString() : 'N/A'}
                    </td>
                    <td>
                        <button class="action-btn" onclick="viewDetails('${app.id}')">View Details</button>
                        ${app.uploadedByUser ? `
                        <button class="action-btn secondary">Download APK</button>
                        <button class="action-btn danger">Delete</button>
                        ` : ''}
                    </td>
                </tr>
                `).join('')}
            </tbody>
        </table>
        `}

    </div>

    <div id="detailsModal" class="modal">
        <div class="modal-content" id="modalContent">
            <!-- Details will be inserted here -->
        </div>
    </div>

    <script>
        const appsData = ${JSON.stringify(apps)};

        function changeDate(date) {
            location.href = '/dashboard?date=' + date;
        }

        function viewDetails(id) {
            const app = appsData.find(a => a.id === id);
            if (app) {
                let permissions = [];
                for (let i = 1; i <= 18; i++) {
                    const perm = app['dangerousPermission' + i];
                    if (perm) permissions.push(perm);
                }

                const html = '<h2>' + (app.appName || 'Unknown App') + '</h2>' +
                    '<p><strong>Package Name:</strong> ' + (app.packageName || 'N/A') + '</p>' +
                    '<p><strong>SHA256:</strong> ' + (app.sha256 || 'N/A') + '</p>' +
                    '<p><strong>Size:</strong> ' + (app.sizeMB ? app.sizeMB.toFixed(2) + ' MB' : 'N/A') + '</p>' +
                    '<p><strong>Source:</strong> ' + (app.source || 'N/A') + '</p>' +
                    '<p><strong>Status:</strong> <span class="status-badge status-' + (app.status || 'unknown') + '">' + (app.status || 'Unknown') + '</span></p>' +
                    '<p><strong>Detection Ratio:</strong> ' + (app.detectionRatio || 'N/A') + '</p>' +
                    '<p><strong>Total Engines:</strong> ' + (app.totalEngines || 'N/A') + '</p>' +
                    '<p><strong>Detected Engines:</strong> ' + (app.detectedEngines || 'N/A') + '</p>' +
                    '<p><strong>Scan Time:</strong> ' + (app.scanTime ? new Date(app.scanTime).toLocaleString() : 'N/A') + '</p>' +
                    '<p><strong>Timestamp:</strong> ' + (app.timestamp ? new Date(app.timestamp).toLocaleString() : 'N/A') + '</p>' +
                    '<p><strong>Uploaded by User:</strong> ' + (app.uploadedByUser ? 'Yes' : 'No') + '</p>' +
                    '<h3>Dangerous Permissions (' + permissions.length + '):</h3>' +
                    '<ul>' + permissions.map(perm => '<li>' + perm + '</li>').join('') + '</ul>' +
                    '<button class="close-btn" onclick="closeModal()">Close</button>';
                    
                document.getElementById('modalContent').innerHTML = html;
                document.getElementById('detailsModal').style.display = 'flex';
            }
        }

        function closeModal() {
            document.getElementById('detailsModal').style.display = 'none';
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
      <body style="background: #0d1421; color: #ef4444; font-family: Arial; text-align: center; padding: 50px;">
        <h1>🚨 Dashboard Error</h1>
        <p>Failed to load apps data: ${err.message}</p>
        <p>Index: ${indexName}</p>
        <button onclick="location.reload()" style="background: #2563eb; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer;">
          Try Again
        </button>
      </body>
      </html>
    `);
  }
});

module.exports = router;