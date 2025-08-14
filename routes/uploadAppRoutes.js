const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const router = express.Router();

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "../uploads/apks");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for APK file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const uniqueName = `temp_${timestamp}_${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 500 * 1024 * 1024, // 500MB limit
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype === 'application/vnd.android.package-archive' || 
        file.originalname.toLowerCase().endsWith('.apk')) {
      cb(null, true);
    } else {
      console.error("Invalid file type:", file.mimetype);
      cb(new Error('Only APK files are allowed'), false);
    }
  }
});

// Import controller functions
const {
  receiveAppData,
  uploadApp,
  getAppDetails,
  downloadApp,
  deleteApp
} = require("../controllers/appController");

// *** ADD THIS ROUTE - This is what your Android app is calling ***
router.post(
  "/upload",  // This will be accessible at /uploadapp/upload
  upload.single("apk"), // Use single file upload since Android sends one APK file
  (req, res) => {
    // Add debug logging
    console.log(">>> Direct /upload route hit");
    console.log("File received:", req.file ? req.file.filename : "No file");
    console.log("Body:", req.body);
    
    // Call the uploadApp controller
    uploadApp(req, res);
  }
);

// Routes for APK upload and management
router.post(
  "/api/app/upload",
  upload.fields([
    { name: "apk", maxCount: 1 },
    { name: "metadata", maxCount: 1 }
  ]),
  uploadApp
);

// GET /api/app/apps - View uploaded apps (HTML page)
router.get("/apps", async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const result = await esClient.search({
      index: "apps",
      size: 100,
      query: { term: { uploadedByUser: true } },
      sort: [{ timestamp: { order: "desc" } }],
    });

    const apps = result.hits.hits.map((hit) => ({
      ...hit._source,
      id: hit._id
    }));

    let html = `
      <html>
      <head>
        <title>Uploaded Apps - Android Malware Detector</title>
        <style>
          body {
            background-color: #0d1b2a;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          h1 {
            font-size: 2.5rem;
            color: #ffffff;
            margin-bottom: 10px;
          }
          .subtitle {
            color: #778da9;
            font-size: 1.1rem;
          }
          .stats {
            display: flex;
            justify-content: center;
            gap: 30px;
            margin: 20px 0;
          }
          .stat-card {
            background: linear-gradient(135deg, #1b263b, #415a77);
            padding: 15px 25px;
            border-radius: 10px;
            text-align: center;
          }
          .stat-number {
            font-size: 1.8rem;
            font-weight: bold;
            color: #90e0ef;
          }
          .stat-label {
            font-size: 0.9rem;
            color: #cad2c5;
          }
          table {
            width: 100%;
            border-spacing: 0;
            border-collapse: separate;
            border-radius: 12px;
            overflow: hidden;
            background-color: #1b263b;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
          }
          thead {
            background: linear-gradient(135deg, #415a77, #778da9);
          }
          th {
            padding: 18px 15px;
            text-align: left;
            font-size: 1rem;
            font-weight: bold;
            color: white;
          }
          td {
            padding: 15px;
            border-bottom: 1px solid #415a77;
            vertical-align: middle;
          }
          tr:hover {
            background-color: #273b54;
            transition: background-color 0.3s ease;
          }
          tr:last-child td {
            border-bottom: none;
          }
          .status {
            font-weight: bold;
            padding: 8px 12px;
            border-radius: 6px;
            display: inline-block;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }
          .status.unknown {
            background-color: #ffb703;
            color: #1b263b;
          }
          .status.safe {
            background-color: #52b788;
            color: white;
          }
          .status.malicious {
            background-color: #e63946;
            color: white;
          }
          .status.sandbox_submitted {
            background-color: #f77f00;
            color: white;
          }
          button {
            padding: 8px 14px;
            border: none;
            border-radius: 6px;
            color: white;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            margin: 2px;
            font-size: 0.85rem;
          }
          .btn-sandbox {
            background: linear-gradient(135deg, #0077b6, #0096c7);
          }
          .btn-sandbox:hover {
            background: linear-gradient(135deg, #005577, #007bb6);
            transform: translateY(-1px);
          }
          .btn-download {
            background: linear-gradient(135deg, #52b788, #74c69d);
          }
          .btn-download:hover {
            background: linear-gradient(135deg, #40916c, #52b788);
            transform: translateY(-1px);
          }
          .btn-delete {
            background: linear-gradient(135deg, #e63946, #f77f00);
          }
          .btn-delete:hover {
            background: linear-gradient(135deg, #d00000, #e63946);
            transform: translateY(-1px);
          }
          form {
            margin: 0;
            display: inline-block;
          }
          .file-info {
            font-size: 0.85rem;
            color: #cad2c5;
            line-height: 1.4;
          }
          .app-name {
            font-weight: 600;
            color: #90e0ef;
          }
          .package-name {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            color: #778da9;
          }
          .no-apps {
            text-align: center;
            padding: 50px;
            color: #778da9;
            font-size: 1.2rem;
          }
          .permissions {
            font-size: 0.8rem;
            color: #ffb703;
          }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>📱 Uploaded Apps</h1>
          <div class="subtitle">Android Malware Detection System</div>
        </div>
        
        <div class="stats">
          <div class="stat-card">
            <div class="stat-number">${apps.length}</div>
            <div class="stat-label">Total Apps</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${apps.filter(app => app.status === 'malicious').length}</div>
            <div class="stat-label">Malicious</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${apps.filter(app => app.status === 'safe').length}</div>
            <div class="stat-label">Safe</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${apps.filter(app => app.status === 'unknown').length}</div>
            <div class="stat-label">Unknown</div>
          </div>
        </div>
    `;

    if (apps.length === 0) {
      html += `
        <div class="no-apps">
          <p>No apps uploaded yet.</p>
          <p>Upload apps using the Android application to see them here.</p>
        </div>
      `;
    } else {
      html += `
        <table>
          <thead>
            <tr>
              <th>App Details</th>
              <th>Package Info</th>
              <th>File Information</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
      `;

      apps.forEach((app) => {
        const fileInfo = app.apkFileName ? `${app.apkFileName}` : 'No file uploaded';
        const uploadDate = new Date(app.timestamp).toLocaleDateString();
        const permissionCount = app.permissions ? app.permissions.length : 0;
        
        html += `
          <tr>
            <td>
              <div class="app-name">${app.appName || "Unknown App"}</div>
              <div class="file-info">Uploaded: ${uploadDate}</div>
              ${app.source ? `<div class="file-info">Source: ${app.source}</div>` : ''}
            </td>
            <td>
              <div class="package-name">${app.packageName}</div>
              ${permissionCount > 0 ? `<div class="permissions">${permissionCount} permissions</div>` : ''}
            </td>
            <td>
              <div class="file-info">${fileInfo}</div>
              <div class="file-info">Size: ${app.sizeMB?.toFixed(2) || 0} MB</div>
              ${app.sha256 ? `<div class="file-info" title="${app.sha256}">SHA-256: ${app.sha256.substring(0, 16)}...</div>` : ''}
            </td>
            <td>
              <span class="status ${app.status || "unknown"}">
                ${app.status || "unknown"}
              </span>
            </td>
            <td>
              <form method="POST" action="/api/app/apps/${app.sha256}/upload-sandbox">
                <button type="submit" class="btn-sandbox">Upload to Sandbox</button>
              </form>
              ${app.apkFileName ? `
                <button onclick="downloadFile('${app.apkFileName}')" class="btn-download">
                  Download APK
                </button>
              ` : ''}
              <button onclick="deleteApp('${app.sha256}', '${app.packageName}')" class="btn-delete">
                Delete
              </button>
            </td>
          </tr>
        `;
      });

      html += `
            </tbody>
          </table>
      `;
    }

    html += `
        <script>
          function downloadFile(fileName) {
            window.location.href = '/api/app/download/' + encodeURIComponent(fileName);
          }
          
          function deleteApp(sha256, packageName) {
            if (confirm('Are you sure you want to delete "' + packageName + '"? This will also delete the APK file.')) {
              fetch('/api/app/delete/' + sha256, { method: 'DELETE' })
                .then(response => response.json())
                .then(data => {
                  if (data.error) {
                    alert('Error: ' + data.error);
                  } else {
                    alert('App deleted successfully');
                    location.reload();
                  }
                })
                .catch(error => {
                  alert('Error: ' + error.message);
                });
            }
          }
        </script>
      </body>
      </html>
    `;

    res.send(html);
  } catch (err) {
    console.error("Failed to fetch apps for upload app page:", err.message);
    res.status(500).send(`
      <html>
      <body style="background: #0d1b2a; color: white; font-family: Arial; text-align: center; padding: 50px;">
        <h1>Error Loading Apps</h1>
        <p>${err.message}</p>
      </body>
      </html>
    `);
  }
});

// POST /api/app/apps/:sha256/upload-sandbox - Upload to sandbox
router.post("/apps/:sha256/upload-sandbox", async (req, res) => {
  const sha256 = req.params.sha256;
  const esClient = req.app.get("esClient");

  try {
    const searchRes = await esClient.search({
      index: "apps",
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      console.error(`App not found for SHA256: ${sha256}`);
      return res.status(404).send("App not found");
    }

    const docId = searchRes.hits.hits[0]._id;
    const appData = searchRes.hits.hits[0]._source;

    // Placeholder for MobSF sandbox upload logic
    console.log(`📤 Uploading to sandbox: ${appData.apkFilePath}`);

    await esClient.update({
      index: "apps",
      id: docId,
      body: {
        doc: {
          status: "sandbox_submitted",
          uploadedByUser: true,
          timestamp: new Date(),
        },
      },
    });

    console.log(`✅ Marked app ${sha256} as sandbox_submitted`);
    res.redirect("/api/app/apps");
  } catch (err) {
    console.error(`Failed to submit app ${sha256} to sandbox:`, err.message);
    res.status(500).send("Failed to submit to sandbox");
  }
});

// GET /api/app/list - Get apps as JSON (API endpoint)
router.get("/list", async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const result = await esClient.search({
      index: "apps",
      size: 100,
      query: { term: { uploadedByUser: true } },
      sort: [{ timestamp: { order: "desc" } }],
    });

    const apps = result.hits.hits.map((hit) => ({
      id: hit._id,
      ...hit._source
    }));

    res.status(200).json({
      total: apps.length,
      apps: apps
    });
  } catch (err) {
    console.error("Failed to fetch apps:", err.message);
    res.status(500).json({ error: "Failed to fetch apps" });
  }
});

// GET /api/app/details/:identifier - Get app details
router.get("/details/:identifier", getAppDetails);

// GET /api/app/download/:fileName - Download APK file
router.get("/download/:fileName", downloadApp);

// DELETE /api/app/delete/:sha256 - Delete app and APK file
router.delete("/delete/:sha256", deleteApp);

// POST /api/app/scan - Original scan endpoint (backward compatibility)
router.post("/scan", receiveAppData);

module.exports = router;