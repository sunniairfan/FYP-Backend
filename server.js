const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const esClient = require('./elasticsearch');
const appRoutes = require('./routes/appRoutes');
const uploadAppRoutes = require('./routes/uploadAppRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes'); // Add this line

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.set('esClient', esClient);

// Helper function to get dynamic index name
const getIndexName = () => {
  const today = new Date();
  const day = String(today.getDate()).padStart(2, '0');
  const month = String(today.getMonth() + 1).padStart(2, '0');
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
            appName: { type: 'text' },
            packageName: { type: 'keyword' },
            sha256: { type: 'keyword' },
            sizeMB: { type: 'float' },
            status: { type: 'keyword' },
            timestamp: { type: 'date' },
            uploadedByUser: { type: 'boolean' },
            dangerousPermission1: { type: 'keyword' },
            dangerousPermission2: { type: 'keyword' },
            dangerousPermission3: { type: 'keyword' },
            dangerousPermission4: { type: 'keyword' },
            dangerousPermission5: { type: 'keyword' },
            dangerousPermission6: { type: 'keyword' },
            dangerousPermission7: { type: 'keyword' },
            dangerousPermission8: { type: 'keyword' },
            dangerousPermission9: { type: 'keyword' },
            dangerousPermission10: { type: 'keyword' },
            dangerousPermission11: { type: 'keyword' },
            dangerousPermission12: { type: 'keyword' },
            dangerousPermission13: { type: 'keyword' },
            dangerousPermission14: { type: 'keyword' },
            dangerousPermission15: { type: 'keyword' },
            dangerousPermission16: { type: 'keyword' },
            dangerousPermission17: { type: 'keyword' },
            dangerousPermission18: { type: 'keyword' },
            source: { type: 'keyword' },
            scanTime: { type: 'date' },
            detectionRatio: { type: 'keyword' },
            totalEngines: { type: 'integer' },
            detectedEngines: { type: 'integer' },
            apkFilePath: { type: 'keyword' },
            apkFileName: { type: 'keyword' },
            uploadSource: { type: 'keyword' }
          }
        }
      });
      console.log(`✅ Created index: ${indexName}`);
    }
  } catch (err) {
    console.error('❌ Failed to ensure index exists:', err.message);
  }
};

// Ensure index exists and has mapping for uploadedByUser
(async () => {
  await ensureIndexExists(esClient);
})();

// Routes
app.use('/', dashboardRoutes); // Add this line - Dashboard routes (must be before other routes)
app.use('/api/app', appRoutes);
app.use('/uploadapp', uploadAppRoutes);

app.get('/', (req, res) => {
  res.send(`
    <div style="background: linear-gradient(135deg, #0a0f1c 0%, #1a1f3a 50%, #0d1421 100%); color: #60a5fa; font-family: Arial; text-align: center; padding: 50px; min-height: 100vh;">
      <h1 style="font-size: 3em; margin-bottom: 20px;">🛡️ Mobile Apps Security Backend</h1>
      <p style="font-size: 1.2em; margin-bottom: 30px;">✅ Backend server is running successfully 🎉</p>
      <div style="margin: 30px 0;">
        <a href="/dashboard" style="background: linear-gradient(45deg, #2563eb, #3b82f6); color: white; text-decoration: none; padding: 15px 30px; border-radius: 8px; font-weight: bold; margin: 10px; display: inline-block; transition: all 0.3s ease;">
          📊 View Dashboard
        </a>
        <a href="/uploadapp/apps" style="background: linear-gradient(45deg, #059669, #10b981); color: white; text-decoration: none; padding: 15px 30px; border-radius: 8px; font-weight: bold; margin: 10px; display: inline-block; transition: all 0.3s ease;">
          📱 Uploaded Apps
        </a>
      </div>
      <div style="margin-top: 40px; font-size: 0.9em; color: #94a3b8;">
        <p>Endpoints available:</p>
        <p>• <code>/dashboard</code> - Security Dashboard</p>
        <p>• <code>/api/dashboard/data</code> - Dashboard API</p>
        <p>• <code>/uploadapp/apps</code> - Uploaded Apps Manager</p>
        <p>• <code>/api/app/*</code> - App Management API</p>
      </div>
    </div>
  `);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`📊 Dashboard available at: http://localhost:${PORT}/dashboard`);
  console.log(`📱 Upload manager at: http://localhost:${PORT}/uploadapp/apps`);
});