// server.js
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const esClient = require('./elasticsearch');
const appRoutes = require('./routes/appRoutes');
const uploadAppRoutes = require('./routes/uploadAppRoutes');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.set('esClient', esClient);

// Ensure index exists and has mapping for uploadedByUser
(async () => {
  const indexName = 'apps';
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
            uploadedByUser: { type: 'boolean' }
          }
        }
      });
      console.log(`✅ Created index: ${indexName}`);
    } else {
      console.log(`📦 Index '${indexName}' already exists`);
    }
  } catch (err) {
    console.error('❌ Failed to check or create index:', err.meta?.body?.error || err.message);
  }
})();

app.use('/api/app', appRoutes);
app.use('/uploadapp', uploadAppRoutes);

app.get('/', (req, res) => {
  res.send('✅ Backend server is running successfully 🎉');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
