// server.js
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const esClient = require('./elasticsearch'); // ✅ using correct path
const appRoutes = require('./routes/appRoutes');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Make Elasticsearch client available to routes
app.set('esClient', esClient);

// Optional: Ensure index exists before starting
(async () => {
  const indexName = 'apps';
  try {
    const exists = await esClient.indices.exists({ index: indexName });
    if (!exists) {
      await esClient.indices.create({
        index: indexName,
        mappings: {
          properties: {
            appName: { type: 'text' },
            packageName: { type: 'keyword' },
            hash: { type: 'keyword' },
            sizeMB: { type: 'float' },
            status: { type: 'keyword' },
            timestamp: { type: 'date' }
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

// Routes
app.use('/api/app', appRoutes);

app.get('/', (req, res) => {
  res.send('✅ Backend server is running successfully 🎉');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
