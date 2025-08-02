const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const { Client } = require('@elastic/elasticsearch');
const appRoutes = require('./routes/appRoutes');

// ✅ Load .env variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// ✅ Middleware
app.use(cors());
app.use(express.json());

// ✅ Elasticsearch setup
const esClient = new Client({
  node: 'https://localhost:9200',
  auth: {
    username: 'elastic',
    password: process.env.ELASTIC_PASSWORD // ✅ Use from .env
  },
  tls: {
    rejectUnauthorized: false
  }
});
app.set('esClient', esClient);

// ✅ Mount API routes
app.use('/api/app', appRoutes);

// ✅ Root endpoint
app.get('/', (req, res) => {
  res.send('Backend server is running successfully 🎉');
});

// ✅ Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
