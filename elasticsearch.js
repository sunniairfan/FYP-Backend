require('dotenv').config();
const { Client } = require('@elastic/elasticsearch');

const esClient = new Client({
  node: process.env.ELASTIC_NODE || 'https://localhost:9200',
  auth: {
    username: process.env.ELASTIC_USERNAME || 'elastic',
    password: process.env.ELASTIC_PASSWORD
  },
  tls: {
    rejectUnauthorized: false, // Accept self-signed certificate
  },
  requestTimeout: 60000,
  pingTimeout: 3000,
  maxRetries: 3,
  resurrectStrategy: 'ping'
});

// Test connection function
async function testConnection() {
  try {
    const health = await esClient.cluster.health();
    console.log('✅ Elasticsearch connected successfully');
    console.log(`📊 Cluster status: ${health.status || health.body?.status || 'unknown'}`);
    return true;
  } catch (error) {
    console.error('❌ Elasticsearch connection failed:', error.message);
    
    if (error.message.includes('ECONNREFUSED') || error.message.includes('no_shard_available')) {
      console.log('💡 Make sure Elasticsearch is running on localhost:9200');
      console.log('💡 Try: Start Elasticsearch service or check ELASTIC_NODE in .env');
    }
    
    return false;
  }
}

// Initialize and test connection
testConnection();

module.exports = { esClient, testConnection };
