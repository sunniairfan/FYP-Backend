const { Client } = require('@elastic/elasticsearch');

const esClient = new Client({
  node: 'https://localhost:9200',
  auth: {
    username: 'elastic',
    password: 'O*lOfhB5*gWK=RdfOF=l', // 🔁 Use your real password here
  },
  tls: {
    rejectUnauthorized: false, // Accept self-signed certificate
  },
});

module.exports = esClient;
