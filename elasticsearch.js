const { Client } = require('@elastic/elasticsearch');
const client = new Client({
  node: 'https://localhost:9200',
  auth: {
    username: 'elastic',
    password: '2*+P9PkehPT+t9iKB_gg'
  },
  tls: {
    rejectUnauthorized: false
  }
});
module.exports = client;