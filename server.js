const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const esClient = require('./utils/elasticClient');
const appRoutes = require('./routes/appRoutes');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

app.set('esClient', esClient);
app.use('/api/app', appRoutes);

app.get('/', (req, res) => {
  res.send('Backend server is running successfully 🎉');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
//bla bla 
