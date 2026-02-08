// routes/appRoutes.js
const express = require("express");
const router = express.Router();
const { receiveAppData, storeMLPrediction } = require("../controllers/appController");

router.post("/upload", receiveAppData);
router.post("/ml-prediction", storeMLPrediction);

module.exports = router;
