// routes/appRoutes.js
const express = require("express");
const router = express.Router();
const { receiveAppData } = require("../controllers/appController");

router.post("/upload", receiveAppData);

module.exports = router;
