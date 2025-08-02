const express = require("express");
const router = express.Router();
const { receiveAppData } = require("../controllers/appController");

// Upload all user apps
router.post("/upload", receiveAppData);

module.exports = router;

