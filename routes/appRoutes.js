// routes/appRoutes.js
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const router = express.Router();
const {
	receiveAppData,
	uploadApp,
	storeMLPrediction,
} = require("../controllers/appController");

const uploadsDir = path.join(__dirname, "../uploads/apks");
if (!fs.existsSync(uploadsDir)) {
	fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
	destination: function (_req, _file, cb) {
		cb(null, uploadsDir);
	},
	filename: function (_req, file, cb) {
		const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
		const uniqueName = `temp_${timestamp}_${file.originalname}`;
		cb(null, uniqueName);
	},
});

const upload = multer({
	storage,
	limits: {
		fileSize: 500 * 1024 * 1024,
	},
	fileFilter: function (_req, file, cb) {
		if (
			file.mimetype === "application/vnd.android.package-archive" ||
			file.originalname.toLowerCase().endsWith(".apk")
		) {
			cb(null, true);
		} else {
			cb(new Error("Only APK files are allowed"), false);
		}
	},
});

router.post("/upload", (req, res, next) => {
	const contentType = String(req.headers["content-type"] || "").toLowerCase();
	const isMultipart = contentType.includes("multipart/form-data");

	if (!isMultipart) {
		return receiveAppData(req, res, next);
	}

	return upload.fields([
		{ name: "apk", maxCount: 1 },
		{ name: "metadata", maxCount: 1 },
	])(req, res, (err) => {
		if (err) {
			return res.status(400).json({
				success: false,
				error: "File upload failed",
				details: err.message,
			});
		}

		return uploadApp(req, res, next);
	});
});

router.post("/ml-prediction", storeMLPrediction);

module.exports = router;
