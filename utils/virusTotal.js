const axios = require("axios");
const dotenv = require("dotenv");
dotenv.config();

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

const checkVirusTotal = async (sha256) => {
  if (!VIRUSTOTAL_API_KEY) {
    console.warn("⚠️ VirusTotal API key is missing.");
    return {
      status: "unknown",
      scanTime: new Date().toISOString(),
      detectionRatio: "0/0",
      totalEngines: 0,
      detectedEngines: 0
    };
  }

  try {
    const url = `https://www.virustotal.com/api/v3/files/${sha256}`;
    const response = await axios.get(url, {
      headers: { "x-apikey": VIRUSTOTAL_API_KEY },
    });

    const data = response.data?.data;
    const stats = data?.attributes?.last_analysis_stats;
    const scanDate = data?.attributes?.last_analysis_date;
    
    const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0, timeout = 0 } = stats || {};
    
    // Calculate totals
    const detectedEngines = malicious + suspicious;
    const totalEngines = harmless + malicious + suspicious + undetected + timeout;
    
    // Determine status (keeping your original logic)
    let status = "safe";
    if (malicious > 0) {
      status = "malicious";
    } else if (suspicious > 0) {
      status = "suspicious";
    }

    // Return detailed information
    return {
      status: status,
      scanTime: scanDate ? new Date(scanDate * 1000).toISOString() : new Date().toISOString(),
      detectionRatio: `${detectedEngines}/${totalEngines}`,
      totalEngines: totalEngines,
      detectedEngines: detectedEngines
    };

  } catch (err) {
    console.error(`⚠️ VirusTotal error for ${sha256}:`, err.message);
    return {
      status: "unknown",
      scanTime: new Date().toISOString(),
      detectionRatio: "0/0",
      totalEngines: 0,
      detectedEngines: 0
    };
  }
};

module.exports = { checkVirusTotal };