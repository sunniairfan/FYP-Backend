const axios = require("axios");
const dotenv = require("dotenv");
dotenv.config();

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;

const checkVirusTotal = async (sha256) => {
  if (!VIRUSTOTAL_API_KEY) {
    console.warn("⚠️ VirusTotal API key is missing.");
    return "unknown";
  }

  try {
    const url = `https://www.virustotal.com/api/v3/files/${sha256}`;
    const response = await axios.get(url, {
      headers: { "x-apikey": VIRUSTOTAL_API_KEY },
    });

    const stats = response.data?.data?.attributes?.last_analysis_stats;
    const { malicious = 0, suspicious = 0 } = stats || {};

    if (malicious > 0) return "malicious";
    if (suspicious > 0) return "suspicious";
    return "safe";
  } catch (err) {
    console.error(`⚠️ VirusTotal error for ${sha256}:`, err.message);
    return "unknown";
  }
};

module.exports = { checkVirusTotal };