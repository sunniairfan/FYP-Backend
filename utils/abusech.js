const axios = require("axios");
const qs = require("qs");

const checkAbuseCH = async (sha256) => {
  try {
    const data = qs.stringify({ query: "get_info", hash: sha256 });
    const response = await axios.post("https://mb-api.abuse.ch/api/v1/", data, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "AndroidEDR/1.0 (mailto:sunnia.irfan@example.com)"
      },
    });

    const result = response.data;
    if (result?.query_status === "ok" && result?.data?.length > 0) {
      return "malicious";
    }
    return "unknown";
  } catch (error) {
    console.error("⚠️ Abuse.ch error:", error.message);
    return "unknown";
  }
};

module.exports = { checkAbuseCH };