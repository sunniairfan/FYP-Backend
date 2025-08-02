const axios = require("axios");
const qs = require("qs");

const checkAbuseCH = async (sha256) => {
  try {
    const data = qs.stringify({
      query: "get_info",
      hash: sha256,
    });

    const response = await axios.post(
      "https://mb-api.abuse.ch/api/v1/",
      data,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    // Check if response was successful
    if (response.status === 200 && response.data) {
      const resData = response.data;

      if (
        resData.query_status === "ok" &&
        Array.isArray(resData.data) &&
        resData.data.length > 0 &&
        resData.data[0].malware !== null
      ) {
        console.log("☠️ Abuse.ch detected:", resData.data[0].malware);
        return "malicious";
      } else {
        return "safe"; // It's better to be specific
      }
    } else {
      console.warn("⚠️ Unexpected response from Abuse.ch:", response.status);
      return "unknown";
    }
  } catch (error) {
    console.error("❌ Error contacting Abuse.ch:", error.message);
    return "unknown";
  }
};

module.exports = { checkAbuseCH };

