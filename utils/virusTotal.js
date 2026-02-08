const axios = require("axios");
const fs = require("fs");
const FormData = require("form-data");
const crypto = require("crypto");
const dotenv = require("dotenv");

dotenv.config();

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VT_BASE_URL = "https://www.virustotal.com/api/v3";

// Calculate SHA-256 hash of a file
const calculateFileHash = (filePath) => {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (data) => hash.update(data));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", (err) => reject(err));
  });
};

// Your existing hash check function (keeping it for backward compatibility)
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
    const url = `${VT_BASE_URL}/files/${sha256}`;
    const response = await axios.get(url, {
      headers: { "x-apikey": VIRUSTOTAL_API_KEY },
      timeout: 30000
    });

    const data = response.data?.data;
    const stats = data?.attributes?.last_analysis_stats;
    const scanDate = data?.attributes?.last_analysis_date;
    
    const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0, timeout = 0 } = stats || {};
    
    const detectedEngines = malicious + suspicious;
    const totalEngines = harmless + malicious + suspicious + undetected + timeout;
    
    let status = "safe";
    if (malicious > 0) {
      status = "malicious";
    } else if (suspicious > 0) {
      status = "suspicious";
    }

    return {
      status: status,
      scanTime: scanDate ? new Date(scanDate * 1000).toISOString() : new Date().toISOString(),
      detectionRatio: `${detectedEngines}/${totalEngines}`,
      totalEngines: totalEngines,
      detectedEngines: detectedEngines
    };

  } catch (err) {
    if (err.response?.status === 404) {
      console.log(`File ${sha256} not found in VirusTotal database`);
      return {
        status: "unknown",
        scanTime: new Date().toISOString(),
        detectionRatio: "0/0",
        totalEngines: 0,
        detectedEngines: 0
      };
    }
    
    console.error(`⚠️ VirusTotal hash check error for ${sha256}:`, err.message);
    return {
      status: "unknown",
      scanTime: new Date().toISOString(),
      detectionRatio: "0/0",
      totalEngines: 0,
      detectedEngines: 0
    };
  }
};

// New function to upload file to VirusTotal for analysis
const uploadFileToVirusTotal = async (filePath) => {
  if (!VIRUSTOTAL_API_KEY) {
    throw new Error("VirusTotal API key is missing");
  }

  if (!fs.existsSync(filePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const fileStats = fs.statSync(filePath);
  const fileSizeMB = fileStats.size / (1024 * 1024);
  
  console.log(`[VT Upload] Starting upload for file: ${filePath} (${fileSizeMB.toFixed(2)} MB)`);

  if (fileStats.size > 32 * 1024 * 1024) {
    throw new Error(`File too large: ${fileSizeMB.toFixed(2)}MB. VirusTotal API limit is 32MB`);
  }

  try {
    const formData = new FormData();
    formData.append('file', fs.createReadStream(filePath));

    const uploadResponse = await axios.post(`${VT_BASE_URL}/files`, formData, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
        ...formData.getHeaders()
      },
      timeout: 300000,
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    });

    const analysisId = uploadResponse.data?.data?.id;
    if (!analysisId) {
      throw new Error("No analysis ID returned from VirusTotal");
    }

    console.log(`[VT Upload] File uploaded successfully. Analysis ID: ${analysisId}`);
    return analysisId;

  } catch (err) {
    if (err.response?.status === 409) {
      const analysisId = err.response.data?.error?.id;
      if (analysisId) {
        console.log(`[VT Upload] File already exists. Using existing analysis ID: ${analysisId}`);
        return analysisId;
      }
    }
    
    if (err.response?.status === 413) {
      throw new Error(`File too large for VirusTotal API (${fileSizeMB.toFixed(2)}MB)`);
    }
    
    console.error("[VT Upload] Upload failed:", {
      status: err.response?.status,
      statusText: err.response?.statusText,
      data: err.response?.data,
      message: err.message
    });
    
    throw new Error(`VirusTotal upload failed: ${err.response?.data?.error?.message || err.message}`);
  }
};

// Function to poll analysis status until completion
const pollAnalysisStatus = async (analysisId, maxAttempts = 30, delaySeconds = 10) => {
  if (!VIRUSTOTAL_API_KEY) {
    throw new Error("VirusTotal API key is missing");
  }

  console.log(`[VT Poll] Starting analysis polling for ID: ${analysisId}`);
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await axios.get(`${VT_BASE_URL}/analyses/${analysisId}`, {
        headers: { 'x-apikey': VIRUSTOTAL_API_KEY },
        timeout: 30000
      });

      const status = response.data?.data?.attributes?.status;
      
      console.log(`[VT Poll] Attempt ${attempt}/${maxAttempts} - Status: ${status}`);

      if (status === "completed") {
        console.log(`[VT Poll] Analysis completed successfully`);
        console.log(`[VT Poll] Full analysis response:`, JSON.stringify(response.data.data, null, 2));
        return response.data.data;
      } else if (status === "queued" || status === "running") {
        if (attempt < maxAttempts) {
          console.log(`[VT Poll] Analysis ${status}, waiting ${delaySeconds}s before next check...`);
          await new Promise(resolve => setTimeout(resolve, delaySeconds * 1000));
        }
      } else {
        throw new Error(`Unexpected analysis status: ${status}`);
      }

    } catch (err) {
      if (err.response?.status === 404) {
        throw new Error(`Analysis ID not found: ${analysisId}`);
      }
      
      console.error(`[VT Poll] Polling error (attempt ${attempt}):`, err.message);
      
      if (attempt === maxAttempts) {
        throw err;
      }
      
      await new Promise(resolve => setTimeout(resolve, delaySeconds * 1000));
    }
  }

  throw new Error(`Analysis polling timeout after ${maxAttempts} attempts (${(maxAttempts * delaySeconds / 60).toFixed(1)} minutes)`);
};

// Function to get file analysis report by file hash
const getFileAnalysisReport = async (fileHash) => {
  if (!VIRUSTOTAL_API_KEY) {
    throw new Error("VirusTotal API key is missing");
  }

  try {
    const response = await axios.get(`${VT_BASE_URL}/files/${fileHash}`, {
      headers: { 'x-apikey': VIRUSTOTAL_API_KEY },
      timeout: 30000
    });

    return response.data.data;

  } catch (err) {
    if (err.response?.status === 404) {
      throw new Error(`File not found in VirusTotal database: ${fileHash}`);
    }
    
    console.error("[VT Report] Failed to get file analysis report:", err.message);
    throw new Error(`Failed to get analysis report: ${err.response?.data?.error?.message || err.message}`);
  }
};

// Main function to perform complete file analysis workflow
const analyzeFileWithVirusTotal = async (filePath) => {
  console.log(`[VT Analysis] Starting complete file analysis for: ${filePath}`);
  
  try {
    // Calculate local hash as fallback
    const localFileHash = await calculateFileHash(filePath);
    
    // Step 1: Upload file to VirusTotal
    const analysisId = await uploadFileToVirusTotal(filePath);
    
    // Step 2: Poll until analysis completes
    const analysisResult = await pollAnalysisStatus(analysisId);
    
    // Step 3: Get the file hash from analysis result or use local hash
    let fileHash = analysisResult?.attributes?.results?.sha256 || 
                   analysisResult?.meta?.file_info?.sha256;
    
    if (!fileHash) {
      console.warn(`[VT Analysis] Could not extract file hash from VirusTotal response, using local hash: ${localFileHash}`);
      fileHash = localFileHash;
    } else {
      console.log(`[VT Analysis] File hash from VirusTotal: ${fileHash}`);
      if (fileHash !== localFileHash) {
        console.warn(`[VT Analysis] Hash mismatch! VirusTotal: ${fileHash}, Local: ${localFileHash}`);
      }
    }
    
    // Step 4: Get detailed file report
    const fileReport = await getFileAnalysisReport(fileHash);
    
    // Step 5: Process and return results
    const stats = fileReport?.attributes?.last_analysis_stats;
    const scanDate = fileReport?.attributes?.last_analysis_date;
    const fileName = fileReport?.attributes?.meaningful_name || 
                     fileReport?.attributes?.names?.[0] || 
                     require('path').basename(filePath);
    
    const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0, timeout = 0 } = stats || {};
    
    const detectedEngines = malicious + suspicious;
    const totalEngines = harmless + malicious + suspicious + undetected + timeout;
    
    let status = "safe";
    if (malicious > 0) {
      status = "malicious";
    } else if (suspicious > 0) {
      status = "suspicious";
    }

    const result = {
      status: status,
      fileHash: fileHash,
      fileName: fileName,
      scanTime: scanDate ? new Date(scanDate * 1000).toISOString() : new Date().toISOString(),
      detectionRatio: `${detectedEngines}/${totalEngines}`,
      totalEngines: totalEngines,
      detectedEngines: detectedEngines,
      maliciousCount: malicious,
      suspiciousCount: suspicious,
      analysisId: analysisId,
      fullReport: fileReport
    };
    
    console.log(`[VT Analysis] Analysis completed:`, {
      status: result.status,
      detectionRatio: result.detectionRatio,
      fileName: result.fileName
    });
    
    console.log("\n=== VIRUSTOTAL ANALYSIS REPORT ===");
    console.log(JSON.stringify(result, null, 2));
    console.log("=================================\n");
    
    return result;

  } catch (error) {
    console.error("[VT Analysis] Analysis failed:", error.message);
    throw error;
  }
};

// Example usage function
const exampleUsage = async () => {
  const filePath = "./example.apk";
  
  try {
    const result = await analyzeFileWithVirusTotal(filePath);
    console.log("Analysis successful!");
    return result;
  } catch (error) {
    console.error("Analysis failed:", error.message);
  }
};

module.exports = {
  checkVirusTotal,
  uploadFileToVirusTotal,
  pollAnalysisStatus,
  getFileAnalysisReport,
  analyzeFileWithVirusTotal,
  exampleUsage
};