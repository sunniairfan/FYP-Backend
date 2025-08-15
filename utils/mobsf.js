const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

const MOBSF_URL = process.env.MOBSF_URL || 'http://localhost:8000';
const API_KEY = process.env.MOBSF_API_KEY || '0a30ffe439e3a64a1e27dff625384b7422998f1bc38cdd0324739eeedbb0ff03';

// Enhanced logging for debugging
function log(message, data = null) {
  console.log(`[MobSF] ${message}`, data ? JSON.stringify(data, null, 2) : '');
}

function logError(message, error) {
  console.error(`[MobSF Error] ${message}:`, {
    message: error.message,
    status: error.response?.status,
    statusText: error.response?.statusText,
    data: error.response?.data,
    url: error.config?.url,
    method: error.config?.method,
    requestBody: error.config?.data // Log the sent body for debugging
  });
}

async function checkConnection() {
  try {
    log("Checking MobSF connection...");
    const response = await axios.get(`${MOBSF_URL}/api/v1/scans`, {
      headers: { 'Authorization': API_KEY },
      timeout: 10000
    });
    log("MobSF connection successful", response.data);
    return true;
  } catch (error) {
    logError("MobSF connection failed", error);
    return false;
  }
}

async function uploadToMobSF(filePath) {
  try {
    // Validate file exists and is readable
    if (!fs.existsSync(filePath)) {
      throw new Error(`File does not exist: ${filePath}`);
    }

    const stats = fs.statSync(filePath);
    const fileName = path.basename(filePath);
    
    log(`Uploading file to MobSF`, {
      filePath,
      fileName,
      fileSize: `${(stats.size / 1024 / 1024).toFixed(2)} MB`,
      isApk: fileName.toLowerCase().endsWith('.apk')
    });

    // Create form data with proper file handling
    const form = new FormData();
    const fileStream = fs.createReadStream(filePath);
    
    // Add file with explicit filename and content type
    form.append('file', fileStream, {
      filename: fileName,
      contentType: 'application/vnd.android.package-archive'
    });

    // Get form headers
    const formHeaders = form.getHeaders();
    
    log("Making upload request to MobSF", {
      url: `${MOBSF_URL}/api/v1/upload`,
      headers: {
        ...formHeaders,
        'Authorization': '[HIDDEN]'
      }
    });

    const response = await axios.post(`${MOBSF_URL}/api/v1/upload`, form, {
      headers: {
        ...formHeaders,
        'Authorization': API_KEY
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 300000 // 5 minutes timeout for large files
    });

    log("Upload successful", {
      hash: response.data.hash,
      scan_type: response.data.scan_type,
      file_name: response.data.file_name
    });

    return response.data;
  } catch (error) {
    logError("Upload to MobSF failed", error);
    throw error;
  }
}

async function scanWithMobSF(hash) {
  try {
    log(`Starting MobSF scan for hash: ${hash}`);
    
    const params = new URLSearchParams();
    params.append('hash', hash);
    // Optionally add re_scan if needed (e.g., for re-scanning)
    // params.append('re_scan', '0'); // Uncomment if you want to explicitly set re_scan

    log('Scan request details:', {
      url: `${MOBSF_URL}/api/v1/scan`,
      body: params.toString(),
      headers: {
        Authorization: '[HIDDEN]',
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const response = await axios.post(
      `${MOBSF_URL}/api/v1/scan`,
      params,
      {
        headers: {
          'Authorization': API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 600000 // 10 minutes timeout for scanning
      }
    );

    log('Scan completed', response.data);
    return response.data;
  } catch (error) {
    logError(`Scan failed for hash: ${hash}`, error);
    throw error;
  }
}

async function getJsonReport(hash) {
  try {
    log(`Fetching JSON report for hash: ${hash}`);
    
    const params = new URLSearchParams();
    params.append('hash', hash);

    log('JSON report request details:', {
      url: `${MOBSF_URL}/api/v1/report_json`,
      body: params.toString(),
      headers: {
        Authorization: '[HIDDEN]',
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const response = await axios.post(
      `${MOBSF_URL}/api/v1/report_json`,
      params,
      {
        headers: {
          'Authorization': API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 60000 // 1 minute timeout
      }
    );

    log("JSON report fetched successfully");
    return response.data;
  } catch (error) {
    logError(`Failed to get JSON report for hash: ${hash}`, error);
    throw error;
  }
}

async function getPdfReport(hash) {
  try {
    log(`Fetching PDF report for hash: ${hash}`);
    
    const params = new URLSearchParams();
    params.append('hash', hash);

    log('PDF report request details:', {
      url: `${MOBSF_URL}/api/v1/download_pdf`,
      body: params.toString(),
      headers: {
        Authorization: '[HIDDEN]',
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const response = await axios.post(
      `${MOBSF_URL}/api/v1/download_pdf`,
      params,
      {
        headers: {
          'Authorization': API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        responseType: 'stream',
        timeout: 60000 // 1 minute timeout
      }
    );

    log("PDF report fetched successfully");
    return response.data;
  } catch (error) {
    logError(`Failed to get PDF report for hash: ${hash}`, error);
    throw error;
  }
}

async function deleteScan(hash) {
  try {
    log(`Deleting scan for hash: ${hash}`);
    
    const params = new URLSearchParams();
    params.append('hash', hash);

    log('Delete scan request details:', {
      url: `${MOBSF_URL}/api/v1/delete_scan`,
      body: params.toString(),
      headers: {
        Authorization: '[HIDDEN]',
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const response = await axios.post(
      `${MOBSF_URL}/api/v1/delete_scan`,
      params,
      {
        headers: {
          'Authorization': API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 30000 // 30 seconds timeout
      }
    );

    log("Scan deleted successfully", response.data);
    return response.data;
  } catch (error) {
    logError(`Failed to delete scan for hash: ${hash}`, error);
    throw error;
  }
}

// Enhanced analyze function with better error handling
async function analyzeAppWithMobSF(filePath) {
  try {
    log(`Starting complete MobSF analysis for: ${filePath}`);
    
    // Step 1: Upload
    const uploadResult = await uploadToMobSF(filePath);
    const hash = uploadResult.hash;
    
    // Step 2: Scan
    await scanWithMobSF(hash);
    
    // Step 3: Get Report
    const report = await getJsonReport(hash);
    
    log("Complete MobSF analysis finished successfully");
    return {
      hash,
      uploadResult,
      report
    };
  } catch (error) {
    logError("Complete MobSF analysis failed", error);
    throw error;
  }
}

// Test function to help debug issues
async function testMobSFConnection() {
  try {
    log("Testing MobSF connection and endpoints...");
    
    // Test basic connection
    const isConnected = await checkConnection();
    if (!isConnected) {
      throw new Error("Cannot connect to MobSF");
    }
    
    // Test API endpoints by making simple requests
    const endpoints = [
      '/api/v1/scans',
      '/api/v1/upload'  // This will fail but tells us about the endpoint
    ];
    
    for (const endpoint of endpoints) {
      try {
        await axios.get(`${MOBSF_URL}${endpoint}`, {
          headers: { 'Authorization': API_KEY },
          timeout: 5000
        });
        log(`Endpoint ${endpoint} is accessible`);
      } catch (error) {
        log(`Endpoint ${endpoint} responded with status: ${error.response?.status}`);
      }
    }
    
    return true;
  } catch (error) {
    logError("MobSF connection test failed", error);
    return false;
  }
}

log("MobSF module loaded", {
  MOBSF_URL,
  API_KEY_SET: !!API_KEY,
  functions: [
    'uploadToMobSF',
    'scanWithMobSF', 
    'getJsonReport',
    'getPdfReport',
    'deleteScan',
    'checkConnection',
    'analyzeAppWithMobSF',
    'testMobSFConnection'
  ]
});

module.exports = {
  uploadToMobSF,
  scanWithMobSF,
  getJsonReport,
  getPdfReport,
  deleteScan,
  checkConnection,
  analyzeAppWithMobSF,
  testMobSFConnection
};