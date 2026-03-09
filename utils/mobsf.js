const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
// MobSF server URL and API key from environment variables or defaults
const MOBSF_URL = process.env.MOBSF_URL || 'http://localhost:8000';
const API_KEY = process.env.MOBSF_API_KEY || '9f00268f2a19adf3fdfc645e6c322d5e85d77c12ea7c4574bf2d0e705396b41d';
function log(message, data = null) {
  console.log(`[MobSF] ${message}`, data ? JSON.stringify(data, null, 2) : '');
}
// Log errors with details

function logError(message, error) {
  console.error(`[MobSF Error] ${message}:`, {
    message: error.message,
    status: error.response?.status,
    statusText: error.response?.statusText,
    data: error.response?.data,
    url: error.config?.url,
    method: error.config?.method,
    requestBody: error.config?.data 
  });
}
// Check connection to MobSF server
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
// Upload a file to MobSF
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
    // Send upload request
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
// Start a scan for a file using its hash
async function scanWithMobSF(hash) {
  try {
    log(`Starting MobSF scan for hash: ${hash}`);
    
    const params = new URLSearchParams();
    params.append('hash', hash);
     log('Scan request details:', {
      url: `${MOBSF_URL}/api/v1/scan`,
      body: params.toString(),
      headers: {
        Authorization: '[HIDDEN]',
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    // Send scan request
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
// Get JSON report for a scan
async function getJsonReport(hash) {
  try {
    log(`Fetching JSON report for hash: ${hash}`);
    
    const params = new URLSearchParams();
    params.append('hash', hash);
// Send JSON report request
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
// Get PDF report for a scan
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
// Send PDF report request
    const response = await axios.post(
      `${MOBSF_URL}/api/v1/download_pdf`,
      params,
      {
        headers: {
          'Authorization': API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        responseType: 'stream',
        timeout: 120000 // 2 minutes timeout for PDF generation
      }
    );

    log("PDF report stream created successfully");
    
    // Add error handling to the stream
    response.data.on('error', (streamError) => {
      logError('PDF stream error', streamError);
    });

    return response.data;
  } catch (error) {
    logError(`Failed to get PDF report for hash: ${hash}`, error);
    throw error;
  }
}
// Delete a scan from MobSF
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
// Send delete request
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

// ─── Dynamic Analysis Functions ─────────────────────────────────────────────

// GET /api/v1/dynamic/get_apps - List apps available for dynamic analysis
async function getDynamicApps() {
  try {
    log('Fetching apps available for dynamic analysis...');
    const response = await axios.get(`${MOBSF_URL}/api/v1/dynamic/get_apps`, {
      headers: { 'Authorization': API_KEY },
      timeout: 30000
    });
    log('Dynamic apps fetched', response.data);
    return response.data;
  } catch (error) {
    logError('Failed to get dynamic apps', error);
    throw error;
  }
}

// POST /api/v1/dynamic/start_analysis - Start dynamic analysis for a given hash
async function startDynamicAnalysis(hash, options = {}) {
  try {
    log(`Starting dynamic analysis for hash: ${hash}`);
    const params = new URLSearchParams();
    params.append('hash', hash);
    if (options.re_install !== undefined) params.append('re_install', options.re_install);
    if (options.install !== undefined) params.append('install', options.install);

    const response = await axios.post(`${MOBSF_URL}/api/v1/dynamic/start_analysis`, params, {
      headers: {
        'Authorization': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 120000 // 2 minutes – app boot can be slow
    });
    log('Dynamic analysis started', response.data);
    return response.data;
  } catch (error) {
    logError(`Failed to start dynamic analysis for hash: ${hash}`, error);
    throw error;
  }
}

// POST /api/v1/dynamic/stop_analysis - Stop dynamic analysis
async function stopDynamicAnalysis(hash) {
  try {
    log(`Stopping dynamic analysis for hash: ${hash}`);
    const params = new URLSearchParams();
    params.append('hash', hash);
    const response = await axios.post(`${MOBSF_URL}/api/v1/dynamic/stop_analysis`, params, {
      headers: {
        'Authorization': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 60000
    });
    log('Dynamic analysis stopped', response.data);
    return response.data;
  } catch (error) {
    logError(`Failed to stop dynamic analysis for hash: ${hash}`, error);
    throw error;
  }
}

// POST /api/v1/dynamic/report_json - Get JSON report of dynamic analysis
async function getDynamicReportJson(hash) {
  try {
    log(`Fetching dynamic JSON report for hash: ${hash}`);
    const params = new URLSearchParams();
    params.append('hash', hash);
    const response = await axios.post(`${MOBSF_URL}/api/v1/dynamic/report_json`, params, {
      headers: {
        'Authorization': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 60000
    });
    log('Dynamic JSON report fetched successfully');
    return response.data;
  } catch (error) {
    logError(`Failed to get dynamic report for hash: ${hash}`, error);
    throw error;
  }
}

// POST /api/v1/android/mobsfy - MobSFy the Android runtime environment
async function mobsfyAndroid(identifier) {
  try {
    log(`MobSFying Android device: ${identifier}`);
    const params = new URLSearchParams();
    params.append('identifier', identifier);
    const response = await axios.post(`${MOBSF_URL}/api/v1/android/mobsfy`, params, {
      headers: {
        'Authorization': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 120000
    });
    log('MobSFy completed', response.data);
    return response.data;
  } catch (error) {
    logError(`Failed to MobSFy device: ${identifier}`, error);
    throw error;
  }
}

// POST /api/v1/android/tls_tests - Run TLS/SSL security tests
async function runTlsTests(hash) {
  try {
    log(`Running TLS tests for hash: ${hash}`);
    const params = new URLSearchParams();
    params.append('hash', hash);
    const response = await axios.post(`${MOBSF_URL}/api/v1/android/tls_tests`, params, {
      headers: {
        'Authorization': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 60000
    });
    log('TLS tests completed', response.data);
    return response.data;
  } catch (error) {
    logError(`Failed TLS tests for hash: ${hash}`, error);
    // Non-fatal – return null so pipeline can continue
    return null;
  }
}

// POST /api/v1/frida/instrument - Frida instrumentation (API monitor + SSL bypass + root bypass)
async function fridaInstrument(hash, hooks = 'api_monitor,ssl_pinning_bypass,root_bypass,debugger_check_bypass') {
  try {
    log(`Starting Frida instrumentation for hash: ${hash}`);
    const params = new URLSearchParams();
    params.append('hash', hash);
    params.append('default_hooks', hooks);
    params.append('auxiliary_hooks', '');
    params.append('frida_code', '');
    const response = await axios.post(`${MOBSF_URL}/api/v1/frida/instrument`, params, {
      headers: {
        'Authorization': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 60000
    });
    log('Frida instrumentation started', response.data);
    return response.data;
  } catch (error) {
    logError(`Failed to start Frida instrumentation for hash: ${hash}`, error);
    // Non-fatal – return null
    return null;
  }
}

// POST /api/v1/frida/logs - Get Frida log output
async function getFridaLogs(hash) {
  try {
    log(`Fetching Frida logs for hash: ${hash}`);
    const params = new URLSearchParams();
    params.append('hash', hash);
    const response = await axios.post(`${MOBSF_URL}/api/v1/frida/logs`, params, {
      headers: {
        'Authorization': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      timeout: 30000
    });
    return response.data;
  } catch (error) {
    logError(`Failed to get Frida logs for hash: ${hash}`, error);
    return null;
  }
}

// GET /api/v1/dynamic/get_apps then filter – check if a hash is ready for dynamic analysis
async function isReadyForDynamicAnalysis(hash) {
  try {
    const data = await getDynamicApps();
    if (!data || !data.apks) return false;
    return data.apks.some(apk => apk.MD5 === hash);
  } catch (_) {
    return false;
  }
}

// POST /api/v1/android/root_ca - Install MobSF Root CA for HTTPS interception
async function installRootCA(action = 'install') {
  try {
    log(`${action === 'install' ? 'Installing' : 'Removing'} Root CA...`);
    const params = new URLSearchParams();
    params.append('action', action);
    const response = await axios.post(`${MOBSF_URL}/api/v1/android/root_ca`, params, {
      headers: { 'Authorization': API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 60000
    });
    log(`Root CA ${action} result`, response.data);
    return response.data;
  } catch (error) {
    logError(`Failed to ${action} Root CA`, error);
    return null; // non-fatal
  }
}

// POST /api/v1/android/global_proxy - Set/unset global HTTPS proxy
async function setGlobalProxy(action = 'set') {
  try {
    log(`${action === 'set' ? 'Setting' : 'Unsetting'} global proxy...`);
    const params = new URLSearchParams();
    params.append('action', action);
    const response = await axios.post(`${MOBSF_URL}/api/v1/android/global_proxy`, params, {
      headers: { 'Authorization': API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 60000
    });
    log(`Global proxy ${action} result`, response.data);
    return response.data;
  } catch (error) {
    logError(`Failed to ${action} global proxy`, error);
    return null; // non-fatal
  }
}

// POST /api/v1/android/activity - Run Activity/Exported Activity tester
async function runActivityTester(hash, test = 'exported') {
  try {
    log(`Running activity tester (${test}) for hash: ${hash}`);
    const params = new URLSearchParams();
    params.append('hash', hash);
    params.append('test', test);
    const response = await axios.post(`${MOBSF_URL}/api/v1/android/activity`, params, {
      headers: { 'Authorization': API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 120000
    });
    log(`Activity tester (${test}) result`, response.data);
    return response.data;
  } catch (error) {
    logError(`Failed to run activity tester (${test})`, error);
    return null; // non-fatal
  }
}

// POST /api/v1/frida/api_monitor - Get Frida API monitor output
async function getFridaApiMonitor(hash) {
  try {
    log(`Fetching Frida API monitor data for hash: ${hash}`);
    const params = new URLSearchParams();
    params.append('hash', hash);
    const response = await axios.post(`${MOBSF_URL}/api/v1/frida/api_monitor`, params, {
      headers: { 'Authorization': API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 30000
    });
    return response.data;
  } catch (error) {
    logError(`Failed to get Frida API monitor data for hash: ${hash}`, error);
    return null; // non-fatal
  }
}

// ─── Full Automated Dynamic Analysis Pipeline ─────────────────────────────────
// Complete pipeline per MobSF docs:
//   mobsfy → root_ca → global_proxy → start → frida → activity_tester
//   → wait → api_monitor → tls_tests → stop → wait(report ready) → report_json
// waitSeconds: how long to let the app run while capturing (default 60s)
async function runFullDynamicAnalysis(hash, waitSeconds = 60) {
  const startTime = Date.now();
  log(`=== Full Dynamic Analysis Pipeline START ===`);
  log(`Hash: ${hash}, Capture wait: ${waitSeconds}s`);

  // ── Step 1: Get device identifier from MobSF ────────────────────────────────
  log('Step 1: Getting device identifier from MobSF...');
  let deviceIdentifier = null;
  let proxyInfo = {};
  try {
    const appsData = await getDynamicApps();
    deviceIdentifier = appsData?.identifier || null;
    proxyInfo = { proxy_ip: appsData?.proxy_ip, proxy_port: appsData?.proxy_port };
    log(`Device identifier: ${deviceIdentifier}`);
  } catch (e) {
    log(`Could not get device identifier (non-fatal): ${e.message}`);
  }

  // ── Step 2: MobSFy the device (setup runtime environment) ───────────────────
  log('Step 2: MobSFying the Android device...');
  let mobsfyResult = null;
  if (deviceIdentifier) {
    mobsfyResult = await mobsfyAndroid(deviceIdentifier);
  } else {
    log('Skipping MobSFy — no device identifier found');
  }

  // ── Step 3: Install Root CA (enables HTTPS traffic capture) ─────────────────
  log('Step 3: Installing MobSF Root CA...');
  const rootCAResult = await installRootCA('install');

  // ── Step 4: Set global HTTPS proxy ──────────────────────────────────────────
  log('Step 4: Setting global HTTPS proxy...');
  const proxyResult = await setGlobalProxy('set');

  // ── Step 5: Start dynamic analysis (installs & launches app on device) ───────
  log('Step 5: Starting dynamic analysis (installing app on emulator)...');
  const startResult = await startDynamicAnalysis(hash);
  log('App installed and launched on emulator');

  // ── Step 6: Wait for app to fully boot ──────────────────────────────────────
  log('Step 6: Waiting 12 seconds for app to boot...');
  await new Promise(resolve => setTimeout(resolve, 12000));

  // ── Step 7: Apply Frida hooks (SSL bypass, root bypass, API monitor) ─────────
  log('Step 7: Applying Frida hooks...');
  const fridaResult = await fridaInstrument(hash);
  log(fridaResult ? 'Frida hooks applied successfully' : 'Frida hooks failed (non-fatal), continuing...');

  // ── Step 8: Run exported Activity tester ────────────────────────────────────
  log('Step 8: Running exported activity tester...');
  const activityExportedResult = await runActivityTester(hash, 'exported');

  // ── Step 9: Run activity tester ─────────────────────────────────────────────
  log('Step 9: Running activity tester...');
  const activityResult = await runActivityTester(hash, 'activity');

  // ── Step 10: Wait for capture period ────────────────────────────────────────
  log(`Step 10: Capturing for ${waitSeconds} seconds (network, API calls, behaviour)...`);
  await new Promise(resolve => setTimeout(resolve, waitSeconds * 1000));

  // ── Step 11: Collect Frida API monitor data ──────────────────────────────────
  log('Step 11: Collecting Frida API monitor data...');
  const apiMonitorData = await getFridaApiMonitor(hash);

  // ── Step 12: Run TLS/SSL security tests ─────────────────────────────────────
  log('Step 12: Running TLS/SSL security tests...');
  const tlsResult = await runTlsTests(hash);

  // ── Step 13: Stop dynamic analysis ──────────────────────────────────────────
  log('Step 13: Stopping dynamic analysis (finalising capture)...');
  await stopDynamicAnalysis(hash);

  // ── Step 14: Wait for MobSF to fully commit dynamic data ────────────────────
  log('Step 14: Waiting 5 seconds for MobSF to save dynamic results...');
  await new Promise(resolve => setTimeout(resolve, 5000));

  // ── Step 15: Collect Frida logs ──────────────────────────────────────────────
  log('Step 15: Collecting Frida logs...');
  const fridaLogs = await getFridaLogs(hash);

  // ── Step 16: Get dynamic JSON report (triggers report compilation in MobSF) ──
  log('Step 16: Fetching dynamic JSON report...');
  let dynamicReport = null;
  let reportRetries = 3;
  while (reportRetries > 0) {
    try {
      dynamicReport = await getDynamicReportJson(hash);
      if (dynamicReport) break;
    } catch (e) {
      reportRetries--;
      if (reportRetries > 0) {
        log(`Report fetch attempt failed, retrying in 3s...`);
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
    }
  }

  // ── Step 17: Cleanup — unset proxy ──────────────────────────────────────────
  log('Step 17: Unsetting global proxy (cleanup)...');
  await setGlobalProxy('unset');

  const elapsed = Math.round((Date.now() - startTime) / 1000);
  log(`=== Dynamic Analysis Pipeline COMPLETE (${elapsed}s) ===`);

  return {
    deviceIdentifier,
    proxyInfo,
    mobsfyResult,
    rootCAResult,
    proxyResult,
    startResult,
    fridaResult,
    activityExportedResult,
    activityResult,
    apiMonitorData,
    tlsResult,
    fridaLogs,
    dynamicReport
  };
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
// Log module initialization
log("MobSF module loaded", {
  MOBSF_URL,
  API_KEY_SET: !!API_KEY,
  functions: [
    'uploadToMobSF', 'scanWithMobSF', 'getJsonReport', 'getPdfReport',
    'deleteScan', 'checkConnection', 'analyzeAppWithMobSF', 'testMobSFConnection',
    'getDynamicApps', 'startDynamicAnalysis', 'stopDynamicAnalysis', 'getDynamicReportJson',
    'mobsfyAndroid', 'installRootCA', 'setGlobalProxy', 'runTlsTests',
    'fridaInstrument', 'getFridaApiMonitor', 'getFridaLogs', 'runActivityTester',
    'isReadyForDynamicAnalysis', 'runFullDynamicAnalysis'
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
  testMobSFConnection,
  // Dynamic analysis
  getDynamicApps,
  startDynamicAnalysis,
  stopDynamicAnalysis,
  getDynamicReportJson,
  mobsfyAndroid,
  installRootCA,
  setGlobalProxy,
  runTlsTests,
  fridaInstrument,
  getFridaApiMonitor,
  getFridaLogs,
  runActivityTester,
  isReadyForDynamicAnalysis,
  runFullDynamicAnalysis
};