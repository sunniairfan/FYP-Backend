# Implementation Summary: Auto-Upload & App Blocking

## ✅ What Has Been Implemented on Backend

### 1. **Auto-Upload APK for High-Risk Apps (Detection >= 30)**
   - ✅ New utility functions in `utils/analysisRequests.js`:
     - `createAutoUploadRequest()` - Creates auto-upload request (IDEMPOTENT)
     - `hasAutoUploadRequestForPackage()` - Checks if request already exists
     - `getAutoUploadRequestsIndexName()` - Gets the daily index name
   
   - ✅ Integration in `controllers/appController.js`:
     - Auto-upload requests created when detection >= 30
     - Only creates once per unique package per day
     - Checks if APK already uploaded before creating request

   - ✅ Elasticsearch Index: `auto_upload_requests_YYYY-MM-DD`
     - Stores: appName, packageName, sha256, detectionRatio, detectedEngines, etc.

### 2. **App Blocking for High-Risk Apps (Detection >= 30)**
   - ✅ New utility functions in `utils/analysisRequests.js`:
     - `createBlockRequest()` - Creates block request (IDEMPOTENT)
     - `hasBlockRequestForPackage()` - Checks if request already exists
     - `getBlockRequestsIndexName()` - Gets the daily index name
   
   - ✅ Integration in `controllers/appController.js`:
     - Block requests created when detection >= 30
     - Only creates once per unique package per day
     - Includes detailed threat information for user

   - ✅ Elasticsearch Index: `block_app_requests_YYYY-MM-DD`
     - Stores: appName, packageName, reason, threat_level, recommended_action, etc.

### 3. **Frontend Request API Endpoints**
   - ✅ New route file: `routes/blockAndUploadRoutes.js`
   
   - **Auto-Upload Endpoints:**
     - `GET /api/block-upload/auto-upload-requests` - Get pending uploads
     - `PUT /api/block-upload/auto-upload-requests/{id}` - Update status
   
   - **Block Endpoints:**
     - `GET /api/block-upload/block-requests` - Get all pending blocks
     - `GET /api/block-upload/block-requests/device/{deviceId}` - Get device-specific blocks
     - `PUT /api/block-upload/block-requests/{id}` - Update block status

### 4. **Server Registration**
   - ✅ Updated `server.js`:
     - Imported blockAndUploadRoutes
     - Mounted at `/api/block-upload`

---

## 📋 What Frontend Needs to Implement

### 1. **Auto-Upload Service**
```
Service Class: AutoUploadService
├─ startAutoUploadListener() - Periodically check for requests
├─ handleAutoUploadRequest() - Process each request
├─ getApkFromDevice() - Retrieve APK file (NATIVE CODE NEEDED)
├─ uploadApkToBackend() - Upload to /uploadapp endpoint
└─ updateRequestStatus() - Update backend via PUT endpoint
```

**Key Steps:**
1. Poll `/api/block-upload/auto-upload-requests` every 5 seconds
2. For each request:
   - Update status to "in_progress"
   - Retrieve APK file from device using package name (NATIVE CODE)
   - Upload to `/uploadapp` endpoint
   - Update status to "completed" or "failed"

### 2. **Block Service**
```
Service Class: BlockService
├─ startBlockListener() - Periodically check for requests
├─ handleBlockRequest() - Process each request
├─ blockAppOnDevice() - Block app (NATIVE CODE NEEDED)
├─ showBlockAlert() - Show alert to user
└─ updateBlockStatus() - Update backend via PUT endpoint
```

**Key Steps:**
1. Poll `/api/block-upload/block-requests/device/{deviceId}` every 3 seconds
2. For each request:
   - Update status to "processing"
   - Call native Android function to block the app (NATIVE CODE)
   - Show critical alert with threat details
   - Update status to "completed" or "failed"

### 3. **User Interface Updates**
- Show notification when auto-uploading apps
- Show critical alert when app is blocked
- Display threat level and recommendation to user
- Option to manually uninstall blocked app

---

## 🔄 Complete Request/Response Examples

### Auto-Upload Flow

**1. Frontend: Fetch pending requests**
```
GET /api/block-upload/auto-upload-requests
```

**Response:**
```json
{
  "count": 1,
  "requests": [{
    "id": "auto_upload_com.example.app_1704067200000",
    "appName": "Malicious App",
    "packageName": "com.example.app",
    "detectedEngines": 45,
    "status": "pending",
    "message": "APK auto-upload initiated - 45 detection engines found..."
  }]
}
```

**2. Frontend: Update to in_progress**
```
PUT /api/block-upload/auto-upload-requests/auto_upload_com.example.app_1704067200000

{
  "status": "in_progress",
  "message": "Retrieving APK from device..."
}
```

**3. Frontend: Upload APK**
```
POST /uploadapp

Form Data:
- apk: [Binary APK File]
- metadata: {"appName":"...","packageName":"...","sha256":"...","source":"auto_upload_high_risk"}
```

**4. Frontend: Update to completed**
```
PUT /api/block-upload/auto-upload-requests/auto_upload_com.example.app_1704067200000

{
  "status": "completed",
  "message": "APK uploaded successfully",
  "apkFilePath": "/uploads/apks/com.example.app_1704067200.apk",
  "apkFileName": "com.example.app_1704067200.apk"
}
```

### Block Flow

**1. Frontend: Fetch pending blocks for device**
```
GET /api/block-upload/block-requests/device/device-id-123
```

**Response:**
```json
{
  "count": 1,
  "requests": [{
    "id": "block_com.malicious.app_1704067200000",
    "appName": "Dangerous Malware",
    "packageName": "com.malicious.app",
    "detectedEngines": 62,
    "status": "pending",
    "detailsForUser": {
      "threat_level": "CRITICAL",
      "detection_count": 62,
      "why_blocked": "This app was detected as potentially malicious by 62 antivirus engines..."
    }
  }]
}
```

**2. Frontend: Update to processing**
```
PUT /api/block-upload/block-requests/block_com.malicious.app_1704067200000

{
  "status": "processing",
  "message": "Blocking app...",
  "deviceId": "device-id-123"
}
```

**3. Frontend: Call Native Android Code to Block App**
```javascript
// Example pseudo-code
window.NativeAndroid.blockApp("com.malicious.app", 
  () => updateStatus("completed"),
  (error) => updateStatus("failed", error)
);
```

**4. Frontend: Update to completed**
```
PUT /api/block-upload/block-requests/block_com.malicious.app_1704067200000

{
  "status": "completed",
  "message": "App has been blocked",
  "blocked_at": "2024-01-02T10:35:30Z",
  "deviceId": "device-id-123"
}
```

---

## ⚠️ IMPORTANT: Idempotent Checks (Only Once Per Package)

### Auto-Upload Idempotency
The backend ensures auto-upload requests are created ONLY ONCE by checking:
1. ✅ No pending auto-upload request already exists for this package
2. ✅ APK is not already uploaded for this package
3. ✅ Creates request only if detection >= 30

### Block Request Idempotency
The backend ensures block requests are created ONLY ONCE by checking:
1. ✅ No pending block request already exists for this package
2. ✅ Creates request only if detection >= 30

### Frontend Should:
1. ✅ Update status to "completed" once upload is done (won't appear again)
2. ✅ Update status to "completed" once blocking is done (won't appear again)
3. ✅ Handle "in_progress" state for recovery if app crashes mid-process
4. ✅ Check for "processing" status in block requests (in case device reboots)

---

## 📊 Database Indexes Created

The following Elasticsearch indexes are automatically created:

1. **Daily Auto-Upload Index**
   ```
   auto_upload_requests_YYYY-MM-DD
   
   Fields:
   - type: "auto_upload_request"
   - source: "high_risk_detection"
   - status: "pending", "in_progress", "completed", "failed"
   - appName, packageName, sha256
   - detectedEngines, totalEngines, detectionRatio
   - createdAt, updatedAt
   - apkFilePath, apkFileName (set by frontend on completion)
   ```

2. **Daily Block Index**
   ```
   block_app_requests_YYYY-MM-DD
   
   Fields:
   - type: "block_app_request"
   - source: "high_risk_detection"
   - status: "pending", "processing", "completed", "failed"
   - appName, packageName, sha256
   - detectedEngines, totalEngines, detectionRatio
   - deviceId
   - createdAt, updatedAt
   - blocked_at (set by frontend on completion)
   - reason, priority
   - detailsForUser (threat_level, recommendation, etc.)
   ```

---

## 🧪 Testing Checklist

### Backend Testing
- [ ] Deploy code changes to backend
- [ ] Restart Node.js server
- [ ] Test endpoint: `GET /api/block-upload/auto-upload-requests` (should be empty)
- [ ] Test endpoint: `GET /api/block-upload/block-requests` (should be empty)
- [ ] Simulate app scan with detection >= 30
- [ ] Verify auto-upload request created in Elasticsearch
- [ ] Verify block request created in Elasticsearch

### Frontend Testing
- [ ] Create AutoUploadService class
- [ ] Implement native Android code to get installed app APK
- [ ] Implement native Android code to block app
- [ ] Test polling: requests appear in console
- [ ] Test auto-upload: APK uploaded successfully
- [ ] Test blocking: app blocked on device
- [ ] Verify status updates on backend

### Integration Testing
- [ ] Run full scan from Android app
- [ ] Verify high-risk app detected
- [ ] Verify auto-upload starts automatically
- [ ] Verify app is blocked automatically
- [ ] User sees alert about blocking
- [ ] Blocked app cannot be opened
- [ ] Dashboard shows blocked app status

---

## 📝 Notes for Frontend Developer

1. **Device ID**: Make sure you're sending the correct device ID in block requests. This allows the backend to filter requests per device.

2. **APK Retrieval**: You'll need native Android code to:
   - Get the APK file from installed app location
   - Read file permissions might be needed
   - Consider how to handle if app is uninstalled

3. **App Blocking**: You'll need native Android code to:
   - Disable the app
   - Remove from launcher (optional)
   - Block in recents (optional)
   - Prevent background execution

4. **Error Handling**: Always update request status with error message if operation fails. This helps with debugging.

5. **User Feedback**: Show clear messages to user about:
   - Apps being auto-uploaded
   - Apps being blocked
   - Threat level information
   - Recommended actions (uninstall, etc.)

---

## 🚀 Prompt for Frontend Developer

Here's the prompt you can give to your frontend team:

---

### 🎯 FRONTEND IMPLEMENTATION PROMPT

**Task**: Implement auto-upload and app blocking for high-risk apps

**Backend Endpoints** (all ready):
1. `GET /api/block-upload/auto-upload-requests` - Get pending uploads
2. `PUT /api/block-upload/auto-upload-requests/{id}` - Update upload status
3. `GET /api/block-upload/block-requests` - Get pending blocks
4. `GET /api/block-upload/block-requests/device/{deviceId}` - Get device blocks
5. `PUT /api/block-upload/block-requests/{id}` - Update block status

**Frontend Services to Create**:

1. **AutoUploadService**
   - Poll `/api/block-upload/auto-upload-requests` every 5 seconds
   - For each request:
     1. Update status → "in_progress"
     2. Get APK file from device (NATIVE CODE)
     3. Upload to `/uploadapp` endpoint
     4. Update status → "completed"
   - On error: Update status → "failed" with error message

2. **BlockService**
   - Poll `/api/block-upload/block-requests/device/{deviceId}` every 3 seconds
   - For each request:
     1. Update status → "processing"
     2. Call native Android code to block app
     3. Show critical alert with threat details
     4. Update status → "completed"
   - On error: Update status → "failed" with error message

**Native Android Code Needed**:
1. `NativeAndroid.getApkFile(packageName)` - Returns File object of APK
2. `NativeAndroid.blockApp(packageName, onSuccess, onError)` - Blocks the app

**User Interface**:
- Show notification when auto-uploading
- Show critical alert when app is blocked
- Display threat level and recommendation
- Show "Uninstall" button for blocked app (optional)

---

Great! Now let me test that the server starts without errors:
