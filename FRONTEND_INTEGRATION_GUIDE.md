# Frontend Integration Guide: Auto-Upload & App Blocking

## Overview

This guide explains how to implement auto-upload APK functionality and app blocking on the frontend when an app with detection ratio >= 30 is detected.

---

## Part 1: Auto-Upload APK Request Handling

### 1.1 Backend Endpoints

#### Get Pending Auto-Upload Requests
```
GET /api/block-upload/auto-upload-requests
```

**Response:**
```json
{
  "message": "Auto-upload requests retrieved",
  "count": 2,
  "requests": [
    {
      "id": "auto_upload_com.example.app_1704067200000",
      "type": "auto_upload_request",
      "source": "high_risk_detection",
      "status": "pending",
      "priority": "critical",
      "appName": "Malicious App",
      "packageName": "com.example.app",
      "sha256": "abc123...",
      "detectionRatio": "45/70",
      "totalEngines": 70,
      "detectedEngines": 45,
      "createdAt": "2024-01-02T10:30:00Z",
      "updatedAt": "2024-01-02T10:30:00Z",
      "message": "APK auto-upload initiated - 45 detection engines found. This app will be analyzed for deeper threats."
    }
  ]
}
```

#### Update Auto-Upload Request Status
```
PUT /api/block-upload/auto-upload-requests/{requestId}
```

**Request Body:**
```json
{
  "status": "in_progress",  // or "completed" or "failed"
  "message": "APK upload started",
  "apkFilePath": "/path/to/uploaded/file.apk",
  "apkFileName": "com.example.app_1704067200.apk",
  "error": null
}
```

**Response:**
```json
{
  "message": "Auto-upload request in_progress",
  "requestId": "auto_upload_com.example.app_1704067200000",
  "status": "in_progress"
}
```

### 1.2 Frontend Implementation Steps

#### Step 1: Periodically Check for Auto-Upload Requests

```javascript
// service/autoUploadService.ts or .js
export class AutoUploadService {
  private checkInterval: number = 5000; // Check every 5 seconds
  private isChecking: boolean = false;

  async startAutoUploadListener(onRequestsFound?: (requests: any[]) => void) {
    setInterval(async () => {
      if (this.isChecking) return;
      this.isChecking = true;

      try {
        const response = await fetch('/api/block-upload/auto-upload-requests');
        const data = await response.json();
        
        if (data.count > 0) {
          console.log('📥 Found auto-upload requests:', data.requests);
          
          // Handle each auto-upload request
          for (const request of data.requests) {
            await this.handleAutoUploadRequest(request);
          }
          
          if (onRequestsFound) {
            onRequestsFound(data.requests);
          }
        }
      } catch (error) {
        console.error('Error checking auto-upload requests:', error);
      } finally {
        this.isChecking = false;
      }
    }, this.checkInterval);
  }

  private async handleAutoUploadRequest(request: any) {
    try {
      // 1. Update status to "in_progress"
      await this.updateRequestStatus(request.id, 'in_progress', 
        'Retrieving APK file from device...');

      // 2. Get APK from device storage using package name
      const apkFile = await this.getApkFromDevice(request.packageName);

      // 3. Upload APK to backend
      const uploadResult = await this.uploadApkToBackend(apkFile, request);

      // 4. Update status to "completed"
      await this.updateRequestStatus(request.id, 'completed',
        `APK uploaded successfully: ${uploadResult.fileName}`,
        uploadResult.filePath,
        uploadResult.fileName
      );

      console.log(`✅ Auto-upload completed for: ${request.appName}`);

    } catch (error) {
      console.error(`❌ Auto-upload failed for ${request.appName}:`, error);
      
      // Update status to "failed"
      await this.updateRequestStatus(request.id, 'failed',
        `Failed to upload APK: ${error.message}`,
        null,
        null,
        error.message
      );
    }
  }

  private async getApkFromDevice(packageName: string): Promise<File> {
    // Implementation depends on your Android app's capability
    // This should retrieve the APK file from the device's storage
    // where the app is installed.

    // Example pseudo-code:
    // const apk = await NativeModule.getInstalledAppApk(packageName);
    // return new File([apk.data], `${packageName}.apk`, { type: 'application/vnd.android.package-archive' });
    
    throw new Error('Not implemented - implement in your Android app');
  }

  private async uploadApkToBackend(apkFile: File, request: any): Promise<any> {
    const formData = new FormData();
    formData.append('apk', apkFile);
    
    // Include metadata
    const metadata = {
      appName: request.appName,
      packageName: request.packageName,
      sha256: request.sha256,
      sizeMB: apkFile.size / (1024 * 1024),
      source: 'auto_upload_high_risk'
    };
    formData.append('metadata', JSON.stringify(metadata));

    const response = await fetch('/uploadapp', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      throw new Error(`Upload failed: ${response.statusText}`);
    }

    return await response.json();
  }

  private async updateRequestStatus(
    requestId: string,
    status: 'pending' | 'in_progress' | 'completed' | 'failed',
    message?: string,
    apkFilePath?: string,
    apkFileName?: string,
    error?: string
  ): Promise<void> {
    const body: any = { status };
    if (message) body.message = message;
    if (apkFilePath) body.apkFilePath = apkFilePath;
    if (apkFileName) body.apkFileName = apkFileName;
    if (error) body.error = error;

    const response = await fetch(`/api/block-upload/auto-upload-requests/${requestId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      throw new Error(`Failed to update request status: ${response.statusText}`);
    }

    return await response.json();
  }
}
```

#### Step 2: Use in Your App (React Example)

```jsx
import { useEffect, useState } from 'react';
import { AutoUploadService } from './service/autoUploadService';

function App() {
  const [autoUploadService] = useState(() => new AutoUploadService());
  const [pendingRequests, setPendingRequests] = useState([]);

  useEffect(() => {
    // Start listening for auto-upload requests when app loads
    autoUploadService.startAutoUploadListener((requests) => {
      setPendingRequests(requests);
      // Show notification to user
      showNotification('Auto-uploading high-risk apps for analysis...');
    });
  }, []);

  return (
    <div>
      {pendingRequests.length > 0 && (
        <div className="notification">
          <p>📥 Auto-uploading {pendingRequests.length} high-risk app(s)...</p>
        </div>
      )}
      {/* Rest of your app */}
    </div>
  );
}
```

---

## Part 2: App Blocking Implementation

### 2.1 Backend Endpoints

#### Get Pending Block Requests
```
GET /api/block-upload/block-requests
```

**Response:**
```json
{
  "message": "Block requests retrieved",
  "count": 1,
  "requests": [
    {
      "id": "block_com.malicious.app_1704067200000",
      "type": "block_app_request",
      "source": "high_risk_detection",
      "status": "pending",
      "priority": "critical",
      "appName": "Dangerous Malware",
      "packageName": "com.malicious.app",
      "sha256": "xyz789...",
      "detectionRatio": "62/70",
      "totalEngines": 70,
      "detectedEngines": 62,
      "deviceId": "device-id-123",
      "createdAt": "2024-01-02T10:35:00Z",
      "updatedAt": "2024-01-02T10:35:00Z",
      "message": "CRITICAL: App blocked due to 62 detection engines. This app poses high security risk and has been blocked from your device.",
      "reason": "high_risk_detection",
      "detailsForUser": {
        "threat_level": "CRITICAL",
        "detection_count": 62,
        "recommended_action": "uninstall",
        "why_blocked": "This app was detected as potentially malicious by 62 antivirus engines. For your security, it has been automatically blocked."
      }
    }
  ]
}
```

#### Get Block Requests for Specific Device
```
GET /api/block-upload/block-requests/device/{deviceId}
```

#### Update Block Request Status
```
PUT /api/block-upload/block-requests/{requestId}
```

**Request Body:**
```json
{
  "status": "processing",  // or "completed" or "failed"
  "message": "App blocking initiated",
  "blocked_at": "2024-01-02T10:35:30Z",
  "deviceId": "device-id-123",
  "error": null
}
```

### 2.2 Frontend Implementation Steps

#### Step 1: Periodically Check for Block Requests

```javascript
// service/blockService.ts or .js
export class BlockService {
  private checkInterval: number = 3000; // Check every 3 seconds
  private isChecking: boolean = false;
  private deviceId: string = ''; // Set this from your device

  async startBlockListener(deviceId: string, onBlocksFound?: (blocks: any[]) => void) {
    this.deviceId = deviceId;

    setInterval(async () => {
      if (this.isChecking) return;
      this.isChecking = true;

      try {
        const response = await fetch(`/api/block-upload/block-requests/device/${deviceId}`);
        const data = await response.json();
        
        if (data.count > 0) {
          console.log('🛑 Found block requests:', data.requests);
          
          // Handle each block request
          for (const request of data.requests) {
            await this.handleBlockRequest(request);
          }
          
          if (onBlocksFound) {
            onBlocksFound(data.requests);
          }
        }
      } catch (error) {
        console.error('Error checking block requests:', error);
      } finally {
        this.isChecking = false;
      }
    }, this.checkInterval);
  }

  private async handleBlockRequest(request: any) {
    try {
      // 1. Update status to "processing"
      await this.updateBlockStatus(request.id, 'processing',
        `Blocking app: ${request.appName}...`);

      // 2. Block the app on device using native code
      await this.blockAppOnDevice(request.packageName);

      // 3. Show critical alert to user
      this.showBlockAlert(request);

      // 4. Update status to "completed"
      await this.updateBlockStatus(request.id, 'completed',
        `App has been blocked: ${request.appName}`,
        new Date().toISOString()
      );

      console.log(`✅ App blocked: ${request.appName}`);

    } catch (error) {
      console.error(`❌ Block failed for ${request.appName}:`, error);
      
      // Update status to "failed"
      await this.updateBlockStatus(request.id, 'failed',
        `Failed to block app: ${error.message}`,
        null,
        error.message
      );
    }
  }

  private async blockAppOnDevice(packageName: string): Promise<void> {
    // Implementation depends on your Android app's capability
    // This should disable/block the app from running

    // Example pseudo-code using native Android module:
    // await NativeModule.blockApp(packageName);
    // This might involve:
    // - Disabling the app
    // - Removing it from launcher
    // - Blocking it in app switcher
    // - Preventing it from running in background

    return new Promise((resolve, reject) => {
      // Call your native Android method
      window.NativeAndroid?.blockApp?.(
        packageName,
        () => resolve(),
        (error: string) => reject(new Error(error))
      );
    });
  }

  private showBlockAlert(request: any) {
    // Show a critical alert to the user
    alert(`🛑 CRITICAL SECURITY ALERT\n\n` +
          `${request.detailsForUser.why_blocked}\n\n` +
          `Threat Level: ${request.detailsForUser.threat_level}\n` +
          `Detection Engines: ${request.detailsForUser.detection_count}\n` +
          `Recommended Action: ${request.detailsForUser.recommended_action}`);

    // Or use a more sophisticated notification system:
    // showCriticalNotification({
    //   title: '🛑 SECURITY ALERT',
    //   message: request.message,
    //   details: request.detailsForUser,
    //   duration: 0 // Don't auto-dismiss
    // });
  }

  private async updateBlockStatus(
    requestId: string,
    status: 'pending' | 'processing' | 'completed' | 'failed',
    message?: string,
    blocked_at?: string,
    error?: string
  ): Promise<void> {
    const body: any = { status, deviceId: this.deviceId };
    if (message) body.message = message;
    if (blocked_at) body.blocked_at = blocked_at;
    if (error) body.error = error;

    const response = await fetch(`/api/block-upload/block-requests/${requestId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      throw new Error(`Failed to update block status: ${response.statusText}`);
    }

    return await response.json();
  }
}
```

#### Step 2: Use in Your App (React Example)

```jsx
import { useEffect, useState } from 'react';
import { BlockService } from './service/blockService';

function SecurityDashboard() {
  const [blockService] = useState(() => new BlockService());
  const [blockedApps, setBlockedApps] = useState([]);
  const deviceId = 'your-device-id'; // Get this from your app

  useEffect(() => {
    // Start listening for block requests when component loads
    blockService.startBlockListener(deviceId, (blocks) => {
      setBlockedApps(blocks);
    });
  }, []);

  return (
    <div>
      {blockedApps.length > 0 && (
        <div className="alert alert-danger">
          <h3>🛑 Security Alert</h3>
          <p>{blockedApps.length} high-risk app(s) have been blocked for your protection.</p>
          <ul>
            {blockedApps.map((app) => (
              <li key={app.id}>
                <strong>{app.appName}</strong> - {app.detailsForUser.why_blocked}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
```

---

## Part 3: Complete Integration Flow

### Flow Diagram

```
User Device → Send App List with SHA256
                    ↓
            Backend Scans with VirusTotal
                    ↓
        Detection >= 30 Found?
            ↙           ↘
          YES             NO
          ↓               ↓
    Create:          Just Notify
    1. Notification   User
    2. Auto-Upload Request
    3. Block Request
          ↓
    Frontend Polls for Requests
          ↓
    Auto-Upload Request?
    ├─ Get APK from device
    ├─ Upload to backend
    └─ Update status → completed
          ↓
    Block Request?
    ├─ Block app on device
    ├─ Show alert to user
    └─ Update status → completed
```

---

## Part 4: Key Points to Remember

### IDEMPOTENT CHECKS (ONLY ONCE)
- ✅ Auto-upload requests are checked to see if:
  - Request already exists for this package today
  - APK is already uploaded for this package
  - Only creates once per unique package per day

- ✅ Block requests are checked to see if:
  - Block request already exists for this package
  - Only creates once per unique package per day

### DATA TO SEND TO BACKEND

When updating auto-upload request:
```javascript
{
  status: "completed",
  message: "APK upload completed",
  apkFilePath: "/uploads/apks/com.example.app_1704067200.apk",
  apkFileName: "com.example.app_1704067200.apk"
}
```

When updating block request:
```javascript
{
  status: "completed",
  message: "App has been blocked",
  blocked_at: "2024-01-02T10:35:30Z",
  deviceId: "device-id-123"
}
```

### ERROR HANDLING
Always handle errors gracefully:
```javascript
// When auto-upload fails
updateRequestStatus(id, "failed", "Error message", null, null, errorText);

// When blocking fails
updateBlockStatus(id, "failed", "Error message", null, errorText);
```

---

## Part 5: Testing the Integration

### Backend Testing

```bash
# 1. Check if auto-upload requests are created
curl http://localhost:5000/api/block-upload/auto-upload-requests

# 2. Check if block requests are created
curl http://localhost:5000/api/block-upload/block-requests

# 3. Update a request
curl -X PUT http://localhost:5000/api/block-upload/auto-upload-requests/{id} \
  -H "Content-Type: application/json" \
  -d '{"status":"completed","apkFileName":"test.apk"}'
```

### Frontend Testing Checklist

- [ ] Auto-upload service starts on app load
- [ ] Block service starts on app load
- [ ] Requests are polled at correct intervals
- [ ] APK is successfully retrieved from device
- [ ] APK is uploaded to backend with correct metadata
- [ ] Status is updated as "in_progress" → "completed"
- [ ] App is blocked on device
- [ ] Alert is shown to user
- [ ] Status is updated as "processing" → "completed"
- [ ] No duplicate uploads or blocks occur

---

## Support Notes

If you encounter any issues:
1. Check console logs for error messages
2. Verify Elasticsearch indices are being created:
   - `auto_upload_requests_YYYY-MM-DD`
   - `block_app_requests_YYYY-MM-DD`
3. Ensure device ID is being sent correctly
4. Check network requests in browser DevTools

---
