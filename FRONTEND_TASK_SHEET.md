# 🎯 FRONTEND DEVELOPMENT TASK SHEET

## EXECUTIVE SUMMARY

Backend has implemented auto-upload and app blocking for high-risk apps (≥30 detection engines).

**Status**: Backend ✅ READY
**Next Step**: Frontend implementation
**Timeline**: 2-3 hours
**Complexity**: Medium (requires native Android integration)

---

## TASK 1: Create AutoUploadService

**Purpose**: Automatically upload APK of high-risk apps to backend for analysis

**What it does**:
1. Polls `/api/block-upload/auto-upload-requests` every 5 seconds
2. For each pending request:
   - Gets APK file from device (NATIVE CODE)
   - Uploads to `/uploadapp` endpoint
   - Updates backend when complete

**Methods needed**:
```typescript
class AutoUploadService {
  startAutoUploadListener(callback?) // Start polling
  handleAutoUploadRequest(request)   // Handle one request
  getApkFromDevice(packageName)      // NATIVE CODE - Get APK
  uploadApkToBackend(file, metadata) // Upload APK
  updateRequestStatus(id, status)    // Tell backend we're done
}
```

**Request Example**:
```json
GET /api/block-upload/auto-upload-requests

Response:
{
  "count": 1,
  "requests": [{
    "id": "auto_upload_com.app_123",
    "appName": "Malicious App",
    "packageName": "com.malicious.app",
    "detectedEngines": 45,
    "status": "pending",
    "message": "APK auto-upload initiated..."
  }]
}
```

**Update Example**:
```json
PUT /api/block-upload/auto-upload-requests/{id}

Request Body:
{
  "status": "in_progress",
  "message": "Uploading APK..."
}

Then later:
{
  "status": "completed",
  "message": "APK uploaded successfully",
  "apkFileName": "com.app_1704067200.apk",
  "apkFilePath": "/uploads/apks/com.app_1704067200.apk"
}
```

**Code Template**:
```typescript
class AutoUploadService {
  private checkInterval = 5000;
  
  async startAutoUploadListener(onFound) {
    setInterval(async () => {
      const response = await fetch('/api/block-upload/auto-upload-requests');
      const data = await response.json();
      
      for (const request of data.requests) {
        await this.handleAutoUploadRequest(request);
      }
      
      if (onFound) onFound(data.requests);
    }, this.checkInterval);
  }
  
  private async handleAutoUploadRequest(request) {
    try {
      // 1. Update to in_progress
      await this.updateRequestStatus(request.id, 'in_progress');
      
      // 2. Get APK from device
      const apkFile = await this.getApkFromDevice(request.packageName);
      
      // 3. Upload to backend
      await this.uploadApkToBackend(apkFile, request);
      
      // 4. Update to completed
      await this.updateRequestStatus(request.id, 'completed');
    } catch (error) {
      // Update to failed with error
      await this.updateRequestStatus(request.id, 'failed', error.message);
    }
  }
  
  private async getApkFromDevice(packageName) {
    // TODO: Call native Android code to get APK
    // Example: window.NativeAndroid.getApk(packageName)
  }
  
  private async uploadApkToBackend(file, metadata) {
    const formData = new FormData();
    formData.append('apk', file);
    formData.append('metadata', JSON.stringify({
      appName: metadata.appName,
      packageName: metadata.packageName,
      source: 'auto_upload_high_risk'
    }));
    
    const response = await fetch('/uploadapp', {
      method: 'POST',
      body: formData
    });
    
    return await response.json();
  }
  
  private async updateRequestStatus(id, status, error = null) {
    const body = { status };
    if (error) body.error = error;
    
    await fetch(`/api/block-upload/auto-upload-requests/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }
}
```

---

## TASK 2: Create BlockService

**Purpose**: Block high-risk apps on user's phone automatically

**What it does**:
1. Polls `/api/block-upload/block-requests/device/{deviceId}` every 3 seconds
2. For each pending block request:
   - Blocks the app on device (NATIVE CODE)
   - Shows critical alert to user
   - Updates backend when complete

**Methods needed**:
```typescript
class BlockService {
  startBlockListener(deviceId, callback?)    // Start polling
  handleBlockRequest(request)                // Handle one request
  blockAppOnDevice(packageName)              // NATIVE CODE - Block app
  showBlockAlert(request)                    // Show alert to user
  updateBlockStatus(id, status, deviceId)   // Tell backend we're done
}
```

**Request Example**:
```json
GET /api/block-upload/block-requests/device/device-id-123

Response:
{
  "count": 1,
  "requests": [{
    "id": "block_com.app_456",
    "appName": "Dangerous Malware",
    "packageName": "com.malicious.app",
    "detectedEngines": 62,
    "status": "pending",
    "detailsForUser": {
      "threat_level": "CRITICAL",
      "why_blocked": "Detected by 62 antivirus engines",
      "recommended_action": "uninstall"
    }
  }]
}
```

**Update Example**:
```json
PUT /api/block-upload/block-requests/{id}

Request Body:
{
  "status": "processing",
  "message": "Blocking app...",
  "deviceId": "device-id-123"
}

Then later:
{
  "status": "completed",
  "message": "App has been blocked",
  "blocked_at": "2024-01-02T10:35:30Z",
  "deviceId": "device-id-123"
}
```

**Code Template**:
```typescript
class BlockService {
  private checkInterval = 3000;
  private deviceId = '';
  
  async startBlockListener(deviceId, onFound) {
    this.deviceId = deviceId;
    
    setInterval(async () => {
      const response = await fetch(
        `/api/block-upload/block-requests/device/${deviceId}`
      );
      const data = await response.json();
      
      for (const request of data.requests) {
        await this.handleBlockRequest(request);
      }
      
      if (onFound) onFound(data.requests);
    }, this.checkInterval);
  }
  
  private async handleBlockRequest(request) {
    try {
      // 1. Update to processing
      await this.updateBlockStatus(request.id, 'processing');
      
      // 2. Block the app
      await this.blockAppOnDevice(request.packageName);
      
      // 3. Show alert to user
      this.showBlockAlert(request);
      
      // 4. Update to completed
      await this.updateBlockStatus(request.id, 'completed');
    } catch (error) {
      // Update to failed with error
      await this.updateBlockStatus(request.id, 'failed', error.message);
    }
  }
  
  private async blockAppOnDevice(packageName) {
    // TODO: Call native Android code to block app
    // Example: window.NativeAndroid.blockApp(packageName)
  }
  
  private showBlockAlert(request) {
    alert(
      `🛑 SECURITY ALERT\n\n` +
      `${request.detailsForUser.why_blocked}\n\n` +
      `Threat Level: ${request.detailsForUser.threat_level}\n` +
      `Detected by: ${request.detectedEngines} engines\n` +
      `Action: ${request.detailsForUser.recommended_action}`
    );
  }
  
  private async updateBlockStatus(id, status, error = null) {
    const body = { status, deviceId: this.deviceId };
    if (error) body.error = error;
    
    await fetch(`/api/block-upload/block-requests/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }
}
```

---

## TASK 3: Native Android Code

**What you need to implement**:

### 1. Get APK from Installed App
```kotlin
// Return the APK file of an installed app
fun getInstalledAppApk(packageName: String): File {
    // Get APK path from package info
    val packageInfo = packageManager.getPackageInfo(packageName, 0)
    val apkPath = packageInfo.applicationInfo.sourceDir
    return File(apkPath)
}

// OR use this JavaScript bridge:
window.NativeAndroid.getApk(packageName, 
  (apkFile) => { /* success */ },
  (error) => { /* error */ }
)
```

### 2. Block App
```kotlin
// Disable/block an app from running
fun blockApp(packageName: String) {
    val pm = getSystemService(Context.PACKAGE_SERVICE) as PackageManager
    
    // Option 1: Using device admin (most secure)
    val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    dpm.removeActiveAdmin(componentName) // requires device admin
    
    // Option 2: Disable user app
    pm.setApplicationEnabledSetting(
        packageName,
        PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
        0
    )
    
    // Option 3: Stop the app
    val activityManager = getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    activityManager.killBackgroundProcesses(packageName)
}

// OR use this JavaScript bridge:
window.NativeAndroid.blockApp(packageName,
  () => { /* success */ },
  (error) => { /* error */ }
)
```

---

## TASK 4: React/Vue Component Integration

**Example (React)**:
```jsx
import { useEffect, useState } from 'react';
import { AutoUploadService } from './services/autoUploadService';
import { BlockService } from './services/blockService';

function SecurityManager() {
  const [autoUploadService] = useState(() => new AutoUploadService());
  const [blockService] = useState(() => new BlockService());
  const [uploading, setUploading] = useState(false);
  const [blocked, setBlocked] = useState([]);
  
  const deviceId = 'your-device-id'; // Get from your app
  
  useEffect(() => {
    // Start auto-upload listener
    autoUploadService.startAutoUploadListener((requests) => {
      setUploading(requests.length > 0);
    });
    
    // Start block listener
    blockService.startBlockListener(deviceId, (blocks) => {
      setBlocked(blocks);
    });
  }, []);
  
  return (
    <div>
      {uploading && (
        <div className="info-banner">
          📥 Auto-uploading high-risk apps for analysis...
        </div>
      )}
      
      {blocked.length > 0 && (
        <div className="alert-banner danger">
          <h3>🛑 Security Alert</h3>
          <p>{blocked.length} app(s) have been blocked for your protection</p>
          {blocked.map(app => (
            <div key={app.id}>
              <strong>{app.appName}</strong> - {app.detailsForUser.threat_level}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default SecurityManager;
```

---

## ACCEPTANCE CRITERIA

- ✅ AutoUploadService polls correctly and uploads APKs
- ✅ BlockService polls correctly and blocks apps
- ✅ Status updates are sent back to backend correctly
- ✅ No duplicate uploads for same app (idempotent)
- ✅ No duplicate blocks for same app (idempotent)
- ✅ User is notified when app is blocked
- ✅ Errors are handled gracefully
- ✅ Services work without interruption

---

## TESTING STEPS

1. **Start Backend**: `npm start`
2. **Test Endpoints**: `node test-implementation.js`
3. **Simulate High-Risk App**: Send app with detection >= 30
4. **Check Requests Created**: 
   - `curl http://localhost:5000/api/block-upload/auto-upload-requests`
   - `curl http://localhost:5000/api/block-upload/block-requests/device/test-device`
5. **Test Auto-Upload**: Implement and run AutoUploadService
6. **Test Blocking**: Implement and run BlockService
7. **Verify Status Updates**: Check backend received status updates

---

## HELPFUL RESOURCES

- **Complete Code Examples**: See `FRONTEND_INTEGRATION_GUIDE.md`
- **API Reference**: See `QUICK_START.md`
- **Implementation Details**: See `IMPLEMENTATION_SUMMARY.md`

---

## KEY DEADLINES / MILESTONES

- [ ] Task 1: AutoUploadService created and tested (Day 1)
- [ ] Task 2: BlockService created and tested (Day 1)
- [ ] Task 3: Native Android code implemented (Day 2)
- [ ] Task 4: React component integration complete (Day 2)
- [ ] Final testing and bug fixes (Day 3)

---

## QUESTIONS?

If you have any questions:
1. Check `FRONTEND_INTEGRATION_GUIDE.md` - has all code examples
2. Run `node test-implementation.js` to verify backend is working
3. Check browser console for network request errors
4. Check backend logs for API errors

**Good luck! 🚀**
