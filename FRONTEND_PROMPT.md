# 🎯 FRONTEND IMPLEMENTATION PROMPT

## Your Task: Auto-Upload APK & Block High-Risk Apps

**Backend Status**: ✅ READY  
**Detection Trigger**: Apps with ≥30 detection engines  
**Estimated Time**: 3-4 hours  

---

## PART 1: Auto-Upload APK Service

### What It Does
When an app with ≥30 detections is found, automatically upload its APK to backend for analysis.

### Implementation Steps

**1. Create AutoUploadService**
```typescript
class AutoUploadService {
  async startAutoUploadListener() {
    // Poll every 5 seconds: GET /api/block-upload/auto-upload-requests
    // For each pending request:
    // 1. Update status → "in_progress"
    // 2. Get APK file from device (NATIVE CODE)
    // 3. Upload to POST /uploadapp
    // 4. Update status → "completed"
  }
}
```

**2. Poll This Endpoint**
```
GET /api/block-upload/auto-upload-requests
```

**Response Example**:
```json
{
  "count": 1,
  "requests": [{
    "id": "auto_upload_com.malicious.app_123",
    "appName": "Malicious App",
    "packageName": "com.malicious.app",
    "detectedEngines": 45,
    "status": "pending"
  }]
}
```

**3. For Each Request Do This**:
```javascript
// Step A: Tell backend you're uploading
PUT /api/block-upload/auto-upload-requests/{requestId}
Body: { "status": "in_progress" }

// Step B: Get APK from device (NATIVE ANDROID CODE)
const apkFile = await nativeAndroid.getApk("com.malicious.app");

// Step C: Upload to backend
POST /uploadapp
Form Data: {
  apk: [APK File],
  metadata: {
    appName: "...",
    packageName: "...",
    source: "auto_upload_high_risk"
  }
}

// Step D: Tell backend you finished
PUT /api/block-upload/auto-upload-requests/{requestId}
Body: {
  "status": "completed",
  "apkFileName": "com.malicious.app_1704067200.apk"
}
```

**4. Native Android Code Needed**
```kotlin
// Get APK file from installed app
fun getInstalledAppApk(packageName: String): File {
    val packageInfo = packageManager.getPackageInfo(packageName, 0)
    val apkPath = packageInfo.applicationInfo.sourceDir
    return File(apkPath)
}
```

---

## PART 2: App Blocking Service

### What It Does
When an app with ≥30 detections is found, automatically block it on the user's phone.

### Implementation Steps

**1. Create BlockService**
```typescript
class BlockService {
  async startBlockListener(deviceId: string) {
    // Poll every 3 seconds: GET /api/block-upload/block-requests/device/{deviceId}
    // For each pending block:
    // 1. Update status → "processing"
    // 2. Block the app (NATIVE CODE)
    // 3. Show alert to user
    // 4. Update status → "completed"
  }
}
```

**2. Poll This Endpoint**
```
GET /api/block-upload/block-requests/device/{deviceId}
```

**Response Example**:
```json
{
  "count": 1,
  "requests": [{
    "id": "block_com.malicious.app_456",
    "appName": "Dangerous Malware",
    "packageName": "com.malicious.app",
    "detectedEngines": 62,
    "status": "pending",
    "detailsForUser": {
      "threat_level": "CRITICAL",
      "why_blocked": "Detected by 62 antivirus engines"
    }
  }]
}
```

**3. For Each Request Do This**:
```javascript
// Step A: Tell backend you're blocking
PUT /api/block-upload/block-requests/{requestId}
Body: { "status": "processing" }

// Step B: Block the app (NATIVE ANDROID CODE)
await nativeAndroid.blockApp("com.malicious.app");

// Step C: Show alert to user
alert("🛑 SECURITY ALERT\nThis app has been blocked due to ${detectedEngines} malware detections");

// Step D: Tell backend you finished
PUT /api/block-upload/block-requests/{requestId}
Body: {
  "status": "completed",
  "blocked_at": "2024-01-02T10:35:30Z",
  "deviceId": "device-id-123"
}
```

**4. Native Android Code Needed**
```kotlin
// Block/disable an app from running
fun blockApp(packageName: String) {
    val pm = getSystemService(Context.PACKAGE_SERVICE) as PackageManager
    pm.setApplicationEnabledSetting(
        packageName,
        PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER,
        0
    )
}
```

---

## PART 3: Integrate Into React App

```jsx
import { useEffect } from 'react';
import AutoUploadService from './services/AutoUploadService';
import BlockService from './services/BlockService';

function App() {
  useEffect(() => {
    // Start services when app loads
    const autoUpload = new AutoUploadService();
    autoUpload.startAutoUploadListener();
    
    const blocker = new BlockService();
    blocker.startBlockListener('device-id-123'); // Use your actual device ID
  }, []);

  return <YourAppComponent />;
}
```

---

## Complete Code Template

### AutoUploadService.ts
```typescript
export class AutoUploadService {
  async startAutoUploadListener() {
    setInterval(async () => {
      const res = await fetch('/api/block-upload/auto-upload-requests');
      const data = await res.json();
      
      for (const req of data.requests) {
        await this.handleRequest(req);
      }
    }, 5000);
  }

  private async handleRequest(req: any) {
    try {
      // 1. Start
      await this.updateStatus(req.id, 'in_progress');
      
      // 2. Get APK
      const apk = await this.getApkFromDevice(req.packageName);
      
      // 3. Upload
      const form = new FormData();
      form.append('apk', apk);
      form.append('metadata', JSON.stringify({
        appName: req.appName,
        packageName: req.packageName,
        source: 'auto_upload_high_risk'
      }));
      await fetch('/uploadapp', { method: 'POST', body: form });
      
      // 4. Complete
      await this.updateStatus(req.id, 'completed', req.id);
    } catch (err) {
      await this.updateStatus(req.id, 'failed', req.id, err.message);
    }
  }

  private async getApkFromDevice(packageName: string) {
    // NATIVE CODE: return File
    return new Promise((resolve, reject) => {
      window.NativeAndroid?.getApk?.(packageName, resolve, reject);
    });
  }

  private async updateStatus(id: string, status: string, ...extra: any[]) {
    await fetch(`/api/block-upload/auto-upload-requests/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, ...(extra[1] && { error: extra[1] }) })
    });
  }
}
```

### BlockService.ts
```typescript
export class BlockService {
  private deviceId: string = '';

  async startBlockListener(deviceId: string) {
    this.deviceId = deviceId;
    setInterval(async () => {
      const res = await fetch(
        `/api/block-upload/block-requests/device/${deviceId}`
      );
      const data = await res.json();
      
      for (const req of data.requests) {
        await this.handleRequest(req);
      }
    }, 3000);
  }

  private async handleRequest(req: any) {
    try {
      // 1. Start
      await this.updateStatus(req.id, 'processing');
      
      // 2. Block app
      await this.blockAppOnDevice(req.packageName);
      
      // 3. Alert user
      alert(`🛑 SECURITY ALERT\n${req.detailsForUser.why_blocked}`);
      
      // 4. Complete
      await this.updateStatus(req.id, 'completed');
    } catch (err) {
      await this.updateStatus(req.id, 'failed', err.message);
    }
  }

  private async blockAppOnDevice(packageName: string) {
    return new Promise((resolve, reject) => {
      window.NativeAndroid?.blockApp?.(packageName, resolve, reject);
    });
  }

  private async updateStatus(id: string, status: string, error?: string) {
    const body: any = { status, deviceId: this.deviceId };
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

## Checklist

- [ ] AutoUploadService created and polling
- [ ] BlockService created and polling
- [ ] Native Android code: getInstalledAppApk()
- [ ] Native Android code: blockApp()
- [ ] React component using both services
- [ ] Test with app detection ≥ 30
- [ ] APK uploads automatically
- [ ] App blocks automatically
- [ ] User sees alerts
- [ ] No duplicate uploads
- [ ] No duplicate blocks

---

## Testing

**1. Verify backend is running:**
```bash
npm start
```

**2. Test endpoints:**
```bash
curl http://localhost:5000/api/block-upload/auto-upload-requests
curl http://localhost:5000/api/block-upload/block-requests
```

**3. Simulate high-risk app:**
```bash
curl -X POST http://localhost:5000/api/app/upload \
  -H "Content-Type: application/json" \
  -d '{
    "userApps": [{
      "appName": "Test App",
      "packageName": "com.test.app",
      "sha256": "abc123",
      "sizeMB": 5
    }],
    "systemApps": []
  }'
```

**4. Check requests appear:**
```bash
curl http://localhost:5000/api/block-upload/auto-upload-requests
```

---

## That's It! 🎉

**Summary**:
- 2 services (AutoUploadService, BlockService)
- 2 native Android functions (getApk, blockApp)
- 1 React component integration
- Total time: 3-4 hours

**Result**: High-risk apps auto-uploaded and auto-blocked! ✅
