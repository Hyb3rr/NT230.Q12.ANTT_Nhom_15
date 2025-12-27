# Fileless Malware Detection - Real-time Monitoring UI

**Dashboard giám sát process tự động** - Không cần nhập input thủ công!

## 🆕 Features v2.0

### 1. **Live Monitoring Tab** 🔍
- ✅ Real-time process statistics
- ✅ Auto-refresh every 5 seconds
- ✅ Start/Stop monitoring controls
- ✅ Malware detection alerts
- ✅ MITRE ATT&CK technique details

### 2. **Manual Analysis Tab** 📝
- ✅ Traditional text input mode
- ✅ Custom threshold settings
- ✅ One-time analysis

---

## 🚀 Quick Start

### 1. Start Backend API

```bash
# Terminal 1: Start API with auto-monitoring
cd /Users/ngaphan/Desktop/MemForen/fileless
pip install psutil
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 2. Start Frontend UI

```bash
# Terminal 2: Start React UI
cd /Users/ngaphan/Desktop/MemForen/fileless/fileless-ui
npm install
npm run dev
```

### 3. Open Browser

```
http://localhost:5173
```

---

## 📊 UI Features

### Live Monitoring Dashboard

Khi vào tab **"🔍 Live Monitoring"**, bạn sẽ thấy:

#### A. Control Panel
```
┌─────────────────────────────────────────────┐
│  Process Monitor Control                   │
│  ┌──────────────┐  ┌──────────────┐        │
│  │ ▶️ Start      │  │ ⏸️ Stop       │        │
│  │  Monitoring   │  │  Monitoring   │        │
│  └──────────────┘  └──────────────┘        │
│  ✅ System is actively scanning processes   │
└─────────────────────────────────────────────┘
```

#### B. Real-time Statistics
```
┌─────────────────────────────────────────────────────────────┐
│  Real-time Monitoring                    🟢 Active          │
├─────────────────────────────────────────────────────────────┤
│  🔍              ⚠️              🚨              ✅          │
│  1,523           12              3               9           │
│  Processes       Suspicious      Malware         Benign      │
│  Scanned         Found           Detected        Processes   │
├─────────────────────────────────────────────────────────────┤
│  Analysis Queue: 0 pending  •  Monitored PIDs: 12           │
└─────────────────────────────────────────────────────────────┘
```

#### C. Malware Detections
```
┌─────────────────────────────────────────────────────────────┐
│  Malware Detections - Recent Findings (3)                   │
├─────────────────────────────────────────────────────────────┤
│  🚨 powershell.exe                        87.3% Malicious   │
│  PID: 12345 • 2024-12-16 14:30:22                          │
│                                                             │
│  Stage: Execution (Stage 1)                                │
│  Path: C:\Windows\System32\WindowsPowerShell\...           │
│  Command: powershell.exe -nop -w hidden -enc ...           │
│  Parent: winword.exe (PID: 8888)                           │
│                                                             │
│  Tactics: [Execution] [Defense Evasion]                    │
│  Techniques: [T1059.001] [T1055] [T1027]                   │
│                                                             │
│  Recommendation: ALERT: Stage 1 attack detected...         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Workflow

### Auto-Monitoring Mode (Recommended)

1. **Open browser** → `http://localhost:5173`
2. **Click tab**: "🔍 Live Monitoring"
3. **Click**: "▶️ Start Monitoring"
4. **Wait**: System auto-scans processes every 2 seconds
5. **View**: Real-time statistics update every 5 seconds
6. **Alerts**: Malware detections appear automatically

### Manual Analysis Mode (Legacy)

1. **Click tab**: "📝 Manual Analysis"
2. **Paste text**: Process info, command line, registry keys
3. **Set threshold**: 0.5 (default) or custom
4. **Click**: "Analyze"
5. **View**: Detection result with MITRE mapping

---

## 🔄 Auto-Refresh

UI tự động refresh mỗi **5 giây** khi ở tab Live Monitoring:

- ✅ Cập nhật số liệu thống kê
- ✅ Lấy danh sách malware mới phát hiện
- ✅ Kiểm tra trạng thái monitor (active/inactive)

**Không cần F5 hay reload page!**

---

## 📡 API Endpoints Used

```javascript
// Control monitoring
POST /monitor/start    // Start scanning
POST /monitor/stop     // Stop scanning

// Get data
GET /monitor/stats       // Statistics (total_scanned, suspicious_found, etc.)
GET /monitor/detections  // List of detected malware

// Legacy endpoints
POST /detect             // Manual analysis
GET /stages              // Attack stage info
GET /techniques/{id}     // MITRE technique details
```

---

## 🎨 UI Components

### Components Created

1. **MonitoringStats** - Statistics panel với 4 số liệu chính
2. **DetectionsList** - Danh sách malware đã phát hiện
3. **Tab Navigation** - Switch giữa Live Monitoring và Manual Analysis
4. **Control Panel** - Start/Stop buttons

### Auto-refresh Logic

```javascript
// Poll every 5 seconds
useEffect(() => {
  if (activeTab === 'monitor') {
    fetchMonitorStats()
    fetchDetections()
    
    const interval = setInterval(() => {
      fetchMonitorStats()
      fetchDetections()
    }, 5000) // 5 seconds
    
    return () => clearInterval(interval)
  }
}, [activeTab])
```

---

## 🛡️ Security Features

### Defensive Display

- ❌ Không hiển thị raw model weights
- ❌ Không expose internal paths
- ✅ Chỉ hiển thị detection results
- ✅ Rate limiting qua API
- ✅ Clean, sanitized output

### Process Info Displayed

```json
{
  "name": "powershell.exe",
  "pid": 12345,
  "cmdline": "powershell.exe -nop -w hidden...",
  "exe_path": "C:\\Windows\\System32\\...",
  "parent_name": "winword.exe",
  "parent_pid": 8888,
  "cpu_percent": 45.2,
  "memory_mb": 156.7,
  "connections": [...]
}
```

---

## 🔧 Configuration

### API Endpoint

File: `.env`
```bash
VITE_API_BASE=http://127.0.0.1:8000
```

### Polling Interval

File: `src/App.jsx`
```javascript
const POLL_INTERVAL = 5000  // 5 seconds (adjust if needed)
```

### Auto-start Monitoring

Backend: Set environment variable
```bash
# Auto-start on API launch
AUTO_MONITOR=true uvicorn app:app --port 8000

# Or disable
AUTO_MONITOR=false uvicorn app:app --port 8000
```

---

## 📊 Comparison: Old vs New UI

| Feature | Old UI | New UI v2.0 |
|---------|--------|-------------|
| **Input method** | Manual text paste | ✅ Auto-monitoring |
| **Process detection** | ❌ None | ✅ Real-time display |
| **Statistics** | ❌ No stats | ✅ Live stats panel |
| **Auto-refresh** | ❌ Manual F5 | ✅ Every 5 seconds |
| **Detections list** | ❌ Single result | ✅ Full history |
| **Control** | ❌ N/A | ✅ Start/Stop buttons |
| **Use case** | Forensics | Live SOC monitoring |

---

## 🐛 Troubleshooting

### UI shows "Failed to fetch stats"

**Problem**: Backend API không chạy
```bash
# Solution: Start backend
cd /Users/ngaphan/Desktop/MemForen/fileless
uvicorn app:app --port 8000
```

### Statistics không update

**Problem**: Monitor chưa start
```bash
# Solution: Click "▶️ Start Monitoring" in UI
# Or check backend logs
```

### CORS errors in browser console

**Problem**: API không allow cross-origin
```python
# In app.py, add CORS middleware:
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Empty detections list

**Nguyên nhân**: Chưa có malware nào được phát hiện
```
✅ Normal! Nếu hệ thống clean, sẽ hiển thị:
"🛡️ No malware detected yet"
```

---

## 📸 Screenshots

### Live Monitoring View
- Tab navigation (Live Monitoring / Manual Analysis)
- Control panel (Start/Stop buttons)
- Statistics grid (4 metrics)
- Detections list (with process details)

### Manual Analysis View
- Text input area
- Threshold slider
- Analyze button
- Result card with MITRE mapping

---

## 🎯 Next Steps

1. ✅ Open browser: `http://localhost:5173`
2. ✅ Switch to "Live Monitoring" tab
3. ✅ Click "Start Monitoring"
4. ✅ Watch real-time process scanning
5. ✅ Click techniques for MITRE details

---

## 📞 Support

- **Backend logs**: `fileless/process_monitor.log`
- **Malware alerts**: `fileless/malware_alerts.log`
- **API docs**: `http://localhost:8000/docs`
- **UI dev server**: `http://localhost:5173`

---

**Version**: 2.0.0 (Real-time Monitoring UI)  
**Framework**: React + Vite  
**API**: FastAPI + Process Monitor  
**Author**: Based on Argus framework
