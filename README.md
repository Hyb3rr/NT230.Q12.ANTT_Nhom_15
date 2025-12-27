# Fileless Malware Detection System

**An AI-powered early-stage fileless malware detection tool using BERT-MLP deep learning architecture**

[![Security](https://img.shields.io/badge/Purpose-DEFENSIVE%20ONLY-blue)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)]()
[![Python](https://img.shields.io/badge/Python-3.8+-green)]()
[![License](https://img.shields.io/badge/License-Research-orange)]()

---

## 📋 Overview

This is a **defensive security tool** designed for SOC/Blue Team operations to detect fileless malware attacks in their early stages, before they reach operational capability. The system uses a BERT-MLP deep learning model trained on memory forensics artifacts and system behavior to classify attacks across four attack lifecycle stages.

### Research Foundation

Based on the paper:
> **"Unveiling the veiled: An early stage detection of fileless malware"**  
> Narendra Singh, Somanath Tripathy  
> Computers & Security, Volume 150, 2025  
> DOI: 10.1016/j.cose.2024.104231

### Key Features

✅ **4-Stage Attack Classification**
- Initial Stage (Reconnaissance, Initial Access)
- Pre-operational Stage (Execution, Persistence, Privilege Escalation)
- Operational Stage (Defense Evasion, Credential Access, Discovery, Lateral Movement)
- Final Stage (Collection, C&C, Exfiltration, Impact)

✅ **BERT-MLP Architecture**
- BERT-base encoder (768-dim contextual embeddings)
- MLP classifier with numeric feature fusion
- 108M parameters, 97.05% accuracy
- <50ms inference latency

✅ **Automatic Process Monitoring** (Windows)
- Real-time process scanning using WMI/psutil
- Suspicious process detection
- Memory dump capture with ProcDump
- Automatic malware analysis

✅ **MITRE ATT&CK Integration**
- Automatic technique mapping
- Tactic correlation
- Stage-specific threat intelligence

✅ **Web UI Dashboard**
- Real-time monitoring statistics
- Detection timeline visualization
- Interactive MITRE ATT&CK mapping
- Process details and recommendations

---

## 🏗️ System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  Fileless Detection System                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌────────────────────┐         ┌──────────────────────┐       │
│  │  Process Monitor   │────────▶│  Memory Extraction   │       │
│  │  (WMI/psutil)      │         │  (ProcDump/WinDbg)   │       │
│  └────────────────────┘         └──────────┬───────────┘       │
│           │                                 │                   │
│           │                                 │                   │
│           ▼                                 ▼                   │
│  ┌────────────────────┐         ┌──────────────────────┐       │
│  │  Suspicious Queue  │────────▶│  Feature Extraction  │       │
│  │  (PIDs)            │         │  (APIs, strings,     │       │
│  └────────────────────┘         │   patterns)          │       │
│                                 └──────────┬───────────┘       │
│                                            │                   │
│                                            ▼                   │
│                                 ┌──────────────────────┐       │
│                                 │   BERT-MLP Model     │       │
│                                 │   (fileless_         │       │
│                                 │    detector.pt)      │       │
│                                 └──────────┬───────────┘       │
│                                            │                   │
│                                            ▼                   │
│                                 ┌──────────────────────┐       │
│                                 │  MITRE ATT&CK        │       │
│                                 │  Mapping & Verdict   │       │
│                                 └──────────────────────┘       │
│                                                                 │
│  ┌──────────────────────────────────────────────────┐          │
│  │          FastAPI REST API (Port 8000)            │          │
│  │  /detect  /health  /monitor/*  /techniques       │          │
│  └──────────────────────────────────────────────────┘          │
│                          │                                      │
│                          ▼                                      │
│  ┌──────────────────────────────────────────────────┐          │
│  │       React + Vite Web UI (Port 5173)            │          │
│  │  Dashboard | Real-time Monitoring | Detections   │          │
│  └──────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### ML Pipeline

```
Input: Memory artifacts / Process behavior
    │
    ▼
┌──────────────────────────┐
│  Feature Extraction      │
│  • API calls             │
│  • Suspicious strings    │
│  • URLs, IPs, Base64     │
│  • Obfuscation patterns  │
│  • Injection indicators  │
└───────────┬──────────────┘
            │
            ▼
┌──────────────────────────┐
│  BERT Tokenizer          │
│  (bert-base-uncased)     │
└───────────┬──────────────┘
            │
            ▼
┌──────────────────────────┐
│  BERT Encoder            │
│  (768-dim embeddings)    │
└───────────┬──────────────┘
            │
            ▼
┌──────────────────────────┐
│  Global Max Pooling      │
└───────────┬──────────────┘
            │
            ▼
┌──────────────────────────┐      ┌─────────────────┐
│  MLP Classifier          │◄─────┤ Numeric Features│
│  (768+256 → 128 → 64 → 4)│      │ (5-100 features)│
└───────────┬──────────────┘      └─────────────────┘
            │
            ▼
┌──────────────────────────┐
│  Softmax Output          │
│  • Initial (Stage 0)     │
│  • Pre-op (Stage 1)      │
│  • Operational (Stage 2) │
│  • Final (Stage 3)       │
└──────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** (3.9 or 3.10 recommended)
- **Windows OS** (for process monitoring features)
- **4GB+ RAM** (for BERT model)
- **GPU** (optional, for faster inference)
- **Node.js 16+** (for Web UI)

### Installation

#### 1. Clone & Setup Python Environment

```bash
cd /path/to/fileless2

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

#### 2. Download Required Tools (Windows)

**ProcDump** (for memory dumps):
```bash
# Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
# Extract to: C:\SysinternalsSuite\procdump.exe
# Or place in current directory as: procdump.exe
```

**WinDbg** (optional, for advanced memory analysis):
```bash
# Download from Windows Store or Windows SDK
# Or use cdb.exe from Windows Debugging Tools
```

#### 3. Verify Installation

```bash
python test_api.py
```

---

## 📖 Usage Guide

### Option 1: Standalone Process Monitoring (Recommended)

**Automatic real-time monitoring of Windows processes:**

```bash
python auto_monitor_demo.py
```

**Output:**
```
======================================================================
  Fileless Malware Detection - Automatic Process Monitor
======================================================================

[1/3] Loading BERT-MLP model...
✓ Model loaded successfully
  Device: cuda:0
  Architecture: BERT-MLP (4-stage classifier)

[2/3] Initializing process monitor...
✓ Process monitor initialized
  ProcDump: C:\SysinternalsSuite\procdump.exe
  Scan interval: 2s

[3/3] Starting automatic monitoring...

Monitoring Windows processes for suspicious activity...
Looking for:
  • Suspicious process names (PowerShell, cmd.exe, wmic.exe, etc.)
  • Abnormal parent-child relationships
  • High CPU/memory usage
  • Unusual network activity

Press Ctrl+C to stop monitoring
======================================================================

INFO - Suspicious process detected: powershell.exe (PID: 12345)
INFO - Adding suspicious PID 12345 to queue
INFO - Analyzing suspicious process PID 12345

⚠️  MALWARE DETECTED ⚠️
Process: powershell.exe (PID: 12345)
Verdict: MALICIOUS
Confidence: 87.34%
Stage: Pre-operational (Stage 1)
Tactics: Execution, Persistence
Techniques: T1059.001 (PowerShell), T1055 (Process Injection)

Recommendation: ALERT - Stage 1 attack detected
```

**Features:**
- ✅ Automatic scanning every 2 seconds
- ✅ Suspicious process detection
- ✅ Memory dump capture (if ProcDump available)
- ✅ Real-time analysis with BERT-MLP
- ✅ MITRE ATT&CK mapping
- ✅ Statistics every 30 seconds

---

### Option 2: FastAPI Server + Web UI

**For dashboard monitoring and REST API access:**

#### Step 1: Start the API Server

```bash
# Start FastAPI backend
uvicorn app:app --host 0.0.0.0 --port 8000

# Or with auto-reload (development)
uvicorn app:app --reload
```

**API will be available at:**
- API: `http://localhost:8000`
- Swagger Docs: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

#### Step 2: Start the Web UI

```bash
cd fileless-ui

# Install dependencies (first time only)
npm install

# Start development server
npm run dev
```

**Web UI will be available at:**
- Dashboard: `http://localhost:5173`

#### Step 3: Use the Dashboard

1. **Monitor Tab**: View real-time monitoring statistics
   - Processes scanned
   - Suspicious processes found
   - Malware detections
   - Current queue size

2. **Detect Tab**: Manual malware detection
   - Enter memory artifacts or process behavior
   - Optional numeric features
   - Confidence threshold adjustment
   - View detailed results with MITRE mapping

3. **Detections Tab**: Detection history timeline
   - Recent malware detections
   - Process details
   - Confidence scores
   - Attack stages

---

### Option 3: REST API (Integration)

**For SIEM/SOC integration:**

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Manual Detection
```bash
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{
    "text": "powershell.exe -EncodedCommand JABhAD0AJwBoAHQAdABwADoALw executing with suspicious parent winword.exe accessing registry HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "threshold": 0.5
  }'
```

**Response:**
```json
{
  "verdict": "malicious",
  "confidence": 0.8734,
  "stage": 1,
  "stage_name": "Pre-operational",
  "probabilities": {
    "Initial": 0.0234,
    "Pre-operational": 0.8734,
    "Operational": 0.0823,
    "Final": 0.0209
  },
  "tactics": ["Execution", "Persistence"],
  "common_techniques": ["T1059.001", "T1112", "T1055"],
  "recommendation": "ALERT: Stage 1 attack detected. Pre-operational phase indicates execution and persistence mechanisms. Immediate investigation required.",
  "inference_time_ms": 42.3
}
```

#### Process Monitor Control
```bash
# Start monitoring
curl -X POST http://localhost:8000/monitor/start

# Get statistics
curl http://localhost:8000/monitor/stats

# Get recent detections
curl http://localhost:8000/monitor/detections

# Stop monitoring
curl -X POST http://localhost:8000/monitor/stop
```

---

## 🧪 Training Your Own Model

The system includes training code in `my_training_code/` directory.

### Dataset Preparation

```bash
cd my_training_code

# Build dataset from various sources
python build_large_dataset.py

# Merge multiple datasets
python merge_datasets.py

# Convert Sysmon logs
python convert_sysmon_thezoo.py
```

### Training

```bash
# Train the BERT-MLP model
python train_fileless_detector.py

# Configuration in train_fileless_detector.py:
# - data_path: Path to events.csv
# - epochs: 25 (as per paper)
# - batch_size: 16
# - learning_rate: 2e-5
# - max_len: 128 tokens
```

**Training Output:**
```
Epoch 1/25
Train Loss: 1.234 | Val Loss: 0.987 | Val Acc: 0.8234

Epoch 25/25
Train Loss: 0.123 | Val Loss: 0.234 | Val Acc: 0.9705

✓ Model saved to: fileless_detector.pt
✓ Config saved to: fileless_detector_cfg.json
```

### Dataset Format

Expected CSV format (`events.csv`):
```csv
text,num_feats,label
"powershell.exe -enc base64payload accessing registry...",[145,4.2,1,15,0.12],1
"mshta.exe executing JavaScript WScript.Shell...",[234,3.8,1,22,0.18],1
"notepad.exe user-initiated normal operation",[67,2.1,0,8,0.05],0
```

**Fields:**
- `text`: Description of process behavior, memory artifacts, or system events
- `num_feats`: JSON array of numeric features [length, entropy, has_base64, token_count, uppercase_ratio]
- `label`: Attack stage (0=Initial, 1=Pre-op, 2=Operational, 3=Final)

---

## 📁 Project Structure

```
fileless2/
├── README_COMPLETE.md              # This file - Complete documentation
├── requirements.txt                # Python dependencies
├── setup.bat                       # Windows setup script
├── sysmon_config.xml              # Sysmon configuration for logging
│
├── Core Components
├── app.py                         # FastAPI server (main entry point)
├── inference.py                   # BERT-MLP inference engine
├── model_loader.py                # Secure model loading
├── schemas.py                     # Pydantic API schemas
├── process_monitor.py             # Windows process monitoring
├── memory_feature_extractor.py    # Memory forensics feature extraction
├── auto_monitor_demo.py           # Standalone monitoring demo
│
├── Model Files
├── fileless_detector.pt           # Trained BERT-MLP weights (not in repo)
├── fileless_detector_cfg.json     # Model configuration
│
├── Training Code
├── my_training_code/
│   ├── train_fileless_detector.py # BERT-MLP training script
│   ├── build_large_dataset.py     # Dataset builder
│   ├── merge_datasets.py          # Dataset merger
│   ├── enhanced_features.py       # Feature engineering
│   ├── fileless_techniques.py     # MITRE technique mapping
│   └── ...                        # Other training utilities
│
└── Web UI
    └── fileless-ui/
        ├── src/
        │   ├── App.jsx            # Main React component
        │   └── main.jsx           # Entry point
        ├── package.json           # Node.js dependencies
        └── vite.config.js         # Vite configuration
```

---

## 🔒 Security Considerations

### Defensive Use Only

⚠️ **This tool is designed EXCLUSIVELY for defensive security operations:**
- ✅ SOC/Blue Team malware detection
- ✅ Incident response and forensics
- ✅ Threat hunting
- ✅ Security research (academic)
- ❌ **NOT** for creating or testing malware
- ❌ **NOT** for offensive security operations

### Security Features

- **Input Validation**: Size limits, type checking, sanitization
- **Rate Limiting**: API request throttling
- **Audit Logging**: All detections logged
- **Eval Mode**: No gradient computation (inference only)
- **Confidence Thresholding**: Configurable detection sensitivity
- **Process Isolation**: Monitored processes in separate queue

### Privacy & Ethics

- Memory dumps may contain sensitive information
- Use on authorized systems only
- Follow your organization's security policies
- Comply with data protection regulations (GDPR, etc.)

---

## 🎯 MITRE ATT&CK Coverage

### Stage 0: Initial
- **Tactics**: Reconnaissance, Initial Access
- **Techniques**: T1566 (Phishing), T1190 (Exploit Public-Facing Application)

### Stage 1: Pre-operational
- **Tactics**: Execution, Persistence, Privilege Escalation
- **Techniques**: T1059.001 (PowerShell), T1112 (Modify Registry), T1053.005 (Scheduled Task), T1055 (Process Injection)

### Stage 2: Operational
- **Tactics**: Defense Evasion, Credential Access, Discovery, Lateral Movement
- **Techniques**: T1027 (Obfuscated Files), T1140 (Deobfuscate/Decode), T1003 (Credential Dumping), T1057 (Process Discovery)

### Stage 3: Final
- **Tactics**: Collection, Command & Control, Exfiltration, Impact
- **Techniques**: T1005 (Data from Local System), T1071.001 (Web Protocols), T1041 (Exfiltration Over C2), T1486 (Data Encrypted for Impact)

---

## 📊 Performance Metrics

### Model Performance (from paper)

| Metric | Value |
|--------|-------|
| Overall Accuracy | 97.05% |
| Precision | 96.8% |
| Recall | 97.2% |
| F1-Score | 97.0% |
| Early Detection (Pre-op) | 59.3% |
| Inference Time | <50ms |

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 4 GB | 8+ GB |
| GPU | None (CPU) | CUDA-capable (RTX 3060+) |
| Storage | 2 GB | 5+ GB |
| OS | Windows 10 | Windows 10/11 |

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Model File Not Found
```
Error: Model file not found: fileless_detector.pt
```
**Solution**: Train the model first using `train_fileless_detector.py` or obtain pre-trained weights.

#### 2. CUDA Out of Memory
```
RuntimeError: CUDA out of memory
```
**Solution**: 
- Reduce batch size in config
- Use CPU mode: Set `device: "cpu"` in `fileless_detector_cfg.json`
- Close other GPU applications

#### 3. ProcDump Not Found
```
WARNING: ProcDump not found; memory dumps disabled
```
**Solution**: Download ProcDump from Microsoft Sysinternals and place in `C:\SysinternalsSuite\` or current directory.

#### 4. WMI Access Denied (Windows)
```
Error: Access denied when querying WMI
```
**Solution**: Run as Administrator or grant WMI permissions.

#### 5. Port Already in Use
```
Error: Address already in use: 8000
```
**Solution**: 
```bash
# Find and kill process using port
netstat -ano | findstr :8000
taskkill /PID <PID> /F

# Or use different port
uvicorn app:app --port 8001
```

---

## 📚 References

### Research Paper
- Singh, N., & Tripathy, S. (2025). Unveiling the veiled: An early stage detection of fileless malware. *Computers & Security*, 150, 104231.
- DOI: https://doi.org/10.1016/j.cose.2024.104231

### Frameworks & Libraries
- **BERT**: Devlin, J., et al. (2018). BERT: Pre-training of Deep Bidirectional Transformers for Language Understanding.
- **PyTorch**: https://pytorch.org/
- **Transformers**: https://huggingface.co/transformers/
- **FastAPI**: https://fastapi.tiangolo.com/
- **React**: https://react.dev/

### MITRE ATT&CK
- https://attack.mitre.org/
- Enterprise ATT&CK Matrix

---

## 🤝 Contributing

This is a research/educational tool. If you want to contribute:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Create Pull Request

**Contribution areas:**
- Improved feature extraction
- Additional MITRE technique coverage
- Performance optimizations
- Documentation improvements
- Bug fixes

---

## 📝 License

This tool is provided for **defensive security research and education only**. Use responsibly and ethically.

**Disclaimer**: The authors and contributors are not responsible for misuse of this tool. Use only on systems you own or have explicit permission to monitor.

---

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review troubleshooting section

---

## 🙏 Acknowledgments

- Research by Narendra Singh & Somanath Tripathy (IIT Patna)
- MITRE ATT&CK Framework
- Hugging Face Transformers team
- FastAPI and React communities
- Microsoft Sysinternals (ProcDump)

---

**Built with ❤️ for defensive security**
