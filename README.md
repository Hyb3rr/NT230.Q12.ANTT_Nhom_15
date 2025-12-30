# Fileless Malware Detection System

**An AI-powered early-stage fileless malware detection tool using BERT-MLP deep learning architecture**


---

## Overview

This is a **defensive security tool** designed to detect fileless malware attacks in their early stages, before they reach operational capability. The system uses a BERT-MLP deep learning model trained on memory forensics artifacts and system behavior to classify attacks across four attack lifecycle stages.

### Research Foundation

Based on the paper:
> **"Unveiling the veiled: An early stage detection of fileless malware"**  

### Key Features

**4-Stage Attack Classification**
- Initial Stage
- Pre-operational Stage
- Operational Stage
- Final Stage

**BERT-MLP Architecture**
- BERT-base encoder
- MLP classifier with numeric feature fusion

**Automatic Process Monitoring** (Windows)
- Real-time process scanning using Sysmon
- Suspicious process detection
- Memory dump capture with ProcDump
- Memory dump analysis with WinDBG

**MITRE ATT&CK Integration**
- Automatic technique mapping
- Tactic correlation
- Stage-specific threat intelligence

**Web UI Dashboard**
- Real-time monitoring statistics
- Detection timeline visualization
- Interactive MITRE ATT&CK mapping
- Process details and recommendations

---
## Table of Contents

1. [Overview](#-overview)
    - [Research Foundation](#research-foundation)
    - [Key Features](#key-features)
2. [System Architecture](#️-system-architecture)
    - [High-Level Architecture](#high-level-architecture)
    - [ML Pipeline](#ml-pipeline)
3. [Quick Start](#-quick-start)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
4. [Usage Guide](#-usage-guide)
    - [Option 1: Terminal Monitoring](#option-1-terminal-monitoring-recommended)
    - [Option 2: Web Dashboard UI](#option-2-web-dashboard-ui)
5. [Training Your Own Model](#-training-your-own-model)
    - [Dataset Preparation](#dataset-preparation)
    - [Training](#training)
    - [Dataset Format](#dataset-format)
6. [Project Structure](#-project-structure)
7. [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
8. [Performance Metrics](#-performance-metrics)
9. [Troubleshooting](#-troubleshooting)
10. [References](#-references)

---

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

## Quick Start

### Prerequisites

- **Python 3.8+** (3.9 or 3.10 recommended)
- **Windows OS** (for process monitoring features)
- **4GB+ RAM** (for BERT model)
- **GPU** (optional, for faster inference)
- **Node.js 16+** (for Web UI)

### Installation

#### 1. Clone & Setup Python Environment
You can download our Pre-trained model at [here](https://drive.google.com/file/d/1-Vsoi7plhVuw7VyZ4Evm36Qu8OcF1lFm/view?usp=drive_link)

```bash
cd /path/to/NT230.Q12.ANTT_Nhom_15

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

**Sysmon** (for system monitor):
```bash
# Download from https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
# Run sysmon in the current directory, you can change the config if you want
./Sysmon64.exe -accepteula -i sysmon_config.xml
```

**WinDbg** (for advanced memory analysis):
```bash
# Download from Windows Store or Windows SDK
# Or use cdbX64.exe from Windows Debugging Tools, copy path of cdbX64.exe in memory_feature_extractor.py
```

#### 3. Verify Installation

```bash
python test_api.py
```

---

## Usage Guide

### Option 1: Terminal Monitoring (Recommended)

**Real-time monitoring with terminal output - Run as Administrator**

1. **Open PowerShell as Administrator**
   - Right-click PowerShell → "Run as Administrator"

2. **Activate virtual environment and run app.py**
   ```powershell
   # Navigate to project directory
   cd C:\path\to\NT230.Q12.ANTT_Nhom_15
   
   # Activate virtual environment
   .\venv\Scripts\Activate.ps1
   
   # Run the application
   python app.py
   ```

3. **Monitor the terminal output**
   ```
   ======================================================================
     Fileless Malware Detection System - Starting...
   ======================================================================
   
   [✓] Loading BERT-MLP model...
   [✓] Model loaded successfully (Device: cuda:0)
   [✓] Initializing Sysmon event monitor...
   [✓] Process monitor started
   
   Monitoring Windows processes for suspicious activity...
   - Scanning Sysmon events in real-time
   - Detecting suspicious process behaviors
   - Capturing memory dumps with ProcDump
   - Analyzing with BERT-MLP AI model
   
   Press Ctrl+C to stop monitoring
   ======================================================================
   
   INFO - Suspicious Sysmon event detected (EventID: 1, RecordID: 12345)
   INFO - Analyzing suspicious process PID 5678 (powershell.exe)
   
   ⚠️  MALWARE DETECTED ⚠️
   Process: powershell.exe (PID: 5678)
   Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   Command: powershell.exe -EncodedCommand JABhAD0AJw...
   
   Detection:
     Verdict: MALICIOUS
     Confidence: 87.34%
     Attack Stage: Pre-operational (Stage 1)
   
   MITRE ATT&CK:
     Tactics: Execution, Persistence
     Techniques: T1059.001 (PowerShell), T1055 (Process Injection)
   
   Recommendation: ALERT - Stage 1 attack detected
   ======================================================================
   ```

**Features:**
- Real-time Sysmon event monitoring
- Automatic suspicious process detection
- Memory dump capture (ProcDump)
- Memory dump analysis (WinDbg)
- AI-powered malware classification
- MITRE ATT&CK technique mapping
- Detailed terminal logging

**API Endpoints (when running app.py):**
- API: `http://localhost:8000`
- Swagger Docs: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

---

### Option 2: Web Dashboard UI

**Visual monitoring with interactive web interface**

**Step 1: Start the backend (if not already running)**
```powershell
# In PowerShell (as Administrator)
cd C:\path\to\NT230.Q12.ANTT_Nhom_15
.\venv\Scripts\Activate.ps1
python app.py
```

**Step 2: Start the Web UI**
```powershell
# Open a new PowerShell window (normal user is fine)
cd C:\path\to\NT230.Q12.ANTT_Nhom_15\fileless-ui

# Install dependencies (first time only)
npm install

# Start development server
npm run dev
```

**Step 3: Access the Dashboard**
- Open browser: `http://localhost:5173`

**Dashboard Features:**

1. **Monitor Tab** - Real-time Statistics
   - Total events scanned
   - Suspicious processes detected
   - Malware confirmed
   - Active monitoring status
   - Detection rate graph

2. **Detect Tab** - Manual Analysis
   - Enter process behavior description
   - Paste command line arguments
   - Input memory artifacts
   - Get instant AI-powered verdict
   - View MITRE ATT&CK mapping

3. **Detections Tab** - History Timeline
   - Recent malware detections
   - Process details and PIDs
   - Confidence scores
   - Attack stages
   - Memory dump locations
   - Downloadable analysis reports

**Screenshots:**
- Real-time monitoring dashboard
- Interactive detection results
- MITRE ATT&CK technique visualization
- Process behavior timeline

---

## Training Your Own Model

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

## Project Structure

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

## MITRE ATT&CK Coverage

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

## Performance Metrics

### Model Performance

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

## Troubleshooting

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


#### 4. Port Already in Use
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

## References

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

