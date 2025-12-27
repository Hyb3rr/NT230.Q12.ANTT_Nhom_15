"""
Automatic Process Monitoring Demo

Standalone script for real-time Windows process monitoring and fileless malware detection.
No API server required - runs directly as a command-line tool.

Usage:
    python auto_monitor_demo.py
"""
import time
import logging
from pathlib import Path

from model_loader import ModelLoader
from inference import FilelessDetector
from process_monitor import ProcessMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auto_monitor_demo.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def main():
    """Run automatic process monitoring demo"""
    
    print("="*70)
    print("  Fileless Malware Detection - Automatic Process Monitor")
    print("  Based on: Singh & Tripathy (2024)")
    print("="*70)
    print()
    
    # Load model
    print("[1/3] Loading BERT-MLP model...")
    try:
        model_loader = ModelLoader(
            model_path="fileless_detector.pt",
            config_path="fileless_detector_cfg.json"
        )
        detector = FilelessDetector(model_loader)
        print(f"✓ Model loaded successfully")
        print(f"  Device: {model_loader.device}")
        print(f"  Architecture: BERT-MLP (4-stage classifier)")
        print()
    except Exception as e:
        print(f"✗ Failed to load model: {e}")
        print(f"\nMake sure you have:")
        print(f"  1. fileless_detector.pt (trained model weights)")
        print(f"  2. fileless_detector_cfg.json (model config)")
        print(f"\nTrain the model first using: python train_fileless_detector.py")
        return
    
    # Initialize process monitor
    print("[2/3] Initializing process monitor...")
    try:
        monitor = ProcessMonitor(detector=detector)
        print("✓ Process monitor initialized")
        if monitor.procdump_path:
            print(f"  ProcDump: {monitor.procdump_path}")
        else:
            print("  ProcDump: Not available (memory dumps disabled)")
            print("  Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump")
        print(f"  Scan interval: {monitor.SCAN_INTERVAL}s")
        print()
    except Exception as e:
        print(f"✗ Failed to initialize monitor: {e}")
        return
    
    # Start monitoring
    print("[3/3] Starting automatic monitoring...")
    print()
    print("Monitoring Windows processes for suspicious activity...")
    print("Looking for:")
    print("  • Suspicious process names (PowerShell, cmd.exe, wmic.exe, etc.)")
    print("  • Abnormal parent-child relationships")
    print("  • High CPU/memory usage")
    print("  • Unusual network activity")
    print()
    print("Press Ctrl+C to stop monitoring")
    print("="*70)
    print()
    
    try:
        monitor.start()
        
        # Monitor loop with periodic stats
        last_stats_time = time.time()
        
        while True:
            time.sleep(5)
            
            # Print stats every 30 seconds
            if time.time() - last_stats_time >= 30:
                stats = monitor.get_stats()
                print()
                print("─" * 70)
                print(f"📊 Monitoring Statistics ({time.strftime('%H:%M:%S')})")
                print("─" * 70)
                print(f"  Processes scanned:     {stats['total_scanned']}")
                print(f"  Suspicious found:      {stats['suspicious_found']}")
                print(f"  Malware detected:      {stats['malware_detected']}")
                print(f"  Benign processes:      {stats['benign_processes']}")
                print(f"  Analysis queue size:   {stats['queue_size']}")
                print("─" * 70)
                print()
                
                # Show recent detections
                detections = monitor.get_recent_detections(limit=3)
                if detections:
                    print("Recent Detections:")
                    for d in detections:
                        print(f"  • {d['process_name']} (PID: {d['pid']}) - {d['verdict'].upper()}")
                        print(f"    Confidence: {d['confidence']*100:.2f}% | Stage: {d['stage_name']}")
                    print()
                
                last_stats_time = time.time()
    
    except KeyboardInterrupt:
        print()
        print("="*70)
        print("Stopping monitor...")
        monitor.stop()
        
        # Final statistics
        stats = monitor.get_stats()
        print()
        print("Final Statistics:")
        print("─" * 70)
        print(f"  Total processes scanned:    {stats['total_scanned']}")
        print(f"  Suspicious processes found: {stats['suspicious_found']}")
        print(f"  Malware detected:           {stats['malware_detected']}")
        print(f"  Benign processes:           {stats['benign_processes']}")
        print("─" * 70)
        print()
        print("✓ Monitoring stopped successfully")
        print()
    
    except Exception as e:
        logger.error(f"Error during monitoring: {e}")
        print(f"✗ Error: {e}")
        monitor.stop()


if __name__ == "__main__":
    main()
