"""
Windows Process Monitor for Fileless Malware Detection
"""
import os
import sys
import time
import logging
import subprocess
import psutil
import json
import platform
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
from queue import Queue
from threading import Thread, Event

from inference import FilelessDetector
from memory_feature_extractor import MemoryFeatureExtractor

# Ensure logs always go to a known location (alongside this file)
LOG_DIR = Path(__file__).resolve().parent
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / 'process_monitor.log'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
# Ensure handlers are present even if logging was configured before import (e.g., uvicorn)
if not logger.handlers:
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
logger.setLevel(logging.INFO)
logger.propagate = False


class ProcessMonitor:
    """
    Real-time Windows process monitor for fileless malware detection
    
    Monitors system for suspicious processes and queues them for analysis (psutil-based)
    """
    
    # Suspicious indicators (based on paper Section 4.1.1)
    SUSPICIOUS_PROCESSES = {
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'wmic.exe',
        'certutil.exe', 'bitsadmin.exe', 'msiexec.exe'
    }
    
    SUSPICIOUS_PARENTS = {
        'winword.exe', 'excel.exe', 'outlook.exe', 'acrobat.exe',
        'acrord32.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe'
    }
    
    # System processes to exclude (protected/known-good)
    SYSTEM_PROCESSES_EXCLUDE = {
        'msmpeng.exe',        # Windows Defender
        'nissrv.exe',         # Windows Defender Network Inspection
        'mssense.exe',        # Windows Defender ATP
        'senseir.exe',        # Windows Defender ATP
        'securityhealthservice.exe',  # Windows Security
        'system',             # System process
        'csrss.exe',          # Client/Server Runtime
        'lsass.exe',          # Local Security Authority
        'winlogon.exe',       # Windows Logon
        'svchost.exe',        # Generic Host (too noisy)
        'windbg.exe',         # WinDbg debugger
        'cdb.exe',            # Console debugger
        'dbgsrv.exe',         # Debug server
        'procdump.exe',       # ProcDump (our own tool)
        'procdump64.exe'      # ProcDump 64-bit
    }
    
    # Thresholds
    HIGH_CPU_THRESHOLD = 80.0  # CPU usage %
    HIGH_MEMORY_THRESHOLD = 500 * 1024 * 1024  # 500 MB
    SCAN_INTERVAL = 2  # seconds (paper uses 2s feature extraction)
    
    def __init__(self, detector=None, procdump_path: Optional[str] = './procdump.exe'):
        """
        Initialize process monitor
        
        Args:
            detector: FilelessDetector instance for malware analysis
            procdump_path: Path to ProcDump.exe (optional)
        """
        self.detector = detector
        # Resolve ProcDump path (allow env override)
        env_procdump = os.getenv('PROCDUMP_PATH')
        candidate = env_procdump or procdump_path
        if candidate:
            candidate = str(Path(candidate).expanduser().resolve())
        self.procdump_path = candidate or self._find_procdump()
        if self.procdump_path and not os.path.exists(self.procdump_path):
            logger.warning(f"ProcDump path not found: {self.procdump_path} - memory dumps disabled")
            self.procdump_path = None
        
        # Sysmon log polling configuration
        self.sysmon_log = os.getenv('SYSMON_LOG', 'Microsoft-Windows-Sysmon/Operational')
        self.sysmon_batch = int(os.getenv('SYSMON_BATCH', '200'))
        self.last_record_id: Optional[int] = None
        logger.info(f"Using Sysmon monitoring from log: {self.sysmon_log}")
        
        # Initialize memory feature extractor
        self.memory_extractor = MemoryFeatureExtractor()
        logger.info("Memory feature extractor initialized")
        
        # Queue for suspicious Sysmon events
        self.suspicious_queue = Queue()
        
        # Tracking
        self.monitored_pids: Set[int] = set()
        self.detected_malware: List[Dict] = []
        
        # Control
        self.stop_event = Event()
        self.monitor_thread: Optional[Thread] = None
        
        # Stats
        self.stats = {
            'total_events': 0,
            'suspicious_found': 0,
            'malware_detected': 0,
            'benign_processes': 0
        }
        
        logger.info("Process Monitor initialized")
        if self.procdump_path:
            logger.info(f"ProcDump found at: {self.procdump_path}")
        else:
            logger.warning("ProcDump not found - memory dumps disabled")
    
    def _find_procdump(self) -> Optional[str]:
        """Try to locate ProcDump.exe"""
        common_paths = [
            r"C:\\SysinternalsSuite\\procdump.exe",
            r"C:\\SysinternalsSuite\\procdump64.exe",
            r"C:\\Program Files\\SysinternalsSuite\\procdump.exe",
            r"C:\\Program Files\\SysinternalsSuite\\procdump64.exe",
            r".\\procdump.exe",
            r".\\procdump64.exe"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return str(Path(path).resolve())
        
        # Try to find in PATH
        try:
            for name in ('procdump.exe', 'procdump64.exe'):
                result = subprocess.run(
                    ['where', name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    found = result.stdout.strip().split('\n')[0]
                    if found:
                        return str(Path(found).resolve())
        except:
            pass
        
        return None
    
    def is_suspicious_process(self, proc: psutil.Process) -> bool:
        """
        Detect suspicious process
        - Unusual process names (LOLBins)
        - Abnormal parent-child relationships
        - High resource usage
        - Unusual network activity
        """
        try:
            name = proc.name().lower()
            
            # Check 1: Known suspicious processes (Living-off-the-Land)
            if name in self.SUSPICIOUS_PROCESSES:
                logger.info(f"Suspicious process detected: {name} (PID: {proc.pid})")
                return True
            
            # Check 2: Abnormal parent-child relationship
            try:
                parent = proc.parent()
                if parent and parent.name().lower() in self.SUSPICIOUS_PARENTS:
                    if name in self.SUSPICIOUS_PROCESSES:
                        logger.info(f"Suspicious parent-child: {parent.name()} -> {name} (PID: {proc.pid})")
                        return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Check 3: High CPU usage
            try:
                cpu_percent = proc.cpu_percent(interval=0.1)
                if cpu_percent > self.HIGH_CPU_THRESHOLD:
                    logger.debug(f"High CPU: {name} (PID: {proc.pid}) - {cpu_percent}%")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Check 4: High memory usage
            try:
                mem_info = proc.memory_info()
                if mem_info.rss > self.HIGH_MEMORY_THRESHOLD:
                    logger.debug(f"High memory: {name} (PID: {proc.pid}) - {mem_info.rss / 1024 / 1024:.1f} MB")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Check 5: Unusual network connections
            try:
                connections = proc.connections(kind='inet')
                if connections and name in self.SUSPICIOUS_PROCESSES:
                    logger.info(f"Suspicious network activity: {name} (PID: {proc.pid})")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            return False
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def capture_memory_dump(self, pid: int) -> Optional[str]:
        """
        Capture memory dump using ProcDump (legacy method)
        
        DEPRECATED: Use capture_memory_dump_named() for better filenames
        Kept for backward compatibility only.
        """
        return self.capture_memory_dump_named(pid, "process", 0, "unknown", 0)
    
    def capture_memory_dump_named(
        self, 
        pid: int, 
        process_name: str,
        stage: int,
        stage_name: str,
        confidence: int
    ) -> Optional[str]:
        """
        Capture memory dump with intelligent filename
        
        Args:
            pid: Process ID
            process_name: Process name (without .exe)
            stage: Stage number (0-3)
            stage_name: Stage description (e.g., 'execution', 'persistence')
            confidence: Confidence percentage (0-100)
            
        Returns:
            Path to dump file with format:
            {process_name}_Stage{stage}_{stage_name}_Conf{confidence}_PID{pid}_{timestamp}.dmp
            
        Example:
            powershell_Stage2_Execution_Conf87_PID12345_20241217_143022.dmp
        """
        if not self.procdump_path:
            logger.warning("ProcDump not available - skipping memory dump")
            return None
        if not os.path.exists(self.procdump_path):
            logger.error(f"ProcDump path missing at runtime: {self.procdump_path}")
            return None
        
        try:
            # Create dumps directory (absolute, next to this file)
            dump_dir = (Path(__file__).resolve().parent / "memory_dumps")
            dump_dir.mkdir(exist_ok=True)
            
            # Generate intelligent dump filename (absolute path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dump_file = (dump_dir / f"{process_name}_Stage{stage}_{stage_name}_Conf{confidence}_PID{pid}_{timestamp}.dmp").resolve()
            
            # Execute ProcDump with -ma flag (full memory dump)
            cmd = [
                self.procdump_path,
                "-accepteula",  # Accept EULA
                "-ma",          # Full memory dump
                str(pid),
                str(dump_file)
            ]
            
            logger.info(
                f"Capturing memory dump for PID {pid} ({process_name}) using {self.procdump_path} -> {dump_file} (cwd={Path.cwd()})"
            )
            creation_flags = 0
            startupinfo = None
            if sys.platform == 'win32':
                if hasattr(subprocess, 'CREATE_NO_WINDOW'):
                    creation_flags = subprocess.CREATE_NO_WINDOW  # avoid flashing a console window
                # Additional hint to hide window for older behaviors
                startupinfo = subprocess.STARTUPINFO()
                if hasattr(subprocess, 'STARTF_USESHOWWINDOW'):
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                creationflags=creation_flags,
                startupinfo=startupinfo
            )

            # Prefer the requested dump_file path, but ProcDump may alter the name; fall back to parsed stdout path
            stdout = (result.stdout or '').strip()
            stderr = (result.stderr or '').strip()

            # If ProcDump renamed the file, try to read it from stdout ("Dump 1 initiated: <path>")
            created_path = None
            if stdout:
                import re
                match = re.search(r"Dump\s+\d+\s+initiated:\s+(.+\.dmp)", stdout)
                if match:
                    alt_path = Path(match.group(1)).resolve()
                    if alt_path.exists():
                        created_path = alt_path
            
            if result.returncode == 0 and dump_file.exists():
                logger.info(f"Memory dump saved: {dump_file}")
                return str(dump_file)
            if created_path:
                logger.warning(
                    f"ProcDump returned rc={result.returncode} but dump exists at {created_path}; proceeding"
                )
                return str(created_path)

            # Fallback: if ProcDump wrote a dump with a different name in the dump_dir, pick the newest
            candidates = sorted(dump_dir.glob('*.dmp'), key=lambda p: p.stat().st_mtime, reverse=True)
            if candidates:
                newest = candidates[0]
                # Only accept if it was just created (within 2 minutes)
                if time.time() - newest.stat().st_mtime < 120:
                    logger.warning(
                        f"ProcDump rc={result.returncode} but found recent dump {newest}; proceeding"
                    )
                    return str(newest.resolve())

            logger.error(
                f"ProcDump failed (rc={result.returncode})\n"
                f"cmd: {' '.join(cmd)}\n"
                f"stdout: {stdout or '[empty]'}\n"
                f"stderr: {stderr or '[empty]'}"
            )
            return None
                
        except subprocess.TimeoutExpired:
            logger.error(f"ProcDump timeout for PID {pid}")
            return None
        except Exception as e:
            logger.error(f"Error capturing memory dump: {e}")
            return None
    
    def extract_process_info(self, proc: psutil.Process) -> Dict:
        """
        Extract process information for analysis
        
        Based on paper's feature extraction (Section 4.1.1)
        """
        try:
            info = {
                'pid': proc.pid,
                'name': proc.name(),
                'timestamp': datetime.now().isoformat(),
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'exe_path': proc.exe() if proc.exe() else '',
                'cwd': proc.cwd() if proc.cwd() else '',
                'username': proc.username() if proc.username() else '',
                'cpu_percent': proc.cpu_percent(interval=0.1),
                'memory_mb': proc.memory_info().rss / 1024 / 1024,
                'num_threads': proc.num_threads(),
                'connections': []
            }
            
            # Parent process info
            try:
                parent = proc.parent()
                if parent:
                    info['parent_pid'] = parent.pid
                    info['parent_name'] = parent.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['parent_pid'] = None
                info['parent_name'] = None
            
            # Network connections
            try:
                connections = proc.connections(kind='inet')
                info['connections'] = [
                    {
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    }
                    for conn in connections[:5]  # Limit to first 5
                ]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.warning(f"Error extracting process info for PID {proc.pid}: {e}")
            return {}
    
    def analyze_process(self, pid: int, event: Optional[Dict] = None) -> Optional[Dict]:
        """
        Analyze suspicious process for malware
        
        Complete analysis pipeline:
        1. Extract process info (live)
        2. Run AI detection
        3. If malicious → capture memory dump with detailed filename
        """
        try:
            proc = psutil.Process(pid)
            
            # Skip system/protected processes
            proc_name = proc.name().lower()
            if proc_name in self.SYSTEM_PROCESSES_EXCLUDE:
                logger.debug(f"Skipping system process: {proc_name} (PID {pid})")
                return None
            
            # Step 1: Extract process info (lightweight, no dump yet)
            proc_info = self.extract_process_info(proc)
            # Overlay Sysmon event context if provided
            if event:
                proc_info['sysmon_event_id'] = event.get('event_id')
                proc_info['sysmon_record_id'] = event.get('record_id')
                proc_info['sysmon_reasons'] = event.get('reasons', [])
                proc_info['sysmon_image'] = event.get('image')
                proc_info['sysmon_cmdline'] = event.get('command_line')
                proc_info['sysmon_parent_image'] = event.get('parent_image')
                proc_info['sysmon_parent_cmdline'] = event.get('parent_command_line')
            
            # Step 2: Build analysis text and run AI detection
            analysis_text = self._build_analysis_text(proc_info, event)
            
            # Step 3: Detect using model
            if self.detector:
                result = self.detector.detect(
                    text=analysis_text,
                    threshold=0.5
                )
                
                # Add process info to result
                result['process_info'] = proc_info
                result['timestamp'] = datetime.now().isoformat()
                
                # Log detection
                logger.info(
                    f"Analysis complete for PID {pid}: "
                    f"{result['verdict']} "
                    f"(stage: {result['stage_name']}, "
                    f"confidence: {result['confidence']:.2%})"
                )
                
                # Step 4: ONLY dump memory if MALICIOUS (not just suspicious)
                if result['verdict'] == 'malicious' and self.procdump_path:
                    proc_name = proc_info.get('name', 'unknown').replace('.exe', '')
                    stage_name = result['stage_name'].lower().replace(' ', '_')
                    confidence = int(result['confidence'] * 100)
                    
                    dump_path = self.capture_memory_dump_named(
                        pid=pid,
                        process_name=proc_name,
                        stage=result['stage'],
                        stage_name=stage_name,
                        confidence=confidence
                    )
                    
                    if dump_path:
                        result['memory_dump'] = dump_path
                        logger.warning(f"MALWARE DUMP: {dump_path}")
                        
                        # Step 5: Extract deep features from memory dump using process-centric tools (capa/FLOSS/YARA)
                        result['dump_analysis_status'] = 'running'
                        logger.info("Dump analysis: extracting deep features (capa/FLOSS/YARA/strings)...")
                        try:
                            memory_features = self.memory_extractor.extract_features(dump_path, target_pid=pid)
                            result['memory_features'] = memory_features
                            result['dump_analysis_status'] = 'success'

                            # Persist extracted features for offline review
                            try:
                                feature_path = Path(dump_path).with_suffix('.analysis.json')
                                with open(feature_path, 'w', encoding='utf-8') as f:
                                    json.dump(memory_features, f, indent=2)
                                result['memory_features_file'] = str(feature_path)
                                logger.info(f"Dump analysis: features saved to {feature_path}")
                            except Exception as e:
                                logger.warning(f"Dump analysis: failed to save features: {e}")
                            
                            # Re-analyze with memory features for better accuracy
                            enhanced_text = analysis_text + "\n\n" + memory_features['feature_text']
                            enhanced_result = self.detector.detect(
                                text=enhanced_text,
                                threshold=0.5
                            )
                            
                            # Update with enhanced analysis
                            result['enhanced_confidence'] = enhanced_result['confidence']
                            result['final_stage'] = enhanced_result['stage_name']
                            result['memory_indicators'] = {
                                'api_calls': memory_features['api_calls'],
                                'obfuscation_score': memory_features['obfuscation_score'],
                                'injection_patterns': len(memory_features['injection_patterns']),
                                'urls': memory_features['urls'][:5],
                                'suspicious_count': len(memory_features['suspicious_strings'])
                            }
                            
                            logger.info(
                                f"Dump analysis complete: "
                                f"{len(memory_features['suspicious_strings'])} indicators, "
                                f"obfuscation={memory_features['obfuscation_score']}, "
                                f"confidence: {result['confidence']:.2%} -> {enhanced_result['confidence']:.2%}"
                            )
                        except Exception as e:
                            result['dump_analysis_status'] = 'failed'
                            result['memory_features_error'] = str(e)
                            logger.error(f"Dump analysis failed: {e}")
                    else:
                        result['memory_dump_error'] = "ProcDump failed; see logs for details"
                
                return result
            else:
                logger.warning("No detector available - returning process info only")
                return {'process_info': proc_info, 'verdict': 'unknown'}
            
        except psutil.NoSuchProcess:
            logger.warning(f"Process {pid} no longer exists")
            return None
        except Exception as e:
            logger.error(f"Error analyzing process {pid}: {e}")
            return None
    
    def _build_analysis_text(self, proc_info: Dict, event: Optional[Dict] = None) -> str:
        """Build text representation for BERT model (augmented with Sysmon event if present)"""
        parts = []
        
        parts.append(f"Process: {proc_info.get('name', 'unknown')} (PID: {proc_info.get('pid', 0)})")
        
        if proc_info.get('parent_name'):
            parts.append(f"Parent: {proc_info['parent_name']} (PID: {proc_info.get('parent_pid', 0)})")
        
        if proc_info.get('cmdline'):
            parts.append(f"Command: {proc_info['cmdline'][:200]}")
        
        if proc_info.get('exe_path'):
            parts.append(f"Path: {proc_info['exe_path']}")
        
        if proc_info.get('connections'):
            for conn in proc_info['connections'][:3]:
                parts.append(f"Network: {conn['local']} -> {conn.get('remote', 'N/A')}")
        
        parts.append(f"CPU: {proc_info.get('cpu_percent', 0):.1f}%")
        parts.append(f"Memory: {proc_info.get('memory_mb', 0):.1f} MB")

        if event:
            parts.append(f"Sysmon EventId: {event.get('event_id')} RecordId: {event.get('record_id')}")
            if event.get('reasons'):
                parts.append(f"Suspicion: {', '.join(event['reasons'])}")
            if event.get('message'):
                parts.append("Sysmon Message:")
                parts.append(event['message'][:2000])
        
        return "\n".join(parts)
    
    def monitor_loop(self):
        """
        Main monitoring loop (runs in separate thread)
        
        Uses Sysmon event polling for suspicious activity
        """
        logger.info("Process monitoring started (Sysmon)")
        
        while not self.stop_event.is_set():
            try:
                self._monitor_loop_sysmon()
                time.sleep(self.SCAN_INTERVAL)
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(self.SCAN_INTERVAL)
    
    def _monitor_loop_sysmon(self):
        """Poll Sysmon events and enqueue suspicious ones."""
        events = self._fetch_sysmon_events()
        for ev in events:
            record_id = ev.get('record_id')
            if self.last_record_id and record_id and record_id <= self.last_record_id:
                continue

            suspicious, reasons = self._is_suspicious_sysmon_event(ev)
            self.stats['total_events'] += 1
            if suspicious:
                ev['reasons'] = reasons
                logger.info(f"Suspicious Sysmon event {record_id} (EID {ev.get('event_id')}): {', '.join(reasons)}")
                self.suspicious_queue.put(ev)
                self.stats['suspicious_found'] += 1

            if record_id and (self.last_record_id is None or record_id > self.last_record_id):
                self.last_record_id = record_id
    
    def analysis_loop(self):
        """
        Process analysis loop (runs in separate thread)
        
        Dequeues suspicious Sysmon events and analyzes associated processes
        """
        logger.info("Analysis loop started")
        
        while not self.stop_event.is_set():
            try:
                if not self.suspicious_queue.empty():
                    event = self.suspicious_queue.get(timeout=1)

                    pid = event.get('pid')
                    if pid:
                        logger.info(f"Analyzing suspicious process PID {pid} from Sysmon Record {event.get('record_id')}")
                        result = self.analyze_process(pid, event)
                    else:
                        logger.info(f"Analyzing Sysmon event without PID (Record {event.get('record_id')})")
                        result = self._analyze_event_without_pid(event)
                    
                    if result:
                        if result['verdict'] == 'malicious':
                            self.detected_malware.append(result)
                            self.stats['malware_detected'] += 1
                            self._alert_malware(result)
                        else:
                            self.stats['benign_processes'] += 1
                else:
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
                time.sleep(1)
        
        logger.info("Analysis loop stopped")
    
    def _alert_malware(self, result: Dict):
        """Send alert for detected malware"""
        proc_info = result.get('process_info', {})
        
        # Format command line (wrap long lines)
        cmdline = proc_info.get('cmdline', 'N/A')
        if len(cmdline) > 70:
            cmdline = cmdline[:67] + '...'
        
        # Format tactics (wrap if too long)
        tactics = result.get('tactics', [])
        tactics_str = ', '.join(tactics) if tactics else 'N/A'
        if len(tactics_str) > 50:
            tactics_str = '\n    '.join(tactics)
        
        # Format techniques (wrap if too long)
        techniques = result.get('common_techniques', [])[:5]
        if len(techniques) > 3:
            techniques_str = '\n    ' + '\n    '.join(techniques)
        else:
            techniques_str = ', '.join(techniques) if techniques else 'N/A'
        
        # Format Sysmon reasons (wrap if too long)
        reasons = proc_info.get('sysmon_reasons', [])
        if reasons:
            if len(reasons) > 2:
                reasons_str = '\n    - ' + '\n    - '.join(reasons)
            else:
                reasons_str = ', '.join(reasons)
        else:
            reasons_str = 'N/A'
        
        # Format recommendation (wrap long lines)
        recommendation = result.get('recommendation', 'N/A')
        if len(recommendation) > 70:
            # Split into multiple lines at sentence boundaries
            import textwrap
            recommendation = '\n  '.join(textwrap.wrap(recommendation, width=70))
        
        alert = f"""
{'='*60}
!! MALWARE DETECTED !!
{'='*60}
Process: {proc_info.get('name', 'unknown')} (PID: {proc_info.get('pid', 0)})
Path: {proc_info.get('exe_path', 'unknown')}
Command: {cmdline}

Detection:
  Verdict: {result['verdict'].upper()}
  Confidence: {result['confidence']:.2%}
  Attack Stage: {result['stage_name']} (Stage {result['stage']})
  
MITRE ATT&CK:
  Tactics: {tactics_str}
  Techniques: {techniques_str}

Sysmon:
  EventId: {proc_info.get('sysmon_event_id', 'N/A')}
  RecordId: {proc_info.get('sysmon_record_id', 'N/A')}
  Reasons: {reasons_str}

Recommendation:
  {recommendation}

Timestamp: {datetime.now().isoformat()}
{'='*60}
"""
        logger.warning(alert)
        
        # Save to file
        alerts_file = Path("malware_alerts.log")
        with open(alerts_file, 'a', encoding='utf-8') as f:
            f.write(alert + "\n")
    
    def start(self):
        """Start monitoring"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            logger.warning("Monitor already running")
            return
        
        logger.info("Starting process monitor...")
        self.stop_event.clear()
        
        # Start monitoring thread
        self.monitor_thread = Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # Start analysis thread
        self.analysis_thread = Thread(target=self.analysis_loop, daemon=True)
        self.analysis_thread.start()
        
        logger.info("Process monitor started successfully")
    
    def stop(self):
        """Stop monitoring"""
        logger.info("Stopping process monitor...")
        self.stop_event.set()
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        if hasattr(self, 'analysis_thread'):
            self.analysis_thread.join(timeout=5)
        
        logger.info("Process monitor stopped")
    
    def get_stats(self) -> Dict:
        """Get monitoring statistics"""
        return {
            **self.stats,
            'queue_size': self.suspicious_queue.qsize(),
            'monitored_pids': len(self.monitored_pids),
            'detected_malware_count': len(self.detected_malware),
            'last_sysmon_record_id': self.last_record_id
        }
    
    def get_detected_malware(self) -> List[Dict]:
        """Get list of detected malware"""
        return self.detected_malware.copy()

    def _fetch_sysmon_events(self) -> List[Dict]:
        """Fetch recent Sysmon events via PowerShell (Get-WinEvent)."""
        try:
            cmd = [
                'powershell', '-NoProfile', '-Command',
                f"Get-WinEvent -LogName '{self.sysmon_log}' -MaxEvents {self.sysmon_batch} | "
                "Select-Object RecordId,TimeCreated,Id,Message | ConvertTo-Json -Depth 4"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode != 0:
                logger.warning(f"Get-WinEvent failed rc={result.returncode}: {result.stderr[:200]}")
                return []
            if not result.stdout:
                return []
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            events = []
            for ev in data:
                record_id = ev.get('RecordId')
                event_id = ev.get('Id')
                message = ev.get('Message') or ''
                time_created = ev.get('TimeCreated')
                parsed = self._parse_sysmon_message(message)
                events.append({
                    'record_id': record_id,
                    'event_id': event_id,
                    'message': message,
                    'time_created': time_created,
                    **parsed
                })
            return events
        except Exception as e:
            logger.error(f"Failed to fetch Sysmon events: {e}")
            return []

    def _parse_sysmon_message(self, message: str) -> Dict:
        """Extract common fields from Sysmon rendered message."""
        fields = {}
        patterns = {
            'pid': r'ProcessId:\s*(\d+)',
            'ppid': r'ParentProcessId:\s*(\d+)',
            'image': r'Image:\s*(.+)',
            'parent_image': r'ParentImage:\s*(.+)',
            'command_line': r'CommandLine:\s*(.+)',
            'parent_command_line': r'ParentCommandLine:\s*(.+)',
            'target_object': r'TargetObject:\s*(.+)',
            'destination_ip': r'DestinationIp:\s*([^\s]+)',
            'destination_port': r'DestinationPort:\s*(\d+)',
            'source_image': r'SourceImage:\s*(.+)',
            'target_image': r'TargetImage:\s*(.+)'
        }
        for key, pat in patterns.items():
            m = re.search(pat, message, re.IGNORECASE)
            if m:
                fields[key] = m.group(1).strip()
        # Normalize image basenames
        if 'image' in fields:
            fields['image_name'] = Path(fields['image']).name.lower()
        if 'parent_image' in fields:
            fields['parent_image_name'] = Path(fields['parent_image']).name.lower()
        # Convert pid/ppid to int if present
        for k in ('pid', 'ppid'):
            if k in fields:
                try:
                    fields[k] = int(fields[k])
                except:
                    pass
        return fields

    def _is_suspicious_sysmon_event(self, ev: Dict) -> (bool, List[str]):
        """Apply heuristics to Sysmon event to decide suspicion."""
        reasons: List[str] = []
        eid = ev.get('event_id')
        image = ev.get('image_name') or ''
        parent_image = ev.get('parent_image_name') or ''
        target_image = ev.get('target_image_name') or ''
        source_image = ev.get('source_image_name') or ''
        cmd = (ev.get('command_line') or '').lower()
        target_object = (ev.get('target_object') or '').lower()

        # Exclude system/protected processes
        if image in self.SYSTEM_PROCESSES_EXCLUDE:
            return False, []
        if source_image in self.SYSTEM_PROCESSES_EXCLUDE:
            return False, []
        if target_image in self.SYSTEM_PROCESSES_EXCLUDE:
            return False, []

        # 1) Script interpreters / LOLBins
        if image in self.SUSPICIOUS_PROCESSES:
            reasons.append(f"LOLBIN: {image}")

        # 2) Parent-child anomalies
        if parent_image in self.SUSPICIOUS_PARENTS and image in self.SUSPICIOUS_PROCESSES:
            reasons.append(f"Parent-child anomaly: {parent_image}->{image}")

        # 3) Registry persistence (Sysmon EID 12/13/14 or Run keys)
        if eid in (12, 13, 14) or ('\\run' in target_object and 'microsoft\\windows' in target_object):
            reasons.append("Registry persistence")

        # 4) Memory artifacts (injection/hollowing): EID 8 (CreateRemoteThread), 10 (Process Access)
        if eid in (8, 10):
            reasons.append("Memory injection/hollowing artifact")

        # 5) Network patterns (C2-ish): EID 3
        if eid == 3:
            reasons.append("Network connection (possible C2)")

        # 6) Script interpreter commandline clues
        if any(token in cmd for token in ['-enc', 'encodedcommand', 'frombase64string', 'downloadstring']):
            reasons.append("Script obfuscation/encoded command")

        suspicious = len(reasons) > 0
        return suspicious, reasons

    def _analyze_event_without_pid(self, event: Dict) -> Optional[Dict]:
        """Analyze Sysmon event when PID is unavailable (event text only)."""
        if not self.detector:
            return None

        analysis_text = f"Sysmon EventId {event.get('event_id')} RecordId {event.get('record_id')}\n" + (event.get('message') or '')
        result = self.detector.detect(text=analysis_text, threshold=0.5)
        result['process_info'] = {'sysmon_event_id': event.get('event_id'), 'sysmon_record_id': event.get('record_id')}
        result['timestamp'] = datetime.now().isoformat()
        return result


if __name__ == "__main__":
    # Test monitoring
    print("Testing Process Monitor...")
    monitor = ProcessMonitor()
    
    try:
        monitor.start()
        print("Monitoring for 30 seconds...")
        time.sleep(30)
        
        stats = monitor.get_stats()
        print("\nStatistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
    finally:
        monitor.stop()
