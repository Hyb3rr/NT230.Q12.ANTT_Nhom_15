"""
Memory Feature Extractor for Fileless Malware Detection

WinDbg-based dump analysis (replaces strings/capa/FLOSS/YARA pipeline)
"""

import re
import os
import sys
import json
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class MemoryFeatureExtractor:
    def __init__(self, volatility_path: Optional[str] = None):
        # Volatility is intentionally disabled in this configuration
        self.use_volatility = False

        # Local tools directory (no auto-download; look alongside file and in tools/)
        self.base_dir = Path(__file__).resolve().parent
        self.tools_dir = self.base_dir / 'tools'
        self.tools_dir.mkdir(exist_ok=True)
        # WinDbg / cdb path (preferred for dump analysis)
        self.windbg_path = (
            self._find_tool('WINDBG_PATH', ['windbg.exe', 'cdb.exe']) or
            self._find_local_tool(['windbg.exe', 'cdb.exe'])
        )
        self.windbg_timeout = int(os.getenv('WINDBG_TIMEOUT', '180'))
        if self.windbg_path:
            logger.info(f"WinDbg debugger found at: {self.windbg_path}")
        else:
            logger.warning("WinDbg (windbg.exe/cdb.exe) not found; dump analysis will be skipped")
        
        self.suspicious_apis = [
            'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
            'CreateRemoteThread', 'QueueUserAPC', 'SetThreadContext',
            'NtMapViewOfSection', 'ZwUnmapViewOfSection', 'ResumeThread',
            'LoadLibrary', 'GetProcAddress', 'WinExec', 'ShellExecute'
        ]
        
        self.lolbin_patterns = [
            'powershell', 'cmd.exe', 'wmic', 'mshta', 'rundll32',
            'regsvr32', 'certutil', 'bitsadmin', 'wscript', 'cscript'
        ]
        
        self.obfuscation_patterns = [
            r'-[eE][nN][cC]',  # PowerShell -enc
            r'-[eE](?:ncodedcommand)?',
            r'[A-Za-z0-9+/]{50,}={0,2}',  # Base64
            r'\\x[0-9a-fA-F]{2}',  # Hex escape
            r'%[0-9a-fA-F]{2}',  # URL encoding
            r'chr\(\d+\)',  # Character encoding
        ]
    
    def _find_volatility(self) -> Optional[str]:
        """Volatility intentionally disabled; return None."""
        return None
    
    def extract_features(self, dump_path: str, target_pid: Optional[int] = None) -> Dict:
        """
        Main feature extraction pipeline (process-centric tools)

        Args:
            dump_path: Path to .dmp file
            target_pid: Specific PID to analyze (extracted from filename if None)
            
        Returns:
            Dictionary with extracted features (strings, capa, FLOSS, YARA)
        """
        if not os.path.exists(dump_path):
            logger.error(f"Dump file not found: {dump_path}")
            return self._empty_features()
        
        logger.info(f"Extracting features from: {dump_path}")
        
        # Extract PID from filename if not provided
        if target_pid is None:
            target_pid = self._extract_pid_from_filename(dump_path)
        
        features = {
            'suspicious_strings': [],
            'api_calls': [],
            'urls': [],
            'ip_addresses': [],
            'base64_blobs': [],
            'obfuscation_indicators': [],
            'injection_patterns': [],
            'lolbin_usage': [],
            'obfuscation_score': 0,
            'feature_text': '',
            'windbg_output': ''
        }
        
        try:
            # Run WinDbg analysis (best-effort)
            windbg_text = self._run_windbg_analysis(dump_path)
            if windbg_text:
                # Save full WinDbg output to separate file (avoid bloating JSON)
                try:
                    windbg_file = Path(dump_path).with_suffix('.windbg.txt')
                    with open(windbg_file, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(windbg_text)
                    logger.info(f"WinDbg output saved to {windbg_file}")
                except Exception as e:
                    logger.warning(f"Failed to save WinDbg output: {e}")
                
                # Store only summary in features (not full output)
                features['windbg_output'] = f"[Full output saved to .windbg.txt file - {len(windbg_text)} chars]"
                features = self._analyze_strings(windbg_text.splitlines(), features)
                features['obfuscation_score'] = self._calculate_obfuscation_score(features)
                logger.info(f"WinDbg extracted {len(features['suspicious_strings'])} suspicious indicators")
            else:
                features['feature_text'] = 'WinDbg analysis unavailable'

            # Build feature text for BERT model (include WinDbg summary)
            features['feature_text'] = self._build_feature_text(features, windbg_text)
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return self._empty_features()
        
        return features

    def _find_tool(self, env_var: str, names: List[str]) -> Optional[str]:
        """Resolve tool path via env override or PATH lookup."""
        env_path = os.getenv(env_var)
        if env_path:
            p = Path(env_path).expanduser()
            if p.exists():
                return str(p)
        for name in names:
            found = shutil.which(name)
            if found:
                return found
        return None

    def _find_local_tool(self, names: List[str]) -> Optional[str]:
        """Look for tool binaries in the script directory or tools subdir."""
        search_dirs = [self.base_dir, self.tools_dir]
        for directory in search_dirs:
            for name in names:
                candidate = directory / name
                if candidate.exists():
                    return str(candidate)
        return None

    def _auto_fetch_tool(self, label: str, urls: List[Optional[str]], binary_names: List[str]) -> Optional[str]:
        """Best-effort download and extract a tool into tools_dir from a list of URLs."""
        for url in urls:
            if not url:
                continue
            try:
                logger.info(f"Attempting to download {label} from {url}")
                with tempfile.TemporaryDirectory() as tmpdir:
                    archive_path = Path(tmpdir) / f"{label}.zip"
                    urllib.request.urlretrieve(url, archive_path)
                    extract_dir = Path(tmpdir) / f"{label}_extracted"
                    extract_dir.mkdir(exist_ok=True)
                    with zipfile.ZipFile(archive_path, 'r') as zf:
                        zf.extractall(extract_dir)
                    # Copy first matching binary to tools_dir
                    for bin_name in binary_names:
                        candidate = next(extract_dir.rglob(bin_name), None)
                        if candidate and candidate.exists():
                            target = self.tools_dir / candidate.name
                            shutil.copy2(candidate, target)
                            if os.name != 'nt':
                                target.chmod(target.stat().st_mode | 0o111)
                            return str(target)
                logger.warning(f"{label}: download succeeded but no expected binary found ({binary_names})")
            except Exception as e:
                logger.warning(f"{label}: auto-download failed from {url}: {e}")
        return None
    
    def _extract_pid_from_filename(self, dump_path: str) -> Optional[int]:
        """Extract PID from dump filename (kept for compatibility)."""
        import re
        match = re.search(r'PID(\d+)', dump_path)
        if match:
            return int(match.group(1))
        return None
    
    
    def _analyze_strings(self, strings_data: List[str], features: Dict) -> Dict:
        """
        Analyze extracted strings for malware indicators
        """
        for string in strings_data:
            # Skip very short strings
            if len(string) < 4:
                continue
            
            # Check for URLs
            if re.search(r'https?://[\w\.\-/]+', string, re.IGNORECASE):
                features['urls'].append(string)
                features['suspicious_strings'].append(f"URL: {string[:100]}")
            
            # Check for IP addresses
            ip_match = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', string)
            if ip_match:
                features['ip_addresses'].extend(ip_match)
                features['suspicious_strings'].append(f"IP: {string[:100]}")
            
            # Check for Base64 (50+ chars)
            b64_match = re.search(r'[A-Za-z0-9+/]{50,}={0,2}', string)
            if b64_match:
                features['base64_blobs'].append(b64_match.group()[:100])
                features['obfuscation_indicators'].append('Base64 encoding detected')
            
            # Check for obfuscation patterns
            for pattern in self.obfuscation_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    features['obfuscation_indicators'].append(f"Obfuscation: {string[:80]}")
                    break
            
            # Check for suspicious API calls
            for api in self.suspicious_apis:
                if api.lower() in string.lower():
                    features['api_calls'].append(api)
                    features['injection_patterns'].append(f"API: {api} in {string[:60]}")
            
            # Check for LOLBin usage
            for lolbin in self.lolbin_patterns:
                if lolbin.lower() in string.lower():
                    features['lolbin_usage'].append(f"{lolbin}: {string[:80]}")
        
        # Deduplicate
        features['api_calls'] = list(set(features['api_calls']))
        features['ip_addresses'] = list(set(features['ip_addresses']))
        
        return features

    def _run_windbg_analysis(self, dump_path: str) -> Optional[str]:
        """Run WinDbg/cdb on a dump and return collected output."""
        if not self.windbg_path:
            return None

        commands = '!analyze -v; lmv; !peb; !handles -a; !threads; q'
        cmd = [self.windbg_path, '-z', dump_path, '-c', commands]
        logger.info(f"Running WinDbg: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.windbg_timeout,
                errors='ignore'
            )
            if result.stdout:
                return result.stdout.strip()
            logger.warning(f"WinDbg produced no output; rc={result.returncode}, stderr={result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            logger.warning(f"WinDbg timed out after {self.windbg_timeout}s on {dump_path}")
        except Exception as e:
            logger.warning(f"WinDbg execution failed: {e}")
        return None
    
    def _calculate_obfuscation_score(self, features: Dict) -> int:
        """
        Calculate obfuscation score (0-100)
        
        Based on:
        - Number of Base64 blobs
        - Obfuscation indicators
        - Encoded command patterns
        """
        score = 0
        
        # Base64 encoding (+5 per blob, max 30)
        score += min(len(features['base64_blobs']) * 5, 30)
        
        # Obfuscation patterns (+10 per unique pattern, max 40)
        score += min(len(set(features['obfuscation_indicators'])) * 10, 40)
        
        # Multiple encoding layers (+20)
        if len(features['obfuscation_indicators']) > 3:
            score += 20
        
        # PowerShell -EncodedCommand (+10)
        for indicator in features['obfuscation_indicators']:
            if '-enc' in indicator.lower():
                score += 10
                break
        
        return min(score, 100)
    
    def _build_feature_text(self, features: Dict, windbg_text: Optional[str] = None) -> str:
        """
        Build comprehensive feature text for BERT model
        
        Combines all extracted features into natural language
        """
        parts = []
        
        # Memory dump analysis header
        parts.append("=== MEMORY DUMP ANALYSIS ===")
        
        # Suspicious API calls
        if features['api_calls']:
            parts.append(f"\nSuspicious APIs detected: {', '.join(features['api_calls'][:10])}")
        
        # Network indicators
        if features['urls']:
            parts.append(f"\nURLs found: {', '.join(features['urls'][:5])}")
        
        if features['ip_addresses']:
            parts.append(f"\nIP addresses: {', '.join(features['ip_addresses'][:5])}")
        
        # Code injection indicators
        if features['injection_patterns']:
            parts.append(f"\nInjection patterns: {'; '.join(features['injection_patterns'][:5])}")
        
        # Obfuscation
        if features['obfuscation_indicators']:
            parts.append(f"\nObfuscation detected (score: {features['obfuscation_score']})")
            parts.append(f"Indicators: {'; '.join(features['obfuscation_indicators'][:3])}")
        
        # LOLBin abuse
        if features['lolbin_usage']:
            parts.append(f"\nLOLBin usage: {'; '.join(features['lolbin_usage'][:3])}")
        
        # Base64 blobs
        if features['base64_blobs']:
            parts.append(f"\nBase64 encoded data found ({len(features['base64_blobs'])} instances)")
        
        # Summary
        parts.append(f"\n=== TOTAL INDICATORS: {len(features['suspicious_strings'])} ===")

        # WinDbg summary (truncated for readability)
        if windbg_text:
            windbg_lines = windbg_text.splitlines()
            # Extract key info: exception, module, failure bucket
            summary_lines = []
            for line in windbg_lines[:100]:  # Check first 100 lines
                if any(key in line for key in ['ExceptionCode:', 'PROCESS_NAME:', 'IMAGE_NAME:', 
                                                'FAILURE_BUCKET_ID:', 'MODULE_NAME:', 'ImageBaseAddress:']):
                    summary_lines.append(line.strip())
                if len(summary_lines) >= 10:  # Max 10 key lines
                    break
            
            if summary_lines:
                parts.append(f"\n[WinDbg] Key findings:")
                parts.extend(['  ' + line for line in summary_lines])
            else:
                # Fallback: show first few lines
                preview = '\n  '.join(windbg_lines[:10]) if windbg_lines else ''
                parts.append(f"\n[WinDbg] preview:\n  {preview}")
        
        return "\n".join(parts)

    def _empty_features(self) -> Dict:
        """Return empty feature set on error"""
        return {
            'suspicious_strings': [],
            'api_calls': [],
            'urls': [],
            'ip_addresses': [],
            'base64_blobs': [],
            'obfuscation_indicators': [],
            'injection_patterns': [],
            'lolbin_usage': [],
            'obfuscation_score': 0,
            'feature_text': 'No features extracted',
            'volatility_plugins': {},
            'windbg_output': ''
        }
