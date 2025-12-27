"""
Enhanced feature extraction for fileless malware detection
Based on: "Unveiling the veiled: An early stage detection of fileless malware"
Singh & Tripathy (2024) - IIT Patna

Key improvements:
- Integration with 4-stage attack classification
- Memory forensics feature extraction (VAD, handles, etc.)
- Enhanced API pattern detection
- LOLBin detection
- Feature Explainer integration
"""
import math
import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

# Import from fileless_techniques for stage detection
try:
    from fileless_techniques import (
        AttackStage, STAGE_NAMES, detect_techniques_from_text,
        infer_stage_from_text, get_technique_weight, ONE_HOT_TIDS_ENHANCED,
        FeatureExplainer, BEHAVIOR_KEYWORDS
    )
except ImportError:
    # Fallback for standalone usage
    AttackStage = None
    STAGE_NAMES = {0: "Initial", 1: "Pre-operational", 2: "Operational", 3: "Final"}


# ===========================
# PowerShell Detection
# ===========================

def detect_powershell_obfuscation(text: str) -> Dict[str, float]:
    """Phát hiện PowerShell obfuscation patterns"""
    text_lower = text.lower()
    
    # PowerShell encoding indicators
    has_encoded = int(any(x in text_lower for x in ['-enc', '-encodedcommand', '-e ', 'frombase64']))
    
    # Obfuscation patterns
    has_invoke_expr = int('invoke-expression' in text_lower or 'iex' in text_lower)
    has_bypass = int('bypass' in text_lower and 'executionpolicy' in text_lower)
    has_hidden = int('-hidden' in text_lower or '-windowstyle hidden' in text_lower)
    has_noprofile = int('-noprofile' in text_lower or '-nop' in text_lower)
    
    # Character substitution obfuscation
    special_char_ratio = sum(1 for c in text if c in '`^~') / max(len(text), 1)
    
    # String concatenation (obfuscation technique)
    concat_count = text.count('+') + text.count('.')
    concat_ratio = concat_count / max(len(text), 1)
    
    return {
        'ps_has_encoded': has_encoded,
        'ps_has_invoke_expr': has_invoke_expr,
        'ps_has_bypass': has_bypass,
        'ps_has_hidden': has_hidden,
        'ps_has_noprofile': has_noprofile,
        'ps_special_char_ratio': special_char_ratio,
        'ps_concat_ratio': concat_ratio,
    }


# ===========================
# API Call Pattern Detection
# ===========================

SUSPICIOUS_API_SEQUENCES = [
    # Memory manipulation
    ['virtualalloc', 'writeprocessmemory', 'createremotethread'],
    ['virtualalloc', 'rtlmovememory', 'createthread'],
    ['ntwritevirtualmemory', 'ntcreatethread'],
    
    # Process injection
    ['openprocess', 'virtualallocex', 'writeprocessmemory'],
    ['zwunmapviewofsection', 'virtualallocex', 'setthreadcontext'],
    
    # Reflective loading
    ['loadlibrary', 'getprocaddress', 'virtualprotect'],
    
    # Registry persistence
    ['regcreatekeyex', 'regsetvalueex'],
    ['regopenkeyex', 'regsetvalueex'],
]

CRITICAL_APIS = {
    # Memory operations
    'virtualalloc', 'virtualallocex', 'virtualprotect', 'virtualprotectex',
    'ntwritevirtualmemory', 'zwwritevirtualmemory', 'rtlmovememory',
    
    # Process operations
    'createprocess', 'createprocessa', 'createprocessw', 'createremotethread',
    'openprocess', 'terminateprocess', 'suspendthread', 'resumethread',
    'setthreadcontext', 'getthreadcontext',
    
    # DLL operations
    'loadlibrary', 'loadlibrarya', 'loadlibraryw', 'getprocaddress',
    'freelibrary', 'getmodulehandle',
    
    # Registry operations
    'regcreatekeyex', 'regopenkeyex', 'regsetvalueex', 'regqueryvalueex',
    'regdeletekey', 'regdeletevalue',
    
    # File operations
    'createfile', 'createfilea', 'createfilew', 'writefile', 'readfile',
    'deletefile', 'movefileex',
    
    # Anti-debugging
    'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess',
    
    # WMI/COM
    'coinitialize', 'cocreateinstance', 'wmi',
}


def extract_api_patterns(text: str) -> Dict[str, float]:
    """Trích xuất API call patterns"""
    text_lower = text.lower()
    
    # Count critical APIs
    api_count = sum(1 for api in CRITICAL_APIS if api in text_lower)
    api_density = api_count / max(len(text.split()), 1)
    
    # Detect suspicious API sequences
    sequence_matches = 0
    for sequence in SUSPICIOUS_API_SEQUENCES:
        # Kiểm tra xem sequence có xuất hiện theo thứ tự không
        positions = []
        for api in sequence:
            pos = text_lower.find(api)
            if pos != -1:
                positions.append(pos)
        
        # Nếu tất cả APIs trong sequence đều có và theo đúng thứ tự
        if len(positions) == len(sequence) and positions == sorted(positions):
            sequence_matches += 1
    
    # Memory operation indicators
    memory_ops = sum(1 for api in ['virtualalloc', 'virtualprotect', 'writeprocessmemory'] 
                     if api in text_lower)
    
    # Process injection indicators
    injection_ops = sum(1 for api in ['createremotethread', 'setthreadcontext', 'ntcreatethread']
                        if api in text_lower)
    
    return {
        'api_count': api_count,
        'api_density': api_density,
        'api_sequence_matches': sequence_matches,
        'api_memory_ops': memory_ops,
        'api_injection_ops': injection_ops,
    }


# ===========================
# Encoding & Obfuscation Detection
# ===========================

def count_encoding_layers(text: str) -> int:
    """Đếm số lớp encoding (nested encoding)"""
    layers = 0
    current = text
    
    # Check for base64
    base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    
    for _ in range(5):  # Max 5 layers
        matches = base64_pattern.findall(current)
        if not matches:
            break
        
        layers += 1
        # Try to decode (simplified check)
        try:
            import base64
            decoded = base64.b64decode(matches[0], validate=True).decode('utf-8', errors='ignore')
            if len(decoded) > 10:
                current = decoded
            else:
                break
        except:
            break
    
    return layers


def detect_obfuscation_patterns(text: str) -> Dict[str, float]:
    """Phát hiện các patterns obfuscation"""
    
    # Character frequency analysis
    char_freq = {}
    for c in text:
        char_freq[c] = char_freq.get(c, 0) + 1
    
    # Abnormal character distribution (could indicate obfuscation)
    if len(char_freq) > 0:
        max_freq = max(char_freq.values())
        avg_freq = sum(char_freq.values()) / len(char_freq)
        freq_variance = max_freq / max(avg_freq, 1)
    else:
        freq_variance = 0
    
    # XOR pattern detection (repeated bytes)
    xor_pattern = int(bool(re.search(r'(\\x[0-9a-fA-F]{2}){10,}', text)))
    
    # Hex string patterns
    hex_pattern = int(bool(re.search(r'0x[0-9a-fA-F]{8,}', text)))
    
    # Excessive escape characters
    escape_ratio = text.count('\\') / max(len(text), 1)
    
    return {
        'obf_freq_variance': freq_variance,
        'obf_has_xor_pattern': xor_pattern,
        'obf_has_hex_pattern': hex_pattern,
        'obf_escape_ratio': escape_ratio,
        'obf_encoding_layers': count_encoding_layers(text),
    }


# ===========================
# Memory & Injection Indicators
# ===========================

def detect_memory_operations(text: str) -> Dict[str, float]:
    """Phát hiện memory operation indicators"""
    text_lower = text.lower()
    
    # Process hollowing indicators
    hollowing_keywords = ['ntunmapviewofsection', 'zwunmapviewofsection', 'process hollowing']
    has_hollowing = int(any(kw in text_lower for kw in hollowing_keywords))
    
    # Reflective DLL injection
    reflective_keywords = ['reflective', 'getprocaddress', 'loadlibrary']
    has_reflective = int(sum(1 for kw in reflective_keywords if kw in text_lower) >= 2)
    
    # APC injection
    apc_keywords = ['queueuserapc', 'ntqueueapcthread']
    has_apc = int(any(kw in text_lower for kw in apc_keywords))
    
    # Thread context manipulation
    context_keywords = ['setthreadcontext', 'getthreadcontext']
    has_context = int(any(kw in text_lower for kw in context_keywords))
    
    # Shellcode indicators
    shellcode_keywords = ['shellcode', 'payload', 'exploit']
    has_shellcode = int(any(kw in text_lower for kw in shellcode_keywords))
    
    return {
        'mem_has_hollowing': has_hollowing,
        'mem_has_reflective': has_reflective,
        'mem_has_apc': has_apc,
        'mem_has_context': has_context,
        'mem_has_shellcode': has_shellcode,
    }


# ===========================
# Registry & Persistence Indicators
# ===========================

def detect_persistence_patterns(text: str) -> Dict[str, float]:
    """Phát hiện persistence mechanisms"""
    text_lower = text.lower()
    
    # Registry run keys
    runkey_patterns = [
        r'hkey_current_user.*software.*microsoft.*windows.*currentversion.*run',
        r'hklm.*software.*microsoft.*windows.*currentversion.*run',
        r'hkcu.*software.*microsoft.*windows.*currentversion.*run',
    ]
    has_runkey = int(any(re.search(p, text_lower) for p in runkey_patterns))
    
    # Scheduled tasks
    schtasks_keywords = ['schtasks', '/create', 'scheduledtask']
    has_schtasks = int(any(kw in text_lower for kw in schtasks_keywords))
    
    # WMI persistence
    wmi_persist = ['wmi', 'filter', 'consumer', 'binding']
    has_wmi_persist = int(sum(1 for kw in wmi_persist if kw in text_lower) >= 3)
    
    # Service creation
    service_keywords = ['createservice', 'sc create', 'new-service']
    has_service = int(any(kw in text_lower for kw in service_keywords))
    
    return {
        'persist_has_runkey': has_runkey,
        'persist_has_schtasks': has_schtasks,
        'persist_has_wmi': has_wmi_persist,
        'persist_has_service': has_service,
    }


# ===========================
# LOLBin Detection
# ===========================

LOLBINS = {
    'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
    'cmd', 'cmd.exe',
    'wmic', 'wmic.exe',
    'rundll32', 'rundll32.exe',
    'regsvr32', 'regsvr32.exe',
    'mshta', 'mshta.exe',
    'certutil', 'certutil.exe',
    'bitsadmin', 'bitsadmin.exe',
    'msiexec', 'msiexec.exe',
    'cscript', 'cscript.exe', 'wscript', 'wscript.exe',
}


def detect_lolbin_usage(text: str) -> Dict[str, float]:
    """Phát hiện Living-off-the-Land binaries"""
    text_lower = text.lower()
    
    lolbin_count = sum(1 for lolbin in LOLBINS if lolbin in text_lower)
    lolbin_density = lolbin_count / max(len(text.split()), 1)
    
    return {
        'lolbin_count': lolbin_count,
        'lolbin_density': lolbin_density,
    }


# ===========================
# Combined Feature Extraction
# ===========================

def extract_advanced_features(text: str) -> Dict[str, float]:
    """Kết hợp tất cả advanced features"""
    features = {}
    
    features.update(detect_powershell_obfuscation(text))
    features.update(extract_api_patterns(text))
    features.update(detect_obfuscation_patterns(text))
    features.update(detect_memory_operations(text))
    features.update(detect_persistence_patterns(text))
    features.update(detect_lolbin_usage(text))
    
    return features


# ===========================
# STAGE-AWARE FEATURE EXTRACTION (Theo bài báo)
# ===========================

@dataclass
class StageFeatures:
    """Features với stage classification theo bài báo"""
    text_features: Dict[str, float]
    detected_techniques: Dict[str, float]
    inferred_stage: int
    stage_confidence: float
    explanations: List[str]


def extract_stage_aware_features(text: str, tid: str = "") -> StageFeatures:
    """
    Trích xuất features kết hợp với stage detection
    Theo phương pháp của bài báo Section 4.3-4.4
    """
    # Basic advanced features
    text_features = extract_advanced_features(text)
    
    # Technique detection
    detected_techniques = {}
    inferred_stage = 0
    stage_confidence = 0.0
    explanations = []
    
    if AttackStage is not None:
        detected_techniques = detect_techniques_from_text(text)
        stage, conf = infer_stage_from_text(text)
        inferred_stage = int(stage)
        stage_confidence = conf
        
        # Get explanations
        explainer = FeatureExplainer()
        explanations = explainer.explain(text)
    
    return StageFeatures(
        text_features=text_features,
        detected_techniques=detected_techniques,
        inferred_stage=inferred_stage,
        stage_confidence=stage_confidence,
        explanations=explanations
    )


def build_complete_features_v2(text: str, tid: str) -> Tuple[List[float], int, float]:
    """
    Xây dựng vector features hoàn chỉnh cho BERT-MLP model
    Phiên bản cải tiến theo bài báo
    
    Returns:
        - feature_vector: List of numeric features
        - inferred_stage: Predicted attack stage (0-3)
        - stage_confidence: Confidence score
    """
    from build_events_from_tram import (
        char_entropy, scan_tokens, keyword_counts
    )
    
    # Basic features
    length = len(text)
    ent = char_entropy(text)
    num_tokens = len(text.split())
    upper_ratio = sum(1 for c in text if c.isupper()) / max(1, len(text))
    has_b64, longest_b64, count_enc, count_chain = scan_tokens(text)
    reg_cnt, proc_cnt = keyword_counts(text)
    
    # One-hot encoding for TID (enhanced list)
    tid_onehot = [1 if tid == t else 0 for t in ONE_HOT_TIDS_ENHANCED] if AttackStage else [0] * 12
    
    # Advanced features
    advanced = extract_advanced_features(text)
    
    # Stage detection features
    detected_techniques = detect_techniques_from_text(text) if AttackStage else {}
    stage, conf = infer_stage_from_text(text) if AttackStage else (0, 0.0)
    
    # Stage one-hot (4 classes)
    stage_onehot = [1 if int(stage) == i else 0 for i in range(4)]
    
    # Technique weight score
    technique_score = sum(detected_techniques.values()) if detected_techniques else 0.0
    
    # Combine all features
    basic_feats = [
        length, 
        ent, 
        has_b64, 
        num_tokens, 
        upper_ratio,
        longest_b64, 
        count_enc, 
        count_chain, 
        reg_cnt, 
        proc_cnt,
        technique_score,  # New: total technique weight
        conf,  # New: stage confidence
    ]
    
    feature_vector = basic_feats + tid_onehot + list(advanced.values()) + stage_onehot
    
    return feature_vector, int(stage), conf


# ===========================
# MEMORY FORENSICS FEATURES (Theo bài báo Section 3.2)
# ===========================

def extract_memory_forensics_features(memory_content: str) -> Dict[str, float]:
    """
    Trích xuất features từ memory dump
    Dựa trên Volatility output như mô tả trong bài báo
    """
    text_lower = memory_content.lower()
    features = {}
    
    # VAD (Virtual Address Descriptor) features
    vad_rwx = int('page_execute_readwrite' in text_lower or 'rwx' in text_lower)
    vad_suspicious = int('vad' in text_lower and ('execute' in text_lower or 'inject' in text_lower))
    
    # Handle information
    handle_count = len(re.findall(r'handle|hkey|hfile', text_lower))
    
    # Network connections
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ip_matches = re.findall(ip_pattern, memory_content)
    unique_ips = len(set(ip_matches))
    
    port_pattern = r':(\d{2,5})'
    port_matches = re.findall(port_pattern, memory_content)
    unique_ports = len(set(port_matches))
    
    # Process parent-child relationships
    abnormal_parent = 0
    suspicious_parents = [
        ('powershell', 'winword'),
        ('cmd', 'winword'),
        ('powershell', 'excel'),
        ('cmd', 'excel'),
        ('rundll32', 'svchost'),
    ]
    for child, parent in suspicious_parents:
        if child in text_lower and parent in text_lower:
            abnormal_parent = 1
            break
    
    # DLL injection indicators
    dll_injection_keywords = ['loadlibrary', 'getprocaddress', 'createremotethread']
    dll_injection_score = sum(1 for kw in dll_injection_keywords if kw in text_lower)
    
    # Command line analysis
    has_encoded_cmd = int('-encodedcommand' in text_lower or '-enc ' in text_lower)
    has_download = int('downloadstring' in text_lower or 'webclient' in text_lower)
    
    # Registry artifacts
    registry_keys = len(re.findall(r'hk[lcu][mr]', text_lower))
    
    features.update({
        'mem_vad_rwx': vad_rwx,
        'mem_vad_suspicious': vad_suspicious,
        'mem_handle_count': handle_count,
        'mem_unique_ips': unique_ips,
        'mem_unique_ports': unique_ports,
        'mem_abnormal_parent': abnormal_parent,
        'mem_dll_injection_score': dll_injection_score,
        'mem_has_encoded_cmd': has_encoded_cmd,
        'mem_has_download': has_download,
        'mem_registry_keys': registry_keys,
    })
    
    return features


# ===========================
# BEHAVIOR SEQUENCE FEATURES
# ===========================

def extract_behavior_sequence(text: str) -> Dict[str, float]:
    """
    Trích xuất behavioral sequence features
    Quan trọng cho stage detection
    """
    text_lower = text.lower()
    
    # Attack chain indicators
    # Initial Access indicators
    initial_score = sum([
        'phishing' in text_lower,
        'attachment' in text_lower,
        'download' in text_lower and 'link' in text_lower,
    ]) / 3
    
    # Execution indicators
    execution_score = sum([
        'powershell' in text_lower,
        'cmd.exe' in text_lower or 'cmd ' in text_lower,
        'wmic' in text_lower,
        'mshta' in text_lower,
        'rundll32' in text_lower,
    ]) / 5
    
    # Persistence indicators
    persistence_score = sum([
        'run' in text_lower and 'registry' in text_lower,
        'schtasks' in text_lower,
        'service' in text_lower and 'create' in text_lower,
        'startup' in text_lower,
    ]) / 4
    
    # Defense evasion indicators
    evasion_score = sum([
        'obfuscat' in text_lower,
        'encode' in text_lower,
        'base64' in text_lower,
        'hidden' in text_lower,
        'bypass' in text_lower,
    ]) / 5
    
    # Credential access indicators
    credential_score = sum([
        'lsass' in text_lower,
        'mimikatz' in text_lower,
        'credential' in text_lower,
        'password' in text_lower,
        'sam' in text_lower,
    ]) / 5
    
    # C2 indicators
    c2_score = sum([
        bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)),
        'beacon' in text_lower,
        'c2' in text_lower,
        'http' in text_lower and ('download' in text_lower or 'upload' in text_lower),
    ]) / 4
    
    # Impact indicators
    impact_score = sum([
        'encrypt' in text_lower,
        'ransom' in text_lower,
        'vssadmin' in text_lower,
        'shadow' in text_lower and 'delete' in text_lower,
    ]) / 4
    
    return {
        'beh_initial_score': initial_score,
        'beh_execution_score': execution_score,
        'beh_persistence_score': persistence_score,
        'beh_evasion_score': evasion_score,
        'beh_credential_score': credential_score,
        'beh_c2_score': c2_score,
        'beh_impact_score': impact_score,
    }


def build_complete_features(text: str, tid: str) -> List[float]:
    """
    Xây dựng vector features hoàn chỉnh
    Kết hợp basic features + advanced features
    """
    from build_events_from_tram import (
        char_entropy, scan_tokens, keyword_counts, one_hot_tid
    )
    
    # Basic features (from original implementation)
    length = len(text)
    ent = char_entropy(text)
    num_tokens = len(text.split())
    upper_ratio = sum(1 for c in text if c.isupper()) / max(1, len(text))
    has_b64, longest_b64, count_enc, count_chain = scan_tokens(text)
    reg_cnt, proc_cnt = keyword_counts(text)
    tid_onehot = one_hot_tid(tid)
    
    # Advanced features
    advanced = extract_advanced_features(text)
    
    # Combine all
    basic_feats = [
        length, ent, has_b64, num_tokens, upper_ratio,
        longest_b64, count_enc, count_chain, reg_cnt, proc_cnt,
    ]
    
    return basic_feats + tid_onehot + list(advanced.values())


# ===========================
# COMPREHENSIVE FEATURE BUILDER (cho BERT-MLP)
# ===========================

def build_bert_mlp_features(text: str, tid: str = "") -> Dict:
    """
    Build features cho BERT-MLP model theo bài báo
    
    Returns dict với:
    - numeric_features: vector số cho MLP head
    - stage_label: predicted stage (để training)
    - technique_ids: detected techniques
    - explanations: feature explanations
    """
    # All numeric features
    basic_advanced = extract_advanced_features(text)
    memory_features = extract_memory_forensics_features(text)
    behavior_features = extract_behavior_sequence(text)
    
    # Combine numeric features
    all_features = {}
    all_features.update(basic_advanced)
    all_features.update(memory_features)
    all_features.update(behavior_features)
    
    # Stage detection
    detected_techniques = {}
    stage_label = 1  # Default to pre-operational
    stage_conf = 0.0
    explanations = []
    
    if AttackStage is not None:
        detected_techniques = detect_techniques_from_text(text)
        stage, conf = infer_stage_from_text(text)
        stage_label = int(stage)
        stage_conf = conf
        
        explainer = FeatureExplainer()
        explanations = explainer.explain(text)
    
    # Add stage-related features
    all_features['stage_confidence'] = stage_conf
    all_features['technique_count'] = len(detected_techniques)
    all_features['technique_weight_sum'] = sum(detected_techniques.values())
    
    return {
        'numeric_features': list(all_features.values()),
        'feature_names': list(all_features.keys()),
        'stage_label': stage_label,
        'stage_confidence': stage_conf,
        'technique_ids': list(detected_techniques.keys()),
        'technique_scores': detected_techniques,
        'explanations': explanations,
    }


# ===========================
# Example Usage
# ===========================

if __name__ == "__main__":
    # Test với một sample
    sample_text = """
    Process: powershell.exe (PID: 1234)
    Parent: winword.exe (abnormal parent-child relationship)
    Command: powershell.exe -noprofile -windowstyle hidden -encodedcommand 
    VirtualAlloc WriteProcessMemory CreateRemoteThread
    HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    VAD protection: PAGE_EXECUTE_READWRITE
    Network: 192.168.1.100:443 -> 10.0.0.1:8080
    """
    
    print("="*60)
    print("ENHANCED FEATURE EXTRACTION TEST")
    print("="*60)
    
    # Test advanced features
    features = extract_advanced_features(sample_text)
    print(f"\nAdvanced features ({len(features)}):")
    for key, value in list(features.items())[:10]:
        print(f"  {key}: {value}")
    
    # Test memory forensics features
    mem_features = extract_memory_forensics_features(sample_text)
    print(f"\nMemory forensics features ({len(mem_features)}):")
    for key, value in mem_features.items():
        print(f"  {key}: {value}")
    
    # Test behavior features
    beh_features = extract_behavior_sequence(sample_text)
    print(f"\nBehavior sequence features ({len(beh_features)}):")
    for key, value in beh_features.items():
        print(f"  {key}: {value:.2f}")
    
    # Test complete BERT-MLP features
    bert_features = build_bert_mlp_features(sample_text, "T1059.001")
    print(f"\nBERT-MLP features:")
    print(f"  Total numeric features: {len(bert_features['numeric_features'])}")
    print(f"  Stage label: {bert_features['stage_label']} ({STAGE_NAMES.get(bert_features['stage_label'], 'Unknown')})")
    print(f"  Stage confidence: {bert_features['stage_confidence']:.2f}")
    print(f"  Detected techniques: {bert_features['technique_ids']}")
    print(f"  Explanations: {len(bert_features['explanations'])} items")
    for exp in bert_features['explanations'][:3]:
        print(f"    - {exp}")
