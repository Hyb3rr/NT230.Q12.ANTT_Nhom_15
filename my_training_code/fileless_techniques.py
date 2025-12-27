"""
Comprehensive MITRE ATT&CK Techniques for Fileless Malware Detection
Based on: "Unveiling the veiled: An early stage detection of fileless malware"
Singh & Tripathy (2024) - IIT Patna

Key methodology:
- 4 Attack Stages: Initial (0), Pre-operational (1), Operational (2), Final (3)
- MITRE ATT&CK mapping with stage classification
- Feature extraction for BERT-MLP model
- Feature Explainer using rule-based + LLM approach
"""

from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import IntEnum
import re
import json


# ===========================
# ATTACK STAGES (từ bài báo - Section 4.2)
# ===========================

class AttackStage(IntEnum):
    """
    4 giai đoạn tấn công theo bài báo:
    - Initial (0): Initial Access - giai đoạn xâm nhập ban đầu
    - Pre-operational (1): Execution, Persistence, Privilege Escalation - chuẩn bị
    - Operational (2): Defense Evasion, Credential Access, Discovery, Lateral Movement
    - Final (3): Collection, C2, Exfiltration, Impact - giai đoạn cuối
    
    Bài báo phát hiện 59.3% malware ở Pre-operational stage (early detection)
    """
    INITIAL = 0
    PRE_OPERATIONAL = 1
    OPERATIONAL = 2
    FINAL = 3


STAGE_NAMES = {
    AttackStage.INITIAL: "Initial Stage",
    AttackStage.PRE_OPERATIONAL: "Pre-operational Stage", 
    AttackStage.OPERATIONAL: "Operational Stage",
    AttackStage.FINAL: "Final Stage"
}

STAGE_DESCRIPTIONS = {
    AttackStage.INITIAL: "Initial access to target system via phishing, exploitation, etc.",
    AttackStage.PRE_OPERATIONAL: "Setting up for attack - execution, persistence, privilege escalation",
    AttackStage.OPERATIONAL: "Active attack - evasion, credential theft, discovery, lateral movement",
    AttackStage.FINAL: "Mission completion - data collection, exfiltration, impact"
}

# Mapping từ MITRE Tactics sang Attack Stage (theo Table 6-8 trong bài báo)
TACTICS_TO_STAGE: Dict[str, AttackStage] = {
    # Initial Stage (0) - Table 6
    "initial-access": AttackStage.INITIAL,
    "reconnaissance": AttackStage.INITIAL,
    "resource-development": AttackStage.INITIAL,
    
    # Pre-operational Stage (1) - Table 7
    "execution": AttackStage.PRE_OPERATIONAL,
    "persistence": AttackStage.PRE_OPERATIONAL,
    "privilege-escalation": AttackStage.PRE_OPERATIONAL,
    
    # Operational Stage (2) - Table 7
    "defense-evasion": AttackStage.OPERATIONAL,
    "credential-access": AttackStage.OPERATIONAL,
    "discovery": AttackStage.OPERATIONAL,
    "lateral-movement": AttackStage.OPERATIONAL,
    
    # Final Stage (3) - Table 8
    "collection": AttackStage.FINAL,
    "command-and-control": AttackStage.FINAL,
    "exfiltration": AttackStage.FINAL,
    "impact": AttackStage.FINAL,
}


# ===========================
# TECHNIQUE INFO DATACLASS
# ===========================

@dataclass
class TechniqueInfo:
    """Thông tin chi tiết về một MITRE ATT&CK technique"""
    tid: str
    name: str
    tactic: str
    stage: AttackStage
    description: str = ""
    weight: float = 1.0
    is_fileless: bool = True
    keywords: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        # Auto-generate keywords from name and description
        if not self.keywords:
            text = f"{self.name} {self.description}".lower()
            self.keywords = [w for w in re.findall(r'\w+', text) if len(w) > 3]


# ===========================
# COMPLETE TECHNIQUE DATABASE
# Dựa trên bài báo và MITRE ATT&CK Enterprise
# ===========================

TECHNIQUE_DATABASE: Dict[str, TechniqueInfo] = {
    # ===============================
    # === INITIAL STAGE (0) ===
    # ===============================
    "T1566": TechniqueInfo("T1566", "Phishing", "initial-access", AttackStage.INITIAL,
        "Phishing attachment or link delivery for initial access", 2.0, True,
        ["phishing", "email", "attachment", "link", "spearphishing"]),
    "T1566.001": TechniqueInfo("T1566.001", "Spearphishing Attachment", "initial-access", AttackStage.INITIAL,
        "Malicious file attachment in targeted email", 2.5, True,
        ["attachment", "document", "macro", "office", "pdf"]),
    "T1566.002": TechniqueInfo("T1566.002", "Spearphishing Link", "initial-access", AttackStage.INITIAL,
        "Link to malicious site that downloads fake installer", 2.5, True,
        ["link", "url", "download", "flash", "installer"]),
    "T1190": TechniqueInfo("T1190", "Exploit Public-Facing Application", "initial-access", AttackStage.INITIAL,
        "Exploiting vulnerable web servers to gain access", 2.5, True,
        ["exploit", "web", "server", "vulnerability", "cve"]),
    "T1133": TechniqueInfo("T1133", "External Remote Services", "initial-access", AttackStage.INITIAL,
        "Using compromised VPN credentials to access network", 2.0, True,
        ["vpn", "rdp", "remote", "citrix", "ssh"]),
    "T1078": TechniqueInfo("T1078", "Valid Accounts", "initial-access", AttackStage.INITIAL,
        "Using stolen/compromised credentials for access", 2.0, True,
        ["credentials", "password", "account", "login", "stolen"]),
    "T1189": TechniqueInfo("T1189", "Drive-by Compromise", "initial-access", AttackStage.INITIAL,
        "Compromising via malicious website visit", 2.0, True,
        ["driveby", "watering", "hole", "browser", "exploit"]),
    "T1195": TechniqueInfo("T1195", "Supply Chain Compromise", "initial-access", AttackStage.INITIAL,
        "Compromising software supply chain", 2.5, True,
        ["supply", "chain", "vendor", "update", "compromise"]),
    
    # ===============================
    # === PRE-OPERATIONAL STAGE (1) ===
    # ===============================
    
    # --- Execution ---
    "T1059": TechniqueInfo("T1059", "Command and Scripting Interpreter", "execution", AttackStage.PRE_OPERATIONAL,
        "Using command/script interpreters for execution", 3.0, True,
        ["cmd", "script", "interpreter", "shell", "command"]),
    "T1059.001": TechniqueInfo("T1059.001", "PowerShell", "execution", AttackStage.PRE_OPERATIONAL,
        "PowerShell command execution - critical for fileless malware", 3.5, True,
        ["powershell", "pwsh", "encodedcommand", "invoke", "iex", "downloadstring"]),
    "T1059.003": TechniqueInfo("T1059.003", "Windows Command Shell", "execution", AttackStage.PRE_OPERATIONAL,
        "cmd.exe command execution", 2.5, True,
        ["cmd", "batch", "bat", "command", "shell"]),
    "T1059.005": TechniqueInfo("T1059.005", "Visual Basic", "execution", AttackStage.PRE_OPERATIONAL,
        "VBScript execution via wscript/cscript", 2.5, True,
        ["vbscript", "wscript", "cscript", "vbs", "visual", "basic"]),
    "T1059.006": TechniqueInfo("T1059.006", "Python", "execution", AttackStage.PRE_OPERATIONAL,
        "Python script execution", 2.0, True,
        ["python", "py", "script"]),
    "T1059.007": TechniqueInfo("T1059.007", "JavaScript", "execution", AttackStage.PRE_OPERATIONAL,
        "JavaScript execution via mshta/cscript", 2.5, True,
        ["javascript", "jscript", "js", "mshta", "hta"]),
    "T1086": TechniqueInfo("T1086", "PowerShell (Legacy)", "execution", AttackStage.PRE_OPERATIONAL,
        "PowerShell - deprecated ID", 3.0, True,
        ["powershell"]),
    "T1106": TechniqueInfo("T1106", "Native API", "execution", AttackStage.PRE_OPERATIONAL,
        "Direct Windows API calls - core fileless technique", 3.5, True,
        ["api", "ntdll", "kernel32", "native", "syscall"]),
    "T1129": TechniqueInfo("T1129", "Shared Modules", "execution", AttackStage.PRE_OPERATIONAL,
        "Loading shared modules for execution", 2.0, True,
        ["dll", "module", "library", "load"]),
    "T1203": TechniqueInfo("T1203", "Exploitation for Client Execution", "execution", AttackStage.PRE_OPERATIONAL,
        "Exploiting client applications like browsers/Office", 2.5, True,
        ["exploit", "browser", "office", "client", "vulnerability"]),
    "T1204": TechniqueInfo("T1204", "User Execution", "execution", AttackStage.PRE_OPERATIONAL,
        "User-triggered malicious execution", 2.0, True,
        ["user", "click", "open", "execute"]),
    "T1204.002": TechniqueInfo("T1204.002", "Malicious File", "execution", AttackStage.PRE_OPERATIONAL,
        "User opens malicious file triggering execution", 2.0, True,
        ["malicious", "file", "document", "macro"]),
    "T1047": TechniqueInfo("T1047", "Windows Management Instrumentation", "execution", AttackStage.PRE_OPERATIONAL,
        "WMI for command execution - living-off-the-land", 3.5, True,
        ["wmi", "wmic", "winmgmt", "management", "instrumentation"]),
    
    # --- Persistence ---
    "T1053": TechniqueInfo("T1053", "Scheduled Task/Job", "persistence", AttackStage.PRE_OPERATIONAL,
        "Using scheduled tasks for persistence", 2.5, True,
        ["schtasks", "scheduled", "task", "job", "cron"]),
    "T1053.005": TechniqueInfo("T1053.005", "Scheduled Task", "persistence", AttackStage.PRE_OPERATIONAL,
        "Windows Task Scheduler abuse", 2.5, True,
        ["schtasks", "taskschd", "scheduler"]),
    "T1543": TechniqueInfo("T1543", "Create or Modify System Process", "persistence", AttackStage.PRE_OPERATIONAL,
        "Modifying system processes for persistence", 2.5, True,
        ["service", "systemd", "launchd"]),
    "T1543.003": TechniqueInfo("T1543.003", "Windows Service", "persistence", AttackStage.PRE_OPERATIONAL,
        "Creating malicious Windows service", 2.5, True,
        ["service", "sc", "create", "start"]),
    "T1547": TechniqueInfo("T1547", "Boot or Logon Autostart Execution", "persistence", AttackStage.PRE_OPERATIONAL,
        "Persistence via autostart mechanisms", 2.5, True,
        ["autostart", "startup", "boot", "logon"]),
    "T1547.001": TechniqueInfo("T1547.001", "Registry Run Keys", "persistence", AttackStage.PRE_OPERATIONAL,
        "Registry Run key persistence - very common", 3.0, True,
        ["registry", "run", "runonce", "hklm", "hkcu", "currentversion"]),
    "T1574": TechniqueInfo("T1574", "Hijack Execution Flow", "persistence", AttackStage.PRE_OPERATIONAL,
        "Hijacking execution flow for persistence", 2.5, True,
        ["hijack", "dll", "path", "search", "order"]),
    "T1574.001": TechniqueInfo("T1574.001", "DLL Search Order Hijacking", "persistence", AttackStage.PRE_OPERATIONAL,
        "DLL search order manipulation", 2.5, True,
        ["dll", "search", "order", "hijack"]),
    "T1574.002": TechniqueInfo("T1574.002", "DLL Side-Loading", "persistence", AttackStage.PRE_OPERATIONAL,
        "DLL side-loading for persistence", 2.5, True,
        ["dll", "sideload", "legitimate"]),
    
    # --- Privilege Escalation ---
    "T1055": TechniqueInfo("T1055", "Process Injection", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "Process injection - critical fileless technique", 3.5, True,
        ["injection", "inject", "process", "memory", "virtualalloc"]),
    "T1055.001": TechniqueInfo("T1055.001", "DLL Injection", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "DLL injection into processes", 3.0, True,
        ["dll", "injection", "loadlibrary", "createremotethread"]),
    "T1055.002": TechniqueInfo("T1055.002", "PE Injection", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "Portable Executable injection", 3.0, True,
        ["pe", "injection", "portable", "executable"]),
    "T1055.003": TechniqueInfo("T1055.003", "Thread Execution Hijacking", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "Hijacking thread execution context", 3.0, True,
        ["thread", "hijack", "setthreadcontext"]),
    "T1055.004": TechniqueInfo("T1055.004", "Asynchronous Procedure Call", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "APC injection for execution", 3.0, True,
        ["apc", "queueuserapc", "asynchronous"]),
    "T1055.005": TechniqueInfo("T1055.005", "Thread Local Storage", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "TLS callback injection", 2.5, True,
        ["tls", "callback", "storage"]),
    "T1055.008": TechniqueInfo("T1055.008", "Ptrace System Calls", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "Ptrace-based injection on Linux", 2.5, True,
        ["ptrace", "linux", "attach"]),
    "T1055.009": TechniqueInfo("T1055.009", "Proc Memory", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "Process memory manipulation via /proc", 2.5, True,
        ["proc", "mem", "memory"]),
    "T1055.011": TechniqueInfo("T1055.011", "Extra Window Memory Injection", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "EWM injection technique", 2.5, True,
        ["ewm", "window", "memory"]),
    "T1055.012": TechniqueInfo("T1055.012", "Process Hollowing", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "Process hollowing - replace legitimate process", 3.5, True,
        ["hollowing", "hollow", "unmapviewofsection", "zwunmap"]),
    "T1055.013": TechniqueInfo("T1055.013", "Process Doppelgänging", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "Process doppelgänging via NTFS transactions", 3.0, True,
        ["doppelganging", "transaction", "ntfs"]),
    "T1055.014": TechniqueInfo("T1055.014", "VDSO Hijacking", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "VDSO hijacking on Linux", 2.5, True,
        ["vdso", "linux"]),
    "T1134": TechniqueInfo("T1134", "Access Token Manipulation", "privilege-escalation", AttackStage.PRE_OPERATIONAL,
        "Token manipulation for privilege escalation", 2.5, True,
        ["token", "impersonate", "duplicate", "privilege"]),
    
    # ===============================
    # === OPERATIONAL STAGE (2) ===
    # ===============================
    
    # --- Defense Evasion ---
    "T1027": TechniqueInfo("T1027", "Obfuscated Files or Information", "defense-evasion", AttackStage.OPERATIONAL,
        "Code/data obfuscation for evasion", 3.0, True,
        ["obfuscation", "encode", "base64", "xor", "packed"]),
    "T1027.001": TechniqueInfo("T1027.001", "Binary Padding", "defense-evasion", AttackStage.OPERATIONAL,
        "Binary padding to change hash", 2.0, True,
        ["padding", "binary", "hash"]),
    "T1027.002": TechniqueInfo("T1027.002", "Software Packing", "defense-evasion", AttackStage.OPERATIONAL,
        "Packing executables to evade detection", 2.5, True,
        ["packer", "upx", "vmprotect", "themida"]),
    "T1027.003": TechniqueInfo("T1027.003", "Steganography", "defense-evasion", AttackStage.OPERATIONAL,
        "Hiding data in images", 2.0, True,
        ["steganography", "image", "hidden"]),
    "T1027.004": TechniqueInfo("T1027.004", "Compile After Delivery", "defense-evasion", AttackStage.OPERATIONAL,
        "Compiling code on target system", 2.5, True,
        ["compile", "source", "build"]),
    "T1027.005": TechniqueInfo("T1027.005", "Indicator Removal from Tools", "defense-evasion", AttackStage.OPERATIONAL,
        "Removing indicators from malicious tools", 2.5, True,
        ["indicator", "removal", "string"]),
    "T1036": TechniqueInfo("T1036", "Masquerading", "defense-evasion", AttackStage.OPERATIONAL,
        "Masquerading as legitimate files/processes", 2.5, True,
        ["masquerade", "disguise", "legitimate"]),
    "T1036.003": TechniqueInfo("T1036.003", "Rename System Utilities", "defense-evasion", AttackStage.OPERATIONAL,
        "Renaming system utilities to evade detection", 2.5, True,
        ["rename", "copy", "system"]),
    "T1036.004": TechniqueInfo("T1036.004", "Masquerade Task or Service", "defense-evasion", AttackStage.OPERATIONAL,
        "Masquerading malicious tasks/services", 2.5, True,
        ["task", "service", "masquerade"]),
    "T1036.005": TechniqueInfo("T1036.005", "Match Legitimate Name or Location", "defense-evasion", AttackStage.OPERATIONAL,
        "Using legitimate-looking names/paths", 2.5, True,
        ["legitimate", "name", "location", "path"]),
    "T1070": TechniqueInfo("T1070", "Indicator Removal", "defense-evasion", AttackStage.OPERATIONAL,
        "Removing indicators of compromise", 2.5, True,
        ["indicator", "removal", "clean", "delete"]),
    "T1070.001": TechniqueInfo("T1070.001", "Clear Windows Event Logs", "defense-evasion", AttackStage.OPERATIONAL,
        "Clearing Windows event logs", 2.5, True,
        ["eventlog", "wevtutil", "clear", "log"]),
    "T1070.004": TechniqueInfo("T1070.004", "File Deletion", "defense-evasion", AttackStage.OPERATIONAL,
        "Deleting malicious files to cover tracks", 2.0, True,
        ["delete", "remove", "file"]),
    "T1112": TechniqueInfo("T1112", "Modify Registry", "defense-evasion", AttackStage.OPERATIONAL,
        "Registry modification for evasion/persistence", 3.0, True,
        ["registry", "reg", "modify", "hklm", "hkcu"]),
    "T1140": TechniqueInfo("T1140", "Deobfuscate/Decode Files", "defense-evasion", AttackStage.OPERATIONAL,
        "Runtime deobfuscation of payloads", 3.0, True,
        ["decode", "deobfuscate", "base64", "decrypt"]),
    "T1202": TechniqueInfo("T1202", "Indirect Command Execution", "defense-evasion", AttackStage.OPERATIONAL,
        "Indirect command execution via forfiles/pcalua", 2.5, True,
        ["forfiles", "pcalua", "indirect"]),
    "T1216": TechniqueInfo("T1216", "Signed Script Proxy Execution", "defense-evasion", AttackStage.OPERATIONAL,
        "Using signed scripts for execution", 2.5, True,
        ["signed", "script", "pubprn"]),
    "T1218": TechniqueInfo("T1218", "Signed Binary Proxy Execution", "defense-evasion", AttackStage.OPERATIONAL,
        "LOLBins for proxy execution - very common", 3.0, True,
        ["lolbin", "signed", "proxy", "binary"]),
    "T1218.001": TechniqueInfo("T1218.001", "Compiled HTML File", "defense-evasion", AttackStage.OPERATIONAL,
        "CHM file abuse", 2.5, True,
        ["chm", "compiled", "html", "hh.exe"]),
    "T1218.004": TechniqueInfo("T1218.004", "InstallUtil", "defense-evasion", AttackStage.OPERATIONAL,
        "InstallUtil.exe abuse", 2.5, True,
        ["installutil", "uninstall"]),
    "T1218.005": TechniqueInfo("T1218.005", "Mshta", "defense-evasion", AttackStage.OPERATIONAL,
        "Mshta.exe executing HTA files - common fileless", 3.0, True,
        ["mshta", "hta", "javascript", "vbscript"]),
    "T1218.007": TechniqueInfo("T1218.007", "Msiexec", "defense-evasion", AttackStage.OPERATIONAL,
        "Msiexec for execution/download", 2.5, True,
        ["msiexec", "msi", "installer"]),
    "T1218.009": TechniqueInfo("T1218.009", "Regsvcs/Regasm", "defense-evasion", AttackStage.OPERATIONAL,
        "Regsvcs/Regasm abuse", 2.5, True,
        ["regsvcs", "regasm", "comregisterfunction"]),
    "T1218.010": TechniqueInfo("T1218.010", "Regsvr32", "defense-evasion", AttackStage.OPERATIONAL,
        "Regsvr32 for script execution - squiblydoo", 3.0, True,
        ["regsvr32", "scrobj", "squiblydoo"]),
    "T1218.011": TechniqueInfo("T1218.011", "Rundll32", "defense-evasion", AttackStage.OPERATIONAL,
        "Rundll32 abuse - core fileless technique", 3.5, True,
        ["rundll32", "dll", "javascript", "shell32"]),
    "T1218.012": TechniqueInfo("T1218.012", "Verclsid", "defense-evasion", AttackStage.OPERATIONAL,
        "Verclsid.exe abuse", 2.0, True,
        ["verclsid"]),
    "T1218.013": TechniqueInfo("T1218.013", "Mavinject", "defense-evasion", AttackStage.OPERATIONAL,
        "Mavinject.exe for DLL injection", 2.5, True,
        ["mavinject", "inject"]),
    "T1564": TechniqueInfo("T1564", "Hide Artifacts", "defense-evasion", AttackStage.OPERATIONAL,
        "Hiding artifacts from detection", 2.5, True,
        ["hide", "hidden", "artifact"]),
    "T1564.001": TechniqueInfo("T1564.001", "Hidden Files and Directories", "defense-evasion", AttackStage.OPERATIONAL,
        "Using hidden files/directories", 2.0, True,
        ["hidden", "attrib", "directory"]),
    "T1564.003": TechniqueInfo("T1564.003", "Hidden Window", "defense-evasion", AttackStage.OPERATIONAL,
        "Hidden window execution", 2.5, True,
        ["hidden", "window", "windowstyle"]),
    
    # --- Credential Access ---
    "T1003": TechniqueInfo("T1003", "OS Credential Dumping", "credential-access", AttackStage.OPERATIONAL,
        "Credential dumping from OS", 3.0, True,
        ["credential", "dump", "password", "hash"]),
    "T1003.001": TechniqueInfo("T1003.001", "LSASS Memory", "credential-access", AttackStage.OPERATIONAL,
        "LSASS memory dumping - critical technique", 3.5, True,
        ["lsass", "mimikatz", "procdump", "comsvcs"]),
    "T1003.002": TechniqueInfo("T1003.002", "Security Account Manager", "credential-access", AttackStage.OPERATIONAL,
        "SAM database extraction", 3.0, True,
        ["sam", "security", "account", "manager"]),
    "T1003.003": TechniqueInfo("T1003.003", "NTDS", "credential-access", AttackStage.OPERATIONAL,
        "NTDS.dit extraction from domain controller", 3.0, True,
        ["ntds", "dit", "domain", "controller"]),
    "T1555": TechniqueInfo("T1555", "Credentials from Password Stores", "credential-access", AttackStage.OPERATIONAL,
        "Password store access", 2.5, True,
        ["credential", "password", "store", "vault"]),
    "T1555.004": TechniqueInfo("T1555.004", "Windows Credential Manager", "credential-access", AttackStage.OPERATIONAL,
        "Windows Credential Manager access", 2.5, True,
        ["credential", "manager", "vaultcmd"]),
    
    # --- Discovery ---
    "T1012": TechniqueInfo("T1012", "Query Registry", "discovery", AttackStage.OPERATIONAL,
        "Registry querying for discovery", 2.0, True,
        ["reg", "query", "registry"]),
    "T1057": TechniqueInfo("T1057", "Process Discovery", "discovery", AttackStage.OPERATIONAL,
        "Discovering running processes via tasklist", 2.0, True,
        ["tasklist", "process", "ps", "get-process"]),
    "T1082": TechniqueInfo("T1082", "System Information Discovery", "discovery", AttackStage.OPERATIONAL,
        "System information gathering via systeminfo", 2.0, True,
        ["systeminfo", "hostname", "ver", "system"]),
    "T1083": TechniqueInfo("T1083", "File and Directory Discovery", "discovery", AttackStage.OPERATIONAL,
        "File/directory enumeration", 2.0, True,
        ["dir", "ls", "find", "tree"]),
    "T1135": TechniqueInfo("T1135", "Network Share Discovery", "discovery", AttackStage.OPERATIONAL,
        "Network share enumeration via net share", 2.0, True,
        ["net", "share", "smb"]),
    
    # --- Lateral Movement ---
    "T1021": TechniqueInfo("T1021", "Remote Services", "lateral-movement", AttackStage.OPERATIONAL,
        "Using remote services for lateral movement", 2.5, True,
        ["remote", "rdp", "ssh", "smb"]),
    "T1021.002": TechniqueInfo("T1021.002", "SMB/Windows Admin Shares", "lateral-movement", AttackStage.OPERATIONAL,
        "SMB lateral movement via admin shares", 2.5, True,
        ["smb", "admin$", "c$", "ipc$"]),
    "T1021.003": TechniqueInfo("T1021.003", "DCOM", "lateral-movement", AttackStage.OPERATIONAL,
        "DCOM for lateral movement", 2.5, True,
        ["dcom", "mmc", "excel"]),
    "T1021.006": TechniqueInfo("T1021.006", "Windows Remote Management", "lateral-movement", AttackStage.OPERATIONAL,
        "WinRM for lateral movement", 2.5, True,
        ["winrm", "wsman", "invoke-command", "enter-pssession"]),
    
    # ===============================
    # === FINAL STAGE (3) ===
    # ===============================
    
    # --- Collection ---
    "T1005": TechniqueInfo("T1005", "Data from Local System", "collection", AttackStage.FINAL,
        "Collecting data from local system", 2.5, True,
        ["collect", "data", "local", "file"]),
    "T1113": TechniqueInfo("T1113", "Screen Capture", "collection", AttackStage.FINAL,
        "Capturing screen content", 2.0, True,
        ["screenshot", "screen", "capture"]),
    "T1115": TechniqueInfo("T1115", "Clipboard Data", "collection", AttackStage.FINAL,
        "Clipboard data collection", 2.0, True,
        ["clipboard", "paste", "copy"]),
    "T1119": TechniqueInfo("T1119", "Automated Collection", "collection", AttackStage.FINAL,
        "Automated data collection on schedule", 2.5, True,
        ["automated", "collection", "scheduled"]),
    
    # --- Command and Control ---
    "T1071": TechniqueInfo("T1071", "Application Layer Protocol", "command-and-control", AttackStage.FINAL,
        "C2 over application protocols", 2.5, True,
        ["c2", "c&c", "http", "dns", "protocol"]),
    "T1071.001": TechniqueInfo("T1071.001", "Web Protocols", "command-and-control", AttackStage.FINAL,
        "HTTP/HTTPS C2 communication", 2.5, True,
        ["http", "https", "web", "beacon"]),
    "T1132": TechniqueInfo("T1132", "Data Encoding", "command-and-control", AttackStage.FINAL,
        "Encoding C2 data for obfuscation", 2.5, True,
        ["encode", "base64", "xor"]),
    "T1571": TechniqueInfo("T1571", "Non-Standard Port", "command-and-control", AttackStage.FINAL,
        "Using non-standard ports for C2", 2.5, True,
        ["port", "nonstandard", "custom"]),
    "T1573": TechniqueInfo("T1573", "Encrypted Channel", "command-and-control", AttackStage.FINAL,
        "Encrypted C2 channel", 2.5, True,
        ["encrypted", "ssl", "tls", "tunnel"]),
    
    # --- Exfiltration ---
    "T1020": TechniqueInfo("T1020", "Automated Exfiltration", "exfiltration", AttackStage.FINAL,
        "Automated data exfiltration on schedule", 2.5, True,
        ["exfiltration", "automated", "upload"]),
    "T1041": TechniqueInfo("T1041", "Exfiltration Over C2 Channel", "exfiltration", AttackStage.FINAL,
        "Exfiltration via existing C2 channel", 2.5, True,
        ["exfiltration", "c2", "upload"]),
    
    # --- Impact ---
    "T1486": TechniqueInfo("T1486", "Data Encrypted for Impact", "impact", AttackStage.FINAL,
        "Ransomware encryption of files", 3.0, True,
        ["ransomware", "encrypt", "ransom", "crypto"]),
    "T1490": TechniqueInfo("T1490", "Inhibit System Recovery", "impact", AttackStage.FINAL,
        "Preventing system recovery by deleting backups", 2.5, True,
        ["vssadmin", "wbadmin", "shadow", "backup", "delete"]),
    "T1529": TechniqueInfo("T1529", "System Shutdown/Reboot", "impact", AttackStage.FINAL,
        "Forcing system shutdown/reboot", 2.0, True,
        ["shutdown", "reboot", "exitwindowsex"]),
    
    # Legacy IDs (for compatibility with older datasets)
    "T1064": TechniqueInfo("T1064", "Scripting (Legacy)", "execution", AttackStage.PRE_OPERATIONAL,
        "Scripting - deprecated ID, use T1059", 2.5, True,
        ["script", "vbs", "js", "ps1"]),
}

# Set các technique IDs
FILELESS_TIDS_COMPREHENSIVE: Set[str] = set(TECHNIQUE_DATABASE.keys())


# ===========================
# STAGE-BASED GROUPING
# ===========================

def get_techniques_by_stage(stage: AttackStage) -> List[str]:
    """Lấy danh sách techniques theo stage"""
    return [tid for tid, info in TECHNIQUE_DATABASE.items() if info.stage == stage]


def get_techniques_by_tactic(tactic: str) -> List[str]:
    """Lấy danh sách techniques theo tactic"""
    return [tid for tid, info in TECHNIQUE_DATABASE.items() if info.tactic == tactic]


STAGE_TECHNIQUES: Dict[AttackStage, List[str]] = {
    AttackStage.INITIAL: get_techniques_by_stage(AttackStage.INITIAL),
    AttackStage.PRE_OPERATIONAL: get_techniques_by_stage(AttackStage.PRE_OPERATIONAL),
    AttackStage.OPERATIONAL: get_techniques_by_stage(AttackStage.OPERATIONAL),
    AttackStage.FINAL: get_techniques_by_stage(AttackStage.FINAL),
}


# ===========================
# WEIGHTED TECHNIQUES (cho feature extraction)
# ===========================

def get_technique_weight(tid: str) -> float:
    """Lấy trọng số của technique từ database"""
    if tid in TECHNIQUE_DATABASE:
        return TECHNIQUE_DATABASE[tid].weight
    return 1.0


# Top techniques cho one-hot encoding (most important for fileless)
ONE_HOT_TIDS_ENHANCED: List[str] = [
    "T1059.001",   # PowerShell - #1 for fileless
    "T1055",       # Process Injection
    "T1055.012",   # Process Hollowing
    "T1106",       # Native API
    "T1047",       # WMI
    "T1112",       # Modify Registry
    "T1027",       # Obfuscation
    "T1218.011",   # Rundll32
    "T1218.005",   # Mshta
    "T1140",       # Deobfuscate
    "T1003.001",   # LSASS Memory
    "T1547.001",   # Registry Run Keys
]


# ===========================
# HELPER FUNCTIONS
# ===========================

def get_technique_info(tid: str) -> Optional[TechniqueInfo]:
    """Lấy thông tin đầy đủ của technique"""
    return TECHNIQUE_DATABASE.get(tid)


def get_stage_for_technique(tid: str) -> Optional[AttackStage]:
    """Lấy stage của technique"""
    info = TECHNIQUE_DATABASE.get(tid)
    return info.stage if info else None


def get_stage_for_tactic(tactic: str) -> Optional[AttackStage]:
    """Lấy stage từ tactic name"""
    return TACTICS_TO_STAGE.get(tactic.lower().replace(" ", "-"))


def is_fileless_technique(tid: str) -> bool:
    """Kiểm tra xem technique có phải fileless không"""
    base_tid = tid.split('.')[0] if '.' in tid else tid
    if tid in TECHNIQUE_DATABASE:
        return TECHNIQUE_DATABASE[tid].is_fileless
    if base_tid in TECHNIQUE_DATABASE:
        return TECHNIQUE_DATABASE[base_tid].is_fileless
    return False


def one_hot_tid_enhanced(tid: str) -> List[int]:
    """One-hot encoding với enhanced TID list"""
    return [1 if tid == t else 0 for t in ONE_HOT_TIDS_ENHANCED]


def one_hot_stage(stage: AttackStage) -> List[int]:
    """One-hot encoding cho attack stage"""
    return [1 if stage == s else 0 for s in AttackStage]


# ===========================
# BEHAVIOR TO TECHNIQUE MAPPING
# ===========================

# Keywords/behaviors mapping to techniques (cho feature extraction)
BEHAVIOR_KEYWORDS: Dict[str, List[str]] = {
    "T1059.001": ["powershell", "pwsh", "-enc", "-encodedcommand", "invoke-expression", 
                  "iex", "downloadstring", "-nop", "-windowstyle hidden"],
    "T1055": ["virtualalloc", "writeprocessmemory", "createremotethread", "injection",
              "ntwritevirtualmemory", "page_execute_readwrite"],
    "T1055.012": ["hollowing", "ntunmapviewofsection", "zwunmapviewofsection"],
    "T1106": ["ntdll", "kernel32", "getprocaddress", "loadlibrary", "native api"],
    "T1047": ["wmi", "wmic", "win32_process", "create", "winmgmt"],
    "T1112": ["registry", "reg add", "reg set", "hklm", "hkcu", "currentversion\\run"],
    "T1027": ["base64", "frombase64string", "xor", "obfuscated", "encoded"],
    "T1218.011": ["rundll32", "javascript:", "shell32"],
    "T1218.005": ["mshta", "hta", "javascript:", "vbscript:"],
    "T1140": ["certutil", "-decode", "frombase64", "decrypt"],
    "T1003.001": ["lsass", "mimikatz", "sekurlsa", "procdump", "comsvcs.dll"],
    "T1547.001": ["run key", "runonce", "currentversion\\run", "startup"],
}


def detect_techniques_from_text(text: str) -> Dict[str, float]:
    """
    Phát hiện techniques từ text dựa trên keywords
    Returns: Dict[tid, confidence_score]
    """
    text_lower = text.lower()
    detected = {}
    
    for tid, keywords in BEHAVIOR_KEYWORDS.items():
        matches = sum(1 for kw in keywords if kw in text_lower)
        if matches > 0:
            confidence = min(matches / len(keywords), 1.0)
            detected[tid] = confidence * get_technique_weight(tid)
    
    return detected


def infer_stage_from_text(text: str) -> Tuple[AttackStage, float]:
    """
    Infer attack stage từ text content
    Returns: (stage, confidence)
    """
    detected = detect_techniques_from_text(text)
    if not detected:
        return AttackStage.INITIAL, 0.0
    
    # Count weighted votes for each stage
    stage_scores = {s: 0.0 for s in AttackStage}
    for tid, conf in detected.items():
        stage = get_stage_for_technique(tid)
        if stage is not None:
            stage_scores[stage] += conf
    
    # Return stage with highest score
    best_stage = max(stage_scores.keys(), key=lambda s: stage_scores[s])
    total = sum(stage_scores.values())
    confidence = stage_scores[best_stage] / total if total > 0 else 0.0
    
    return best_stage, confidence


# ===========================
# FEATURE EXPLAINER (từ bài báo Section 4.4)
# ===========================

class FeatureExplainer:
    """
    Rule-based Feature Explainer theo bài báo.
    Giải thích các key features trong memory dump.
    """
    
    EXPLANATION_RULES = {
        # Process paths
        r"c:\\windows\\syswow64\\(\w+\.exe)": 
            "{} running from suspicious 32-bit system path (SysWOW64)",
        r"c:\\windows\\system32\\(\w+\.exe)":
            "{} running from System32 directory",
        r"c:\\users\\.*\\appdata\\.*\\(\w+\.exe)":
            "{} running from user AppData directory (suspicious for system processes)",
        r"c:\\temp\\|c:\\windows\\temp\\":
            "Process executing from temporary directory (common malware behavior)",
            
        # VAD protection
        r"vad protection.*page_execute_readwrite":
            "Memory region with PAGE_EXECUTE_READWRITE protection - indicates code injection",
        r"vad.*rwx|page_execute_readwrite":
            "Suspicious memory protection allowing read-write-execute",
            
        # Registry
        r"hk(?:lm|cu)\\.*currentversion\\run":
            "Registry Run key modification for persistence",
        r"hkcu\\software\\.*\\.*":
            "User-specific registry key access - possible configuration storage",
        r"regread|regwrite|registry":
            "Registry access detected - checking for persistence or configuration",
            
        # Network
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)":
            "Network connection to {}:{} - potential C2 communication",
        r"http[s]?://":
            "HTTP/HTTPS URL detected - possible download or C2",
            
        # PowerShell
        r"-encodedcommand|-enc\s":
            "PowerShell encoded command execution - evasion technique",
        r"invoke-expression|iex\s":
            "PowerShell Invoke-Expression - dynamic code execution",
        r"downloadstring|webclient":
            "PowerShell download operation - stage 2 payload delivery",
        r"-windowstyle hidden":
            "Hidden window execution - evasion technique",
            
        # Script execution
        r"wscript\.shell|activexobject":
            "WScript.Shell ActiveX object - script-based execution",
        r"javascript.*eval|vbscript":
            "Script execution via eval or VBScript",
            
        # Process injection
        r"virtualalloc.*writeprocessmemory":
            "Memory allocation and writing - process injection pattern",
        r"createremotethread":
            "Remote thread creation - code injection into another process",
        r"process hollowing|ntunmapviewofsection":
            "Process hollowing technique - replacing legitimate process",
            
        # LOLBins
        r"mshta\.exe":
            "Mshta.exe execution - HTML Application host (LOLBin)",
        r"rundll32\.exe":
            "Rundll32.exe execution - DLL proxy (LOLBin)",
        r"regsvr32\.exe":
            "Regsvr32.exe execution - COM DLL registration (LOLBin)",
        r"certutil":
            "Certutil usage - possible download or decode operation",
            
        # Credential access
        r"lsass|mimikatz|sekurlsa":
            "LSASS memory access - credential dumping attempt",
        r"sam|security account manager":
            "SAM database access - local credential extraction",
            
        # Impact
        r"vssadmin.*delete|shadow.*delete":
            "Volume Shadow Copy deletion - ransomware indicator",
        r"encrypt|ransom":
            "Encryption activity - potential ransomware",
    }
    
    def __init__(self):
        self.compiled_rules = {
            re.compile(pattern, re.IGNORECASE): template 
            for pattern, template in self.EXPLANATION_RULES.items()
        }
    
    def explain(self, text: str) -> List[str]:
        """
        Generate explanations for features in text
        Returns: List of explanation strings
        """
        explanations = []
        
        for pattern, template in self.compiled_rules.items():
            match = pattern.search(text)
            if match:
                if match.groups():
                    explanation = template.format(*match.groups())
                else:
                    explanation = template
                explanations.append(explanation)
        
        return explanations
    
    def explain_with_techniques(self, text: str) -> List[Dict]:
        """
        Generate explanations with associated techniques
        Returns: List of dicts with explanation and techniques
        """
        explanations = self.explain(text)
        detected = detect_techniques_from_text(text)
        
        results = []
        for exp in explanations:
            result = {
                'explanation': exp,
                'techniques': []
            }
            # Find related techniques
            for tid, score in detected.items():
                info = get_technique_info(tid)
                if info:
                    result['techniques'].append({
                        'tid': tid,
                        'name': info.name,
                        'stage': STAGE_NAMES[info.stage],
                        'confidence': score
                    })
            results.append(result)
        
        return results


# ===========================
# VALIDATION
# ===========================

def validate_dataset_coverage(dataset_tids: Set[str]) -> dict:
    """
    Kiểm tra coverage của dataset so với MITRE techniques
    """
    covered = dataset_tids & FILELESS_TIDS_COMPREHENSIVE
    missing = FILELESS_TIDS_COMPREHENSIVE - dataset_tids
    extra = dataset_tids - FILELESS_TIDS_COMPREHENSIVE
    
    # Coverage by stage
    stage_coverage = {}
    for stage in AttackStage:
        stage_tids = set(STAGE_TECHNIQUES[stage])
        stage_covered = len(stage_tids & dataset_tids)
        stage_coverage[stage.name] = {
            'total': len(stage_tids),
            'covered': stage_covered,
            'percentage': stage_covered / len(stage_tids) * 100 if stage_tids else 0
        }
    
    return {
        'total_techniques': len(FILELESS_TIDS_COMPREHENSIVE),
        'covered_techniques': len(covered),
        'coverage_percentage': len(covered) / len(FILELESS_TIDS_COMPREHENSIVE) * 100,
        'missing_techniques': list(missing)[:20],  # First 20
        'extra_techniques': list(extra)[:10],
        'stage_coverage': stage_coverage,
    }


def get_dataset_statistics() -> dict:
    """Lấy thống kê về technique database"""
    return {
        'total_techniques': len(TECHNIQUE_DATABASE),
        'stage_distribution': {
            stage.name: len(STAGE_TECHNIQUES[stage]) 
            for stage in AttackStage
        },
        'tactic_distribution': {
            tactic: len(get_techniques_by_tactic(tactic))
            for tactic in set(TACTICS_TO_STAGE.keys())
        },
        'fileless_count': sum(1 for t in TECHNIQUE_DATABASE.values() if t.is_fileless),
        'one_hot_features': len(ONE_HOT_TIDS_ENHANCED),
    }


# ===========================
# EXPORT FOR OTHER MODULES
# ===========================

# Legacy compatibility
TECHNIQUE_WEIGHTS = {tid: info.weight for tid, info in TECHNIQUE_DATABASE.items()}

TECHNIQUE_CATEGORIES = {
    "execution": get_techniques_by_tactic("execution"),
    "persistence": get_techniques_by_tactic("persistence"),
    "privilege_escalation": get_techniques_by_tactic("privilege-escalation"),
    "defense_evasion": get_techniques_by_tactic("defense-evasion"),
    "credential_access": get_techniques_by_tactic("credential-access"),
    "discovery": get_techniques_by_tactic("discovery"),
    "lateral_movement": get_techniques_by_tactic("lateral-movement"),
    "collection": get_techniques_by_tactic("collection"),
    "command_control": get_techniques_by_tactic("command-and-control"),
    "exfiltration": get_techniques_by_tactic("exfiltration"),
    "impact": get_techniques_by_tactic("impact"),
}


# ===========================
# EXAMPLE USAGE
# ===========================

if __name__ == "__main__":
    print("="*60)
    print("FILELESS MALWARE DETECTION - TECHNIQUE DATABASE")
    print("Based on: Singh & Tripathy (2024)")
    print("="*60)
    
    stats = get_dataset_statistics()
    print(f"\nTotal techniques: {stats['total_techniques']}")
    print(f"Fileless techniques: {stats['fileless_count']}")
    print(f"One-hot features: {stats['one_hot_features']}")
    
    print(f"\nStage distribution:")
    for stage, count in stats['stage_distribution'].items():
        print(f"  {stage}: {count} techniques")
    
    print(f"\nOne-hot TIDs: {ONE_HOT_TIDS_ENHANCED}")
    
    # Test detection
    sample_text = """
    powershell.exe -encodedcommand VirtualAlloc WriteProcessMemory
    HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    """
    detected = detect_techniques_from_text(sample_text)
    stage, conf = infer_stage_from_text(sample_text)
    
    print(f"\nSample text detection:")
    print(f"  Detected techniques: {list(detected.keys())}")
    print(f"  Inferred stage: {STAGE_NAMES[stage]} (confidence: {conf:.2f})")
    
    # Test explainer
    print(f"\nFeature Explainer test:")
    explainer = FeatureExplainer()
    explanations = explainer.explain(sample_text)
    for exp in explanations:
        print(f"  - {exp}")
