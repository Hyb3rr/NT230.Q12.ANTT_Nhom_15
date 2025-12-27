"""
Convert Sysmon logs và TheZoo malware metadata thành TRAM-compatible dataset
"""

import json
import pandas as pd
import os
import re
from pathlib import Path
from typing import List, Dict, Tuple
from collections import defaultdict
import random

# Sysmon Event IDs và ý nghĩa
SYSMON_EVENTS = {
    1: ("Process Create", 1),           # Pre-operational
    2: ("File creation time changed", 1),
    3: ("Network connection", 2),       # Operational
    4: ("Sysmon service state changed", 1),
    5: ("Process terminated", 2),
    6: ("Driver loaded", 1),
    7: ("Image loaded", 1),             # DLL injection
    8: ("CreateRemoteThread", 2),       # Process injection
    9: ("RawAccessRead", 2),
    10: ("ProcessAccess", 2),           # Credential dumping
    11: ("FileCreate", 1),
    12: ("Registry key/value created/deleted", 1),
    13: ("Registry value set", 1),
    14: ("Registry key/value renamed", 1),
    15: ("FileCreateStreamHash", 1),
    17: ("PipeEvent (Pipe Created)", 2),
    18: ("PipeEvent (Pipe Connected)", 2),
    19: ("WmiEvent", 1),
    20: ("WmiEvent", 1),
    21: ("WmiEvent", 1),
    22: ("DNSEvent", 2),
    23: ("FileDelete", 2),              # Anti-forensics
    24: ("ClipboardChange", 2),
    25: ("ProcessTampering", 2),
    26: ("FileDeleteDetected", 2),
}

# Malware family to stage/technique mapping
MALWARE_FAMILIES = {
    "RAT": {"stage": 2, "techniques": ["T1219", "T1071", "T1059"]},
    "Ransomware": {"stage": 2, "techniques": ["T1486", "T1490", "T1059"]},
    "Backdoor": {"stage": 1, "techniques": ["T1547", "T1053", "T1059"]},
    "Trojan": {"stage": 1, "techniques": ["T1204", "T1059", "T1055"]},
    "Worm": {"stage": 1, "techniques": ["T1091", "T1570", "T1059"]},
    "Rootkit": {"stage": 1, "techniques": ["T1014", "T1055", "T1059"]},
    "Spyware": {"stage": 2, "techniques": ["T1056", "T1113", "T1005"]},
    "Botnet": {"stage": 2, "techniques": ["T1071", "T1105", "T1059"]},
    "Dropper": {"stage": 0, "techniques": ["T1204", "T1566", "T1059"]},
    "Downloader": {"stage": 1, "techniques": ["T1105", "T1059", "T1071"]},
    "Keylogger": {"stage": 2, "techniques": ["T1056", "T1005", "T1041"]},
    "Miner": {"stage": 2, "techniques": ["T1496", "T1059", "T1071"]},
    "APT": {"stage": 2, "techniques": ["T1003", "T1055", "T1071"]},
    "Exploit": {"stage": 0, "techniques": ["T1203", "T1190", "T1059"]},
}


def parse_sysmon_message(message: str) -> Dict[str, str]:
    """Parse Sysmon message into key-value pairs"""
    result = {}
    lines = message.replace('\r\n', '\n').split('\n')
    
    for line in lines:
        if ':' in line:
            key, _, value = line.partition(':')
            result[key.strip()] = value.strip()
    
    return result


def sysmon_to_sentence(event: Dict) -> Tuple[str, int]:
    """Convert Sysmon event to natural language sentence with stage label"""
    event_id = event.get('Id', 0)
    message = event.get('Message', '')
    parsed = parse_sysmon_message(message)
    
    event_name, default_stage = SYSMON_EVENTS.get(event_id, ("Unknown", 1))
    stage = default_stage
    
    # Build sentence based on event type
    sentences = []
    
    if event_id == 1:  # Process Create
        image = parsed.get('Image', 'unknown process')
        cmdline = parsed.get('CommandLine', '')
        parent = parsed.get('ParentImage', '')
        
        image_name = os.path.basename(image)
        parent_name = os.path.basename(parent) if parent else ''
        
        if 'powershell' in image.lower():
            sentences.append(f"PowerShell process was created to execute commands on the system.")
            if '-encoded' in cmdline.lower() or '-enc' in cmdline.lower():
                sentences.append(f"PowerShell executed with encoded command to evade detection.")
                stage = 1
            if '-noprofile' in cmdline.lower() or '-windowstyle hidden' in cmdline.lower():
                sentences.append(f"PowerShell launched with hidden window and no profile for stealth execution.")
                stage = 1
        elif 'cmd.exe' in image.lower():
            sentences.append(f"Windows command shell (cmd.exe) was spawned for command execution.")
            stage = 1
        elif 'wscript' in image.lower() or 'cscript' in image.lower():
            sentences.append(f"Windows Script Host executed a script file on the system.")
            stage = 1
        else:
            sentences.append(f"Process {image_name} was created on the system.")
        
        if parent_name and parent_name.lower() in ['winword.exe', 'excel.exe', 'outlook.exe']:
            sentences.append(f"Suspicious process spawned from Office application {parent_name}.")
            stage = 0  # Initial access - macro execution
            
    elif event_id == 3:  # Network Connection
        dest_ip = parsed.get('DestinationIp', '')
        dest_port = parsed.get('DestinationPort', '')
        image = parsed.get('Image', '')
        
        if dest_port in ['443', '80', '8080', '8443']:
            sentences.append(f"Process established network connection to {dest_ip}:{dest_port} using web protocols.")
        elif dest_port in ['53']:
            sentences.append(f"DNS query was made to external server, potential C2 over DNS.")
        else:
            sentences.append(f"Network connection established to {dest_ip} on port {dest_port}.")
        stage = 2
        
    elif event_id == 7:  # Image Load
        image = parsed.get('Image', '')
        loaded = parsed.get('ImageLoaded', '')
        loaded_name = os.path.basename(loaded) if loaded else ''
        
        if 'clr.dll' in loaded.lower() or 'mscoree.dll' in loaded.lower():
            sentences.append(f".NET runtime was loaded, indicating managed code execution.")
        elif 'amsi.dll' in loaded.lower():
            sentences.append(f"AMSI interface loaded for script scanning.")
        else:
            sentences.append(f"Module {loaded_name} was loaded into process memory.")
        stage = 1
        
    elif event_id == 8:  # CreateRemoteThread
        source = parsed.get('SourceImage', '')
        target = parsed.get('TargetImage', '')
        sentences.append(f"Remote thread was created in target process, indicating process injection.")
        stage = 2
        
    elif event_id == 10:  # ProcessAccess
        source = parsed.get('SourceImage', '')
        target = parsed.get('TargetImage', '')
        if 'lsass' in target.lower():
            sentences.append(f"Process accessed LSASS memory, potential credential dumping attempt.")
            stage = 2
        else:
            sentences.append(f"Process accessed another process memory space.")
            
    elif event_id == 11:  # FileCreate
        target = parsed.get('TargetFilename', '')
        image = parsed.get('Image', '')
        
        if '\\Temp\\' in target or '\\tmp\\' in target.lower():
            sentences.append(f"File was created in temporary directory by {os.path.basename(image)}.")
        elif '.ps1' in target.lower() or '.vbs' in target.lower() or '.bat' in target.lower():
            sentences.append(f"Script file was dropped to disk for later execution.")
            stage = 1
        elif '.exe' in target.lower() or '.dll' in target.lower():
            sentences.append(f"Executable file was written to disk.")
            stage = 1
        else:
            sentences.append(f"File was created on the system.")
            
    elif event_id in [12, 13, 14]:  # Registry
        target = parsed.get('TargetObject', '')
        if 'Run' in target or 'RunOnce' in target:
            sentences.append(f"Registry Run key was modified for persistence.")
            stage = 1
        elif 'Services' in target:
            sentences.append(f"Windows Services registry was modified.")
            stage = 1
        else:
            sentences.append(f"Registry modification was detected.")
            
    elif event_id == 22:  # DNS
        query = parsed.get('QueryName', '')
        sentences.append(f"DNS query was made for domain {query}.")
        stage = 2
        
    elif event_id in [23, 26]:  # File Delete
        target = parsed.get('TargetFilename', '')
        sentences.append(f"File was deleted, potential anti-forensics activity.")
        stage = 2
    
    else:
        sentences.append(f"Sysmon event {event_id} ({event_name}) was detected on the system.")
    
    return ' '.join(sentences), stage


def convert_sysmon_to_dataset(sysmon_path: str) -> pd.DataFrame:
    """Convert Sysmon JSON log to TRAM dataset format"""
    print(f"Loading Sysmon logs from {sysmon_path}...")
    
    with open(sysmon_path, 'r', encoding='utf-8') as f:
        events = json.load(f)
    
    print(f"Loaded {len(events)} events")
    
    rows = []
    for event in events:
        sentence, stage = sysmon_to_sentence(event)
        if sentence and len(sentence) > 20:  # Filter short/empty sentences
            rows.append({
                'sentence': sentence,
                'stage': stage,
                'source': 'sysmon',
                'event_id': event.get('Id', 0)
            })
    
    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset=['sentence'])
    
    print(f"Generated {len(df)} unique sentences from Sysmon logs")
    return df


def get_malware_type(name: str) -> str:
    """Infer malware type from folder name"""
    name_lower = name.lower()
    
    if 'rat' in name_lower or 'electro' in name_lower:
        return 'RAT'
    elif 'ransom' in name_lower or 'wannacry' in name_lower or 'petya' in name_lower:
        return 'Ransomware'
    elif 'backdoor' in name_lower or 'msil' in name_lower:
        return 'Backdoor'
    elif 'trojan' in name_lower or 'horse' in name_lower:
        return 'Trojan'
    elif 'worm' in name_lower or 'conficker' in name_lower:
        return 'Worm'
    elif 'rootkit' in name_lower:
        return 'Rootkit'
    elif 'spy' in name_lower or 'pegasus' in name_lower:
        return 'Spyware'
    elif 'bot' in name_lower or 'mirai' in name_lower:
        return 'Botnet'
    elif 'drop' in name_lower:
        return 'Dropper'
    elif 'download' in name_lower:
        return 'Downloader'
    elif 'keylog' in name_lower:
        return 'Keylogger'
    elif 'miner' in name_lower or 'coin' in name_lower:
        return 'Miner'
    elif 'apt' in name_lower or 'bear' in name_lower or 'duke' in name_lower:
        return 'APT'
    elif 'exploit' in name_lower or 'eternal' in name_lower:
        return 'Exploit'
    else:
        return 'Trojan'  # Default


def generate_thezoo_descriptions(malware_name: str, malware_type: str) -> List[Dict]:
    """Generate text descriptions for TheZoo malware based on known behavior"""
    
    family_info = MALWARE_FAMILIES.get(malware_type, MALWARE_FAMILIES['Trojan'])
    base_stage = family_info['stage']
    
    # Clean name for display
    display_name = malware_name.replace('.', ' ').replace('_', ' ')
    
    templates = {
        'RAT': [
            (f"The {display_name} remote access trojan establishes persistent backdoor access to compromised systems.", 1),
            (f"{display_name} RAT allows attackers to execute commands remotely on infected machines.", 2),
            (f"The {display_name} implant provides full remote control capabilities including file access and keylogging.", 2),
            (f"{display_name} communicates with C2 servers using encrypted channels for command retrieval.", 2),
        ],
        'Ransomware': [
            (f"The {display_name} ransomware encrypts files on the victim system demanding payment for decryption.", 2),
            (f"{display_name} deletes shadow copies to prevent system recovery after encryption.", 2),
            (f"The {display_name} payload spreads laterally through network shares encrypting accessible files.", 2),
            (f"{display_name} drops ransom notes in encrypted directories with payment instructions.", 2),
        ],
        'Backdoor': [
            (f"The {display_name} backdoor maintains persistent access to compromised systems.", 1),
            (f"{display_name} creates hidden communication channels for attacker access.", 1),
            (f"The {display_name} implant survives system reboots through registry modifications.", 1),
            (f"{display_name} provides covert access for follow-on exploitation activities.", 2),
        ],
        'Trojan': [
            (f"The {display_name} trojan disguises malicious functionality as legitimate software.", 1),
            (f"{display_name} downloads additional payloads after initial execution.", 1),
            (f"The {display_name} malware establishes persistence through scheduled tasks.", 1),
            (f"{display_name} collects system information and sends it to remote servers.", 2),
        ],
        'Worm': [
            (f"The {display_name} worm propagates automatically through network connections.", 1),
            (f"{display_name} exploits vulnerabilities to spread to adjacent systems.", 1),
            (f"The {display_name} malware replicates through removable media and network shares.", 1),
            (f"{display_name} scanning activity detected as it probes for vulnerable hosts.", 2),
        ],
        'Rootkit': [
            (f"The {display_name} rootkit hides malicious processes from system monitoring tools.", 1),
            (f"{display_name} modifies kernel structures to maintain stealth.", 1),
            (f"The {display_name} implant intercepts system calls to hide its presence.", 1),
            (f"{display_name} provides persistent hidden access below the operating system level.", 1),
        ],
        'Spyware': [
            (f"The {display_name} spyware captures screenshots and keystrokes from victim systems.", 2),
            (f"{display_name} exfiltrates sensitive documents and credentials to attacker servers.", 2),
            (f"The {display_name} implant monitors user activity and communications.", 2),
            (f"{display_name} harvests browser credentials and saved passwords.", 2),
        ],
        'Botnet': [
            (f"The {display_name} bot joins infected systems to a command and control network.", 2),
            (f"{display_name} receives commands from botnet operators for coordinated attacks.", 2),
            (f"The {display_name} malware participates in distributed denial of service attacks.", 2),
            (f"{display_name} can be updated remotely with new malicious capabilities.", 2),
        ],
        'Dropper': [
            (f"The {display_name} dropper delivers secondary payloads to compromised systems.", 0),
            (f"{display_name} unpacks and executes embedded malicious code.", 0),
            (f"The {display_name} sample downloads additional malware components from remote servers.", 1),
            (f"{display_name} provides initial access for follow-on exploitation.", 0),
        ],
        'Downloader': [
            (f"The {display_name} downloader retrieves malicious payloads from remote servers.", 1),
            (f"{display_name} fetches and executes secondary stage malware.", 1),
            (f"The {display_name} sample establishes connection to download additional tools.", 1),
            (f"{display_name} serves as initial loader for more sophisticated malware.", 1),
        ],
        'Keylogger': [
            (f"The {display_name} keylogger records all keyboard input on infected systems.", 2),
            (f"{display_name} captures credentials entered in browsers and applications.", 2),
            (f"The {display_name} implant logs keystrokes and periodically exfiltrates them.", 2),
            (f"{display_name} hooks keyboard input to steal sensitive information.", 2),
        ],
        'Miner': [
            (f"The {display_name} cryptominer consumes system resources for cryptocurrency mining.", 2),
            (f"{display_name} installs mining software that runs hidden from the user.", 2),
            (f"The {display_name} malware mines cryptocurrency using victim computing power.", 2),
            (f"{display_name} connects to mining pools to contribute hash power.", 2),
        ],
        'APT': [
            (f"The {display_name} APT implant provides advanced persistent access to targeted networks.", 2),
            (f"{display_name} conducts reconnaissance and lateral movement within compromised environments.", 2),
            (f"The {display_name} toolkit enables long-term espionage operations.", 2),
            (f"{display_name} exfiltrates sensitive data using covert communication channels.", 3),
        ],
        'Exploit': [
            (f"The {display_name} exploit targets vulnerabilities to gain initial system access.", 0),
            (f"{display_name} leverages software flaws to execute arbitrary code.", 0),
            (f"The {display_name} attack exploits unpatched systems for compromise.", 0),
            (f"{display_name} bypasses security controls through vulnerability exploitation.", 0),
        ],
    }
    
    selected_templates = templates.get(malware_type, templates['Trojan'])
    
    return [{'sentence': s, 'stage': st, 'malware_name': malware_name, 'malware_type': malware_type} 
            for s, st in selected_templates]


def convert_thezoo_to_dataset(thezoo_path: str) -> pd.DataFrame:
    """Convert TheZoo malware repository to TRAM dataset format"""
    print(f"Scanning TheZoo repository at {thezoo_path}...")
    
    binaries_path = Path(thezoo_path) / 'malware' / 'Binaries'
    if not binaries_path.exists():
        print(f"[WARNING] Binaries folder not found at {binaries_path}")
        return pd.DataFrame()
    
    malware_folders = [f for f in binaries_path.iterdir() if f.is_dir()]
    print(f"Found {len(malware_folders)} malware families")
    
    rows = []
    for folder in malware_folders:
        malware_name = folder.name
        malware_type = get_malware_type(malware_name)
        
        descriptions = generate_thezoo_descriptions(malware_name, malware_type)
        rows.extend(descriptions)
    
    df = pd.DataFrame(rows)
    df['source'] = 'thezoo'
    
    print(f"Generated {len(df)} sentences from TheZoo malware")
    return df


def main():
    print("="*70)
    print("CONVERT SYSMON + THEZOO TO TRAM DATASET")
    print("="*70)
    
    all_data = []
    
    # 1. Convert Sysmon logs
    sysmon_path = "dataset_URLhaus/sysmon.json"
    if Path(sysmon_path).exists():
        print("\n[1/3] Processing Sysmon logs...")
        df_sysmon = convert_sysmon_to_dataset(sysmon_path)
        all_data.append(df_sysmon)
        
        print(f"\n   Sysmon stage distribution:")
        dist = df_sysmon['stage'].value_counts().sort_index()
        for s, c in dist.items():
            print(f"      Stage {s}: {c}")
    
    # 2. Convert TheZoo
    thezoo_path = "dataset_theZoo/theZoo"
    if Path(thezoo_path).exists():
        print("\n[2/3] Processing TheZoo repository...")
        df_thezoo = convert_thezoo_to_dataset(thezoo_path)
        all_data.append(df_thezoo)
        
        print(f"\n   TheZoo stage distribution:")
        dist = df_thezoo['stage'].value_counts().sort_index()
        for s, c in dist.items():
            print(f"      Stage {s}: {c}")
    
    # 3. Combine and extract features
    if all_data:
        print("\n[3/3] Combining and extracting features...")
        df_combined = pd.concat(all_data, ignore_index=True)
        df_combined = df_combined.drop_duplicates(subset=['sentence'])
        
        print(f"\n   Combined dataset: {len(df_combined)} sentences")
        
        # Extract features
        try:
            from enhanced_features import build_bert_mlp_features
            
            features_list = []
            for idx, row in df_combined.iterrows():
                result = build_bert_mlp_features(row['sentence'])
                features_list.append(str(result['numeric_features']))
                
                if (idx + 1) % 200 == 0:
                    print(f"      Processed {idx + 1}/{len(df_combined)}...")
            
            df_combined['num_feats'] = features_list
            
        except ImportError as e:
            print(f"   [WARNING] Could not extract features: {e}")
            df_combined['num_feats'] = ''
        
        # Save
        output_file = "sysmon_thezoo_dataset.csv"
        df_combined[['sentence', 'num_feats', 'stage']].to_csv(output_file, index=False)
        print(f"\n   Saved to: {output_file}")
        
        # Summary
        print("\n" + "="*70)
        print("[SUCCESS] Dataset generation complete!")
        print("="*70)
        print(f"\nTotal samples: {len(df_combined)}")
        print(f"\nStage distribution:")
        dist = df_combined['stage'].value_counts().sort_index()
        for s, c in dist.items():
            pct = c / len(df_combined) * 100
            print(f"   Stage {s}: {c:4d} ({pct:5.1f}%)")
        
        print(f"\nSource distribution:")
        src_dist = df_combined['source'].value_counts()
        for src, c in src_dist.items():
            print(f"   {src}: {c}")
        
        print("\n" + "="*70)
        print("To merge with main dataset:")
        print("   python -c \"import pandas as pd; ...")
        print("="*70)
        
        return df_combined
    
    return None


if __name__ == "__main__":
    main()
