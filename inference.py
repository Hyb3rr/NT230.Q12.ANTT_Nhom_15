"""
Inference Engine for Fileless Malware Detection
Implements secure prediction pipeline
"""
import logging
import math
import re
from typing import Dict, List, Optional, Tuple

import torch
import numpy as np

logger = logging.getLogger(__name__)

# Attack stage mapping (based on paper Table 1)
STAGE_NAMES = {
    0: "Initial",           # Initial Access, Reconnaissance
    1: "Pre-operational",   # Execution, Persistence, Privilege Escalation
    2: "Operational",       # Defense Evasion, Credential Access, Discovery, Lateral Movement
    3: "Final"              # Collection, C2, Exfiltration, Impact
}

# MITRE ATT&CK tactics by stage
STAGE_TACTICS = {
    0: ["Reconnaissance", "Initial Access"],
    1: ["Execution", "Persistence", "Privilege Escalation"],
    2: ["Defense Evasion", "Credential Access", "Discovery", "Lateral Movement"],
    3: ["Collection", "Command and Control", "Exfiltration", "Impact"]
}

# Common fileless techniques by stage
FILELESS_TECHNIQUES = {
    0: ["T1566.001", "T1566.002", "T1190"],  # Phishing, Exploit
    1: ["T1059.001", "T1112", "T1053.005", "T1055"],  # PowerShell, Registry, Scheduled Task, Injection
    2: ["T1027", "T1140", "T1003", "T1057", "T1021.006"],  # Obfuscation, Credential Dumping, Discovery
    3: ["T1005", "T1071.001", "T1041", "T1486"]  # Collection, C2, Exfiltration, Impact
}


class FilelessDetector:
    """
    Fileless malware detection engine
    
    Performs inference using trained BERT-MLP model
    """
    
    # Security: Input size limits
    MAX_TEXT_LENGTH = 10000  # 10KB max
    MAX_NUMERIC_FEATURES = 100
    MIN_CONFIDENCE_THRESHOLD = 0.5
    
    def __init__(self, model_loader):
        """
        Initialize detector
        
        Args:
            model_loader: ModelLoader instance with loaded model
        """
        self.model_loader = model_loader
        self.model = model_loader.get_model()
        self.tokenizer = model_loader.get_tokenizer()
        self.config = model_loader.get_config()
        self.device = model_loader.device
        self.max_length = model_loader.get_max_length()
        self.num_feat_dim = model_loader.get_num_feat_dim()
        
        logger.info("Fileless detector initialized")
    
    def _validate_input(self, text: str, numeric_features: Optional[List[float]]):
        """
        Validate input with security checks
        
        Security:
        - Size limits to prevent DoS
        - Type validation
        - Sanitization
        """
        # Check text
        if not isinstance(text, str):
            raise ValueError("Text must be a string")
        
        if len(text) == 0:
            raise ValueError("Text cannot be empty")
        
        if len(text) > self.MAX_TEXT_LENGTH:
            raise ValueError(f"Text exceeds maximum length ({self.MAX_TEXT_LENGTH} chars)")
        
        # Check numeric features
        if numeric_features is not None:
            if not isinstance(numeric_features, (list, tuple)):
                raise ValueError("Numeric features must be a list or tuple")
            
            if len(numeric_features) > self.MAX_NUMERIC_FEATURES:
                raise ValueError(f"Too many numeric features (max {self.MAX_NUMERIC_FEATURES})")
            
            # Validate all are numeric
            for i, feat in enumerate(numeric_features):
                if not isinstance(feat, (int, float)) or math.isnan(feat) or math.isinf(feat):
                    raise ValueError(f"Invalid numeric feature at index {i}")
    
    def _extract_default_features(self, text: str) -> List[float]:
        """
        Extract default numeric features from text
        
        Features (based on paper):
        1. Text length
        2. Character entropy
        3. Has base64-like strings (indicator of encoded payloads)
        4. Token count
        5. Uppercase ratio (obfuscation indicator)
        """
        # Length
        length = len(text)
        
        # Entropy
        entropy = self._calculate_entropy(text)
        
        # Base64 detection (common in fileless malware)
        has_base64 = 1.0 if self._detect_base64(text) else 0.0
        
        # Token count
        tokens = text.split()
        token_count = len(tokens)
        
        # Uppercase ratio (obfuscation indicator)
        if length > 0:
            upper_ratio = sum(1 for c in text if c.isupper()) / length
        else:
            upper_ratio = 0.0
        
        return [length, entropy, has_base64, token_count, upper_ratio]
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        # Character frequency
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        total = len(text)
        entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
        
        return entropy
    
    def _detect_base64(self, text: str) -> bool:
        """
        Detect base64-encoded strings (common in fileless malware)
        
        Fileless malware often uses base64 to encode:
        - PowerShell commands
        - Shellcode
        - Configuration data
        """
        # Look for base64-like strings (16+ chars, alphanumeric + +/=)
        tokens = text.split()
        for token in tokens:
            if len(token) >= 16:
                # Check if mostly base64 characters
                base64_chars = sum(1 for c in token if c.isalnum() or c in '+/=')
                if base64_chars / len(token) > 0.9:
                    return True
        return False
    
    def _pad_features(self, features: List[float], target_dim: Optional[int] = None) -> List[float]:
        """Pad or trim features to target dimension"""
        target_dim = target_dim or self.num_feat_dim
        features = list(features)
        
        if len(features) < target_dim:
            # Pad with zeros
            features += [0.0] * (target_dim - len(features))
        elif len(features) > target_dim:
            # Trim
            features = features[:target_dim]
        
        return features
    
    @torch.no_grad()  # Security: No gradient computation
    def detect(
        self,
        text: str,
        numeric_features: Optional[List[float]] = None,
        threshold: float = 0.5
    ) -> Dict:
        """
        Detect fileless malware and identify attack stage
        
        Args:
            text: Memory forensics artifacts, process behavior description
            numeric_features: Optional numeric features (auto-extracted if not provided)
            threshold: Confidence threshold (default: 0.5)
        
        Returns:
            Dictionary with:
            - verdict: "malicious" or "benign"
            - confidence: Confidence score [0, 1]
            - stage: Predicted stage ID [0-3]
            - stage_name: Human-readable stage name
            - probabilities: Probability distribution over stages
            - tactics: MITRE ATT&CK tactics for this stage
            - techniques: Common techniques for this stage
        
        Security:
        - Input validation and sanitization
        - No gradient computation
        - No raw model internals exposed
        """
        # Security: Validate inputs
        self._validate_input(text, numeric_features)
        
        # Validate threshold
        if not (0.0 <= threshold <= 1.0):
            threshold = self.MIN_CONFIDENCE_THRESHOLD
        
        # Extract numeric features if not provided
        if numeric_features is None:
            numeric_features = self._extract_default_features(text)
            logger.debug("Auto-extracted numeric features")
        
        # Pad features to expected dimension
        numeric_features = self._pad_features(numeric_features, target_dim=self.num_feat_dim)
        
        # Tokenize text
        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            truncation=True,
            padding='max_length',
            return_tensors='pt'
        )
        
        # Move to device
        input_ids = encoding['input_ids'].to(self.device)
        attention_mask = encoding['attention_mask'].to(self.device)
        num_feats_tensor = torch.tensor([numeric_features], dtype=torch.float).to(self.device)
        
        # Model inference
        self.model.eval()  # Ensure eval mode
        with torch.no_grad():
            logits = self.model(input_ids, attention_mask, num_feats_tensor)
            probabilities = torch.softmax(logits, dim=-1)
        
        # Get predictions
        probs = probabilities[0].cpu().numpy()
        predicted_stage = int(np.argmax(probs))
        confidence = float(probs[predicted_stage])
        
        # Determine verdict
        verdict = "malicious" if confidence >= threshold else "benign"
        
        # Get stage information
        stage_name = STAGE_NAMES[predicted_stage]
        tactics = STAGE_TACTICS[predicted_stage]
        techniques = FILELESS_TECHNIQUES[predicted_stage]
        
        # Build response
        result = {
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "stage": predicted_stage,
            "stage_name": stage_name,
            "probabilities": {
                STAGE_NAMES[i]: round(float(prob), 4)
                for i, prob in enumerate(probs)
            },
            "tactics": tactics,
            "common_techniques": techniques,
            "threshold": threshold
        }
        
        # Add warning for low confidence
        if confidence < 0.7:
            result["warning"] = "Low confidence detection - manual review recommended"
        
        # Add stage-specific recommendations
        result["recommendation"] = self._get_recommendation(predicted_stage, confidence)
        
        logger.info(f"Detection: {verdict} (stage: {stage_name}, confidence: {confidence:.2%})")
        
        return result
    
    def _get_recommendation(self, stage: int, confidence: float) -> str:
        """Get security recommendation based on stage"""
        if confidence < 0.5:
            return "Insufficient evidence - continue monitoring"
        
        recommendations = {
            0: "Potential initial access detected. Review network logs and email gateway for phishing attempts.",
            1: "Pre-operational stage detected. Check for unauthorized persistence mechanisms, scheduled tasks, and registry modifications.",
            2: "Operational stage detected. Malware is actively evading defenses. Isolate affected system and conduct memory forensics.",
            3: "Final stage detected. Data exfiltration likely in progress. Immediately isolate system and preserve forensic evidence."
        }
        
        return recommendations.get(stage, "Unknown stage - conduct full investigation")
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict]:
        """
        Get information about MITRE ATT&CK technique
        
        Args:
            technique_id: MITRE technique ID (e.g., "T1059.001")
        
        Returns:
            Dictionary with technique details or None if not found
        """
        # Technique database (subset of common fileless techniques)
        TECHNIQUE_DB = {
            "T1566.001": {
                "name": "Phishing: Spearphishing Attachment",
                "tactic": "Initial Access",
                "description": "Adversaries send spearphishing emails with malicious attachments",
                "detection": "Monitor email attachments, execution of office macros"
            },
            "T1059.001": {
                "name": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "description": "Adversaries abuse PowerShell to execute malicious commands",
                "detection": "Monitor PowerShell execution, script block logging, encoded commands"
            },
            "T1112": {
                "name": "Modify Registry",
                "tactic": "Defense Evasion",
                "description": "Adversaries modify Windows Registry for persistence",
                "detection": "Monitor registry key modifications, especially Run keys"
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "Defense Evasion / Privilege Escalation",
                "description": "Adversaries inject code into legitimate processes",
                "detection": "Monitor for suspicious cross-process activity, memory protection changes"
            },
            "T1003": {
                "name": "OS Credential Dumping",
                "tactic": "Credential Access",
                "description": "Adversaries dump credentials from memory or SAM database",
                "detection": "Monitor LSASS access, suspicious process memory reads"
            },
            "T1041": {
                "name": "Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "description": "Adversaries exfiltrate data over existing C2 channel",
                "detection": "Monitor for unusual data transfers over C2 connections"
            }
        }
        
        return TECHNIQUE_DB.get(technique_id)
    
    def batch_detect(
        self,
        texts: List[str],
        numeric_features_list: Optional[List[List[float]]] = None,
        threshold: float = 0.5
    ) -> List[Dict]:
        """
        Batch detection for multiple samples
        
        Security: Limited to prevent resource exhaustion
        """
        MAX_BATCH_SIZE = 32
        
        if len(texts) > MAX_BATCH_SIZE:
            raise ValueError(f"Batch size exceeds maximum ({MAX_BATCH_SIZE})")
        
        results = []
        for i, text in enumerate(texts):
            num_feats = numeric_features_list[i] if numeric_features_list else None
            result = self.detect(text, num_feats, threshold)
            results.append(result)
        
        return results
