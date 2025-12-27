"""
Prediction module for Fileless Malware Detector
Based on: "Unveiling the veiled: An early stage detection of fileless malware"
Singh & Tripathy (2024) - IIT Patna

Supports 4-stage classification:
- Stage 0: Initial (Initial Access)
- Stage 1: Pre-operational (Execution, Persistence, Privilege Escalation)
- Stage 2: Operational (Defense Evasion, Credential Access, Discovery, Lateral Movement)
- Stage 3: Final (Collection, C2, Exfiltration, Impact)
"""
import argparse
import json
import os
import math
import torch
from typing import Dict, List, Tuple, Optional
from transformers import AutoTokenizer, AutoModel

from train_fileless_detector import BertFusion, TrainConfig

# Try to import stage-related modules
try:
    from fileless_techniques import (
        AttackStage, STAGE_NAMES, detect_techniques_from_text,
        infer_stage_from_text, FeatureExplainer, get_technique_info
    )
    from enhanced_features import build_bert_mlp_features
    STAGE_AWARE = True
except ImportError:
    STAGE_AWARE = False
    STAGE_NAMES = {0: "Initial", 1: "Pre-operational", 2: "Operational", 3: "Final"}


def char_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def default_num_feats(text: str):
    tokens = text.split()
    upper_ratio = sum(1 for c in text if c.isupper()) / max(1, len(text))
    has_b64 = 1 if any(len(t) >= 16 and all(c.isalnum() or c in "+/=" for c in t) for t in tokens) else 0
    return [len(text), char_entropy(text), has_b64, len(tokens), upper_ratio]


def load_config(path="fileless_detector_cfg.json"):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def pad_or_trim_feats(feats, dim):
    feats = list(feats)
    if len(feats) < dim:
        feats += [0.0] * (dim - len(feats))
    elif len(feats) > dim:
        feats = feats[:dim]
    return feats


def predict(text: str, num_feats, cfg: TrainConfig, num_feat_dim: int):
    """
    Predict attack stage for given text
    Returns: (predicted_stage, probabilities, explanations)
    """
    # Auto-detect device - use CUDA only if available
    if torch.cuda.is_available():
        device = cfg.device
    else:
        device = "cpu"
    
    tok = AutoTokenizer.from_pretrained(cfg.model_name)
    model = BertFusion(
        cfg.model_name, 
        num_feat_dim, 
        cfg.num_labels,
        dropout=getattr(cfg, 'dropout', 0.3),
        freeze_bert=False  # No need to freeze during inference
    ).to(device)
    
    state_path = "fileless_detector.pt"
    assert os.path.exists(state_path), "missing fileless_detector.pt"
    model.load_state_dict(torch.load(state_path, map_location=device))
    model.eval()

    enc = tok(
        text,
        max_length=cfg.max_len,
        truncation=True,
        padding="max_length",
        return_tensors="pt",
    )
    num_feats_tensor = torch.tensor([num_feats], dtype=torch.float)
    enc = {k: v.to(device) for k, v in enc.items()}
    num_feats_tensor = num_feats_tensor.to(device)
    
    with torch.no_grad():
        logits = model(**enc, num_feats=num_feats_tensor)
        probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
        pred = int(probs.argmax())
    
    # Get explanations if available
    explanations = []
    detected_techniques = {}
    if STAGE_AWARE:
        explainer = FeatureExplainer()
        explanations = explainer.explain(text)
        detected_techniques = detect_techniques_from_text(text)
    
    return pred, probs.tolist(), explanations, detected_techniques


def predict_with_analysis(text: str, require_model: bool = True) -> Dict:
    """
    Full prediction with detailed analysis (matching paper output)
    If require_model=False, will use rule-based analysis when model is missing
    """
    cfg_data = load_config()
    if cfg_data:
        cfg = TrainConfig(**cfg_data)
    else:
        cfg = TrainConfig()
    
    model_exists = os.path.exists("fileless_detector.pt")
    
    # Get features
    if STAGE_AWARE:
        feature_result = build_bert_mlp_features(text, "")
        feats = feature_result['numeric_features']
    else:
        feats = default_num_feats(text)
    
    # Determine feature dimension
    dim = None
    if os.path.exists("events.csv"):
        import pandas as pd
        df = pd.read_csv("events.csv")
        dim = len(json.loads(df.iloc[0]["num_feats"]))
    else:
        dim = len(feats)
    
    feats = pad_or_trim_feats(feats, dim)
    
    # Use model or fallback to rule-based
    if model_exists:
        pred, probs, explanations, techniques = predict(text, feats, cfg, dim)
    else:
        # Rule-based analysis when no model is available
        if STAGE_AWARE:
            techniques = detect_techniques_from_text(text)
            stage_result = infer_stage_from_text(text)
            pred = int(stage_result[0])  # Extract stage from tuple (stage, confidence)
            rule_confidence = stage_result[1]
            explainer = FeatureExplainer()
            explanations = explainer.explain(text)
        else:
            techniques = {}
            pred = 0
            rule_confidence = 0.5
            explanations = []
        
        # Create simulated probabilities based on rule-based prediction
        probs = [0.1, 0.1, 0.1, 0.1]
        probs[pred] = max(0.4, rule_confidence)
    
    # Build detailed response
    result = {
        'predicted_stage': pred,
        'stage_name': STAGE_NAMES.get(pred, f"Stage {pred}"),
        'probabilities': {
            STAGE_NAMES.get(i, f"Stage {i}"): float(p) 
            for i, p in enumerate(probs)
        },
        'confidence': float(max(probs)),
        'is_early_detection': pred in [0, 1],  # Initial or Pre-operational
        'explanations': explanations[:5],  # Top 5 explanations
        'detected_techniques': [
            {
                'tid': tid,
                'name': get_technique_info(tid).name if STAGE_AWARE and get_technique_info(tid) else tid,
                'score': score
            }
            for tid, score in sorted(techniques.items(), key=lambda x: -x[1])[:5]
        ] if techniques else [],
        'model_used': model_exists,
    }
    
    return result


def print_analysis_report(result: Dict):
    """Print formatted analysis report"""
    print("="*60)
    print("FILELESS MALWARE DETECTION ANALYSIS")
    print("="*60)
    
    stage_colors = {
        0: "🟢",  # Initial - green (least severe)
        1: "🟡",  # Pre-operational - yellow  
        2: "🟠",  # Operational - orange
        3: "🔴",  # Final - red (most severe)
    }
    
    stage_num = result['predicted_stage']
    emoji = stage_colors.get(stage_num, "⚪")
    
    print(f"\n{emoji} Predicted Stage: {result['stage_name']}")
    print(f"   Confidence: {result['confidence']:.1%}")
    
    if result['is_early_detection']:
        print(f"   ✅ EARLY DETECTION - Attack can be prevented!")
    else:
        print(f"   ⚠️ LATE DETECTION - Damage may have occurred")
    
    print(f"\nStage Probabilities:")
    for stage, prob in result['probabilities'].items():
        bar_len = int(prob * 30)
        bar = "█" * bar_len + "░" * (30 - bar_len)
        print(f"   {stage:<20} [{bar}] {prob:.1%}")
    
    if result['detected_techniques']:
        print(f"\nDetected MITRE ATT&CK Techniques:")
        for tech in result['detected_techniques']:
            print(f"   • {tech['tid']}: {tech['name']} (score: {tech['score']:.2f})")
    
    if result['explanations']:
        print(f"\nKey Findings:")
        for i, exp in enumerate(result['explanations'], 1):
            print(f"   {i}. {exp}")
    
    print("\n" + "="*60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Predict fileless malware attack stage")
    parser.add_argument("text", nargs='?', help="log or command string to analyze")
    parser.add_argument("--num_feats", help="JSON list of numeric features", default=None)
    parser.add_argument("--num_feat_dim", type=int, default=None, help="override numeric feature dimension")
    parser.add_argument("--detailed", action="store_true", help="show detailed analysis report")
    parser.add_argument("--demo", action="store_true", help="run demo with sample text")
    args = parser.parse_args()

    # Demo mode
    if args.demo or args.text is None:
        demo_text = """
        Process: powershell.exe (PID: 5432)
        Parent: winword.exe (abnormal parent-child relationship)
        Command: powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA
        Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
        Network: src ip 192.168.1.100:52341 dst ip 203.45.67.89:443
        VAD protection: PAGE_EXECUTE_READWRITE
        Invoke-WebRequest downloading payload from external server
        VirtualAlloc WriteProcessMemory CreateRemoteThread
        """
        print("Running demo with sample malicious activity...")
        result = predict_with_analysis(demo_text)
        print_analysis_report(result)
        print("\nJSON Output:")
        print(json.dumps(result, indent=2, default=str))
    else:
        # Normal prediction
        cfg_data = load_config()
        if cfg_data:
            cfg = TrainConfig(**cfg_data)
        else:
            cfg = TrainConfig()

        if args.num_feats:
            feats = json.loads(args.num_feats)
        else:
            feats = default_num_feats(args.text)

        dim = args.num_feat_dim
        if dim is None:
            if os.path.exists("events.csv"):
                import pandas as pd
                df = pd.read_csv("events.csv")
                dim = len(json.loads(df.iloc[0]["num_feats"]))
            else:
                dim = len(feats)
        
        feats = pad_or_trim_feats(feats, dim)

        if args.detailed:
            result = predict_with_analysis(args.text)
            print_analysis_report(result)
        else:
            pred, probs, _, _ = predict(args.text, feats, cfg, dim)
            print(json.dumps({
                "predicted_stage": pred,
                "stage_name": STAGE_NAMES.get(pred, f"Stage {pred}"),
                "probabilities": probs,
                "features": feats
            }, indent=2))
