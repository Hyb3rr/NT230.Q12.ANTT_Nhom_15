"""
Build Large Dataset (15K+ samples) từ Multiple TRAM Sources
Phân bố target: Initial 12%, Pre-op 59.3%, Operational 21.1%, Final 7.6%
"""
import json
import pandas as pd
import sys
from pathlib import Path
from collections import Counter
import random

# Import từ fileless_techniques
sys.path.insert(0, str(Path(__file__).parent))
from fileless_techniques import get_technique_info, AttackStage, TECHNIQUE_DATABASE
from enhanced_features import build_bert_mlp_features

# ======================== CONFIG ========================
TARGET_TOTAL = 15764  # Số samples trong paper
TARGET_DISTRIBUTION = {
    AttackStage.INITIAL: 0.12,         # 12%   = 1,892 samples
    AttackStage.PRE_OPERATIONAL: 0.593, # 59.3% = 9,348 samples
    AttackStage.OPERATIONAL: 0.211,     # 21.1% = 3,326 samples
    AttackStage.FINAL: 0.076            # 7.6%  = 1,198 samples
}

DATA_SOURCES = {
    'tram_training': 'tram/data/training/bootstrap-training-data.json',
    'tram_archive': 'tram/data/training/attack_may_2023_merged_bootstrap_data2.json',
    'tram_reports': 'tram/data/training/contrib/all_analyzed_reports.json',
    'tram_negative': 'tram/data/training/contrib/negative_data.json',
    'tram2_multi': 'tram/data/tram2-data/multi_label.json',
    'tram2_single': 'tram/data/tram2-data/single_label.json',
    'tram2_training_multi': 'tram/data/training/tram2_data/multi_label.json',
    'tram2_training_single': 'tram/data/training/tram2_data/single_label.json',
}

# ======================== HELPER FUNCTIONS ========================
def get_stage_from_technique(tid: str) -> int:
    """Map technique ID to stage (0/1/2/3)"""
    info = get_technique_info(tid)
    if info and hasattr(info, 'stage'):
        return int(info.stage)
    return -1  # Unknown


def extract_sentences_from_tram(data, source_name):
    """Extract (sentence, stage) từ TRAM JSON"""
    rows = []
    
    if isinstance(data, list):
        # Format 1: [{"text": "...", "label": "T1234"}] - single_label.json
        # Format 2: [{"sentence": "...", "labels": [...]}] - multi_label.json
        for item in data:
            if not isinstance(item, dict):
                continue
            
            # Lấy text từ nhiều field names
            text = item.get('text') or item.get('sentence', '')
            
            # Lấy techniques từ nhiều field names
            techniques = []
            if 'label' in item and item['label']:
                techniques = [item['label']]
            elif 'labels' in item and item['labels']:
                techniques = item['labels']
            elif 'techniques' in item and item['techniques']:
                techniques = item['techniques']
            
            if text and techniques:
                # Lấy stage từ technique đầu tiên
                tid = techniques[0] if isinstance(techniques, list) else techniques
                tid = str(tid).strip()
                
                if not tid or tid == 'None':
                    continue
                
                stage = get_stage_from_technique(tid)
                
                if stage >= 0:
                    rows.append({
                        'sentence': text.strip(),
                        'stage': stage,
                        'source': source_name,
                        'technique': tid
                    })
    
    elif isinstance(data, dict):
        # Format 3: {"report_id": {"sentence_id": {...}}}
        # Check if this is metadata dict (has 'name', 'text' keys)
        if 'name' in data and 'text' in data:
            # This is metadata, skip
            return rows
        
        for report_id, report_data in data.items():
            if isinstance(report_data, dict):
                for sentence_id, sentence_data in report_data.items():
                    if isinstance(sentence_data, dict):
                        text = sentence_data.get('text', '')
                        techniques = sentence_data.get('techniques', [])
                        
                        if text and techniques:
                            tid = techniques[0] if isinstance(techniques, list) else techniques
                            tid = str(tid).strip()
                            
                            if not tid or tid == 'None':
                                continue
                            
                            stage = get_stage_from_technique(tid)
                            
                            if stage >= 0:
                                rows.append({
                                    'sentence': text.strip(),
                                    'stage': stage,
                                    'source': source_name,
                                    'technique': tid
                                })
    
    return rows


def load_all_sources():
    """Load tất cả data sources"""
    all_rows = []
    stats = {}
    
    for source_name, filepath in DATA_SOURCES.items():
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            rows = extract_sentences_from_tram(data, source_name)
            all_rows.extend(rows)
            stats[source_name] = len(rows)
            print(f"[OK] {source_name:25s}: {len(rows):6,d} samples")
        
        except FileNotFoundError:
            print(f"[X] {source_name:25s}: FILE NOT FOUND")
        except Exception as e:
            print(f"[X] {source_name:25s}: ERROR - {e}")
    
    return all_rows, stats


def balance_by_stage(df, target_total=TARGET_TOTAL, target_dist=TARGET_DISTRIBUTION):
    """Balance dataset theo target distribution"""
    
    # Tính target counts
    target_counts = {
        stage: int(target_total * prob)
        for stage, prob in target_dist.items()
    }
    
    print("\n[TARGET] Distribution:")
    for stage, count in target_counts.items():
        print(f"   Stage {stage} ({stage.name:15s}): {count:5,d} samples ({target_dist[stage]*100:.1f}%)")
    
    # Current distribution
    current_counts = df['stage'].value_counts().to_dict()
    print("\n[CURRENT] Distribution:")
    total_current = len(df)
    for stage in AttackStage:
        count = current_counts.get(int(stage), 0)
        pct = (count / total_current * 100) if total_current > 0 else 0
        print(f"   Stage {int(stage)} ({stage.name:15s}): {count:5,d} samples ({pct:.1f}%)")
    
    # Balance strategy
    balanced_parts = []
    
    for stage, target_count in target_counts.items():
        stage_df = df[df['stage'] == int(stage)]
        current_count = len(stage_df)
        
        if current_count == 0:
            print(f"\n[WARNING] Stage {int(stage)} ({stage.name}): NO DATA AVAILABLE!")
            continue
        
        if current_count >= target_count:
            # Downsample
            sampled = stage_df.sample(n=target_count, random_state=42)
            print(f"   Stage {int(stage)} ({stage.name:15s}): Downsample {current_count:5,d} -> {target_count:5,d}")
        else:
            # Upsample with replacement
            sampled = stage_df.sample(n=target_count, replace=True, random_state=42)
            print(f"   Stage {int(stage)} ({stage.name:15s}): Upsample   {current_count:5,d} -> {target_count:5,d} (with replacement)")
        
        balanced_parts.append(sampled)
    
    # Combine và shuffle
    balanced_df = pd.concat(balanced_parts, ignore_index=True)
    balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return balanced_df


def print_distribution_stats(df, title="Distribution"):
    """In statistics về distribution"""
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")
    
    total = len(df)
    print(f"Total samples: {total:,d}\n")
    
    stage_counts = df['stage'].value_counts().sort_index()
    
    print(f"{'Stage':<6} {'Name':<17} {'Count':>8} {'Percent':>8} {'Target':>8}")
    print("-" * 60)
    
    for stage_int in sorted(stage_counts.index):
        stage = AttackStage(stage_int)
        count = stage_counts[stage_int]
        pct = (count / total * 100)
        target_pct = TARGET_DISTRIBUTION[stage] * 100
        
        print(f"{stage_int:<6} {stage.name:<17} {count:>8,d} {pct:>7.1f}% {target_pct:>7.1f}%")
    
    print("=" * 60)


def main():
    print("="*70)
    print(" BUILD LARGE DATASET (15K+ Samples) - Paper Distribution")
    print("="*70)
    
    # Step 1: Load all sources
    print("\n[1] Loading data from all sources...")
    all_rows, stats = load_all_sources()
    
    if not all_rows:
        print("\n❌ ERROR: No data loaded!")
        return
    
    print(f"\n[OK] Total raw samples: {len(all_rows):,d}")
    
    # Step 2: Create DataFrame
    df = pd.DataFrame(all_rows)
    
    # Dedup
    df_before_dedup = len(df)
    df = df.drop_duplicates(subset='sentence', keep='first')
    print(f"[OK] After deduplication: {len(df):,d} samples (removed {df_before_dedup - len(df):,d} duplicates)")
    
    # Step 3: Balance
    print("\n[2] Balancing to target distribution...")
    df_balanced = balance_by_stage(df, TARGET_TOTAL, TARGET_DISTRIBUTION)
    
    # Step 4: Stats
    print_distribution_stats(df_balanced, "FINAL BALANCED DATASET")
    
    # Step 5: Extract numeric features
    print("\n[3] Extracting numeric features (this may take a few minutes)...")
    num_feats_list = []
    for idx, row in df_balanced.iterrows():
        if idx % 1000 == 0:
            print(f"   Processed {idx:,}/{len(df_balanced):,} samples...")
        result = build_bert_mlp_features(row['sentence'])
        num_feats_list.append(json.dumps(result['numeric_features']))
    
    df_balanced['num_feats'] = num_feats_list
    print(f"[OK] Feature extraction complete!")
    
    # Step 6: Save
    output_file = 'events_15k_balanced.csv'
    output_main = 'events.csv'  # Also save as main dataset
    df_balanced[['sentence', 'num_feats', 'stage']].to_csv(output_file, index=False, encoding='utf-8')
    df_balanced[['sentence', 'num_feats', 'stage']].to_csv(output_main, index=False, encoding='utf-8')
    
    print(f"\n[SUCCESS] Dataset saved to: {output_file}")
    print(f"   Total samples: {len(df_balanced):,d}")
    
    # Source breakdown
    print("\n[SOURCE] Breakdown:")
    source_counts = df_balanced['source'].value_counts()
    for source, count in source_counts.items():
        pct = (count / len(df_balanced) * 100)
        print(f"   {source:25s}: {count:6,d} ({pct:5.1f}%)")
    
    print("\n" + "="*70)
    print("[SUCCESS] DONE! Ready to train with:")
    print(f"   python train_fileless_detector.py --data {output_file}")
    print("="*70)


if __name__ == '__main__':
    main()
