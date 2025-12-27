"""
Merge dataset mới 5K với dataset 15K từ TRAM (rebuild)
"""
import pandas as pd
import sys
from pathlib import Path
import subprocess

def rebuild_and_merge():
    """Rebuild 15K từ TRAM và merge với 5K mới"""
    print("="*70)
    print("MERGE DATASET 5K MỚI VÀO 15K CŨ (REBUILD)")
    print("="*70)

    # Step 1: Load 5K mới
    print("\n[1/5] Loading dataset mới (5K)...")
    if not Path('events_all.csv').exists():
        print("   ✗ File events_all.csv không tồn tại!")
        return None
        
    df_new = pd.read_csv('events_all.csv')
    print(f"   ✓ Loaded {len(df_new):,} samples")
    print(f"   Distribution: {dict(df_new['stage'].value_counts().sort_index())}")

    # Step 2: Rebuild 15K từ TRAM
    print("\n[2/5] Rebuilding dataset 15K từ TRAM sources...")
    print("   (Chạy build_large_dataset.py...)")
    
    result = subprocess.run([sys.executable, 'build_large_dataset.py'], 
                           capture_output=True, text=True)

    if result.returncode != 0:
        print(f"   ✗ Error building dataset:")
        print(result.stderr)
        return None

    # Check output file
    if not Path('events_15k_balanced.csv').exists():
        print("   ✗ File events_15k_balanced.csv không được tạo!")
        return None

    df_15k = pd.read_csv('events_15k_balanced.csv')
    print(f"   ✓ Rebuilt {len(df_15k):,} samples")
    print(f"   Distribution: {dict(df_15k['stage'].value_counts().sort_index())}")

    # Step 3: Merge và deduplicate (smart merge - keep 15K + unique from 5K)
    print("\n[3/5] Merging datasets (intelligent deduplication)...")
    print(f"   15K dataset: {len(df_15k):,} samples")
    print(f"   5K dataset: {len(df_new):,} samples")
    
    # Find unique sentences in 5K that are NOT in 15K
    df_new_unique = df_new[~df_new['sentence'].isin(df_15k['sentence'])]
    print(f"   Unique in 5K (not in 15K): {len(df_new_unique):,} samples")
    
    # Merge: 15K + unique from 5K
    df_merged = pd.concat([df_15k, df_new_unique], ignore_index=True)
    print(f"   ✓ Final merged dataset: {len(df_merged):,} samples")

    # Step 4: Distribution analysis
    print("\n[4/5] Final dataset statistics:")
    print(f"   Total samples: {len(df_merged):,}")

    dist = df_merged['stage'].value_counts().sort_index()
    target_dist = {0: 0.12, 1: 0.593, 2: 0.211, 3: 0.076}

    print("\n   Stage distribution:")
    for stage in sorted(dist.index):
        actual_pct = dist[stage]/len(df_merged)*100
        target_pct = target_dist[stage]*100
        diff = actual_pct - target_pct
        print(f"      Stage {stage}: {dist[stage]:>5} ({actual_pct:>5.1f}%) | Target: {target_pct:>5.1f}% | Diff: {diff:>+6.1f}%")

    # Step 5: Save
    print("\n[5/5] Saving merged dataset...")
    df_merged.to_csv('events_merged_20k.csv', index=False)
    print(f"   ✓ Saved to events_merged_20k.csv ({len(df_merged):,} samples)")

    # Backup old files
    print("\n[Backup] Moving old files...")
    if Path('events_all.csv').exists():
        if Path('backup_events_all_5k.csv').exists():
            Path('backup_events_all_5k.csv').unlink()
        Path('events_all.csv').rename('backup_events_all_5k.csv')
        print("   ✓ events_all.csv → backup_events_all_5k.csv")

    if Path('events_15k_balanced.csv').exists():
        if Path('backup_events_15k.csv').exists():
            Path('backup_events_15k.csv').unlink()
        Path('events_15k_balanced.csv').rename('backup_events_15k.csv')
        print("   ✓ events_15k_balanced.csv → backup_events_15k.csv")

    # Rename merged to events.csv for training
    if Path('events.csv').exists():
        Path('events.csv').unlink()
    Path('events_merged_20k.csv').rename('events.csv')
    print("   ✓ events_merged_20k.csv → events.csv (ready for training)")

    print("\n" + "="*70)
    print("✅ HOÀN TẤT!")
    print("="*70)
    print(f"\nFinal dataset: events.csv ({len(df_merged):,} samples)")
    print("\nSẵn sàng để train với lệnh:")
    print("   python train_fileless_detector.py")
    print("="*70)
    
    return df_merged
    print(f"Old: {len(df_old)} + New: {len(df_new)} = {len(df_merged)}")
    
    print("\n💡 Next steps:")
    print("   Fine-tune model with merged data:")
if __name__ == '__main__':
    rebuild_and_merge()
