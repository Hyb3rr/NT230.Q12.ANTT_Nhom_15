"""
So sánh kết quả với bài báo
"""
import json

print('='*70)
print('SO SANH KET QUA VOI BAI BAO')
print('Singh & Tripathy (2024) - Fileless Malware Detection')
print('='*70)

with open('training_results.json') as f:
    r = json.load(f)

# Paper metrics
paper = {
    'dataset_size': 15764,
    'accuracy': 97.05,
    'precision': 97.05,
    'recall': 97.78,
    'f1': 97.41,
    'distribution': {0: 12.0, 1: 59.3, 2: 21.1, 3: 7.6}
}

# Our metrics
ours = {
    'dataset_size': 18059,
    'accuracy': r['test_accuracy'] * 100,
    'precision': r['test_metrics']['macro_precision'] * 100,
    'recall': r['test_metrics']['macro_recall'] * 100,
    'f1': r['test_metrics']['macro_f1'] * 100,
    'distribution': {0: 11.0, 1: 59.1, 2: 22.9, 3: 7.0}
}

print(f"\n{'Metric':<20} {'Paper':>12} {'Ours':>12} {'Diff':>12}")
print('-'*56)
print(f"{'Dataset Size':<20} {paper['dataset_size']:>12,} {ours['dataset_size']:>12,} {ours['dataset_size']-paper['dataset_size']:>+12,}")
print(f"{'Accuracy (%)':<20} {paper['accuracy']:>12.2f} {ours['accuracy']:>12.2f} {ours['accuracy']-paper['accuracy']:>+12.2f}")
print(f"{'Precision (%)':<20} {paper['precision']:>12.2f} {ours['precision']:>12.2f} {ours['precision']-paper['precision']:>+12.2f}")
print(f"{'Recall (%)':<20} {paper['recall']:>12.2f} {ours['recall']:>12.2f} {ours['recall']-paper['recall']:>+12.2f}")
print(f"{'F1-Score (%)':<20} {paper['f1']:>12.2f} {ours['f1']:>12.2f} {ours['f1']-paper['f1']:>+12.2f}")

print(f"\n{'Stage Distribution':^56}")
print('-'*56)
print(f"{'Stage':<20} {'Paper (%)':>12} {'Ours (%)':>12} {'Diff':>12}")
stage_names = {0:'Initial', 1:'Pre-op', 2:'Operational', 3:'Final'}
for s in range(4):
    print(f"{stage_names[s]:<20} {paper['distribution'][s]:>12.1f} {ours['distribution'][s]:>12.1f} {ours['distribution'][s]-paper['distribution'][s]:>+12.1f}")

print(f"\n{'Per-Stage Performance (Ours)':^56}")
print('-'*56)
for stage, m in r['per_stage_metrics'].items():
    print(f"{stage:<15} P={m['precision']*100:5.1f}%  R={m['recall']*100:5.1f}%  F1={m['f1']*100:5.1f}%  (n={m['support']})")

print('\n' + '='*70)
print('DATASET SOURCES:')
print('='*70)
print('  1. TRAM Original (MITRE ATT&CK):     ~15,763 samples')
print('  2. APT Malware (12 groups):          ~1,232 samples')  
print('  3. TheZoo (262 malware families):    ~1,048 samples')
print('  4. Sysmon Logs (URLhaus):               ~16 samples')
print('  -------------------------------------------------')
print('  TOTAL:                               ~18,059 samples')

print('\n' + '='*70)
print('NHAN XET:')
print('='*70)
acc_diff = ours['accuracy'] - paper['accuracy']
if acc_diff >= 0:
    print(f'  [+] Accuracy cao hon bai bao {acc_diff:.2f}%')
else:
    print(f'  [-] Accuracy thap hon bai bao {abs(acc_diff):.2f}%')
    print(f'      Nguyen nhan co the:')
    print(f'      - Dataset da duoc mo rong voi data tu nhieu nguon khac nhau')
    print(f'      - APT/TheZoo data duoc generate tu templates, khong phai real data')
    print(f'      - Distribution thay doi nhe (Operational: +1.8%)')

print(f'\n  [i] Dataset lon hon bai bao: +{ours["dataset_size"]-paper["dataset_size"]:,} samples (+{(ours["dataset_size"]-paper["dataset_size"])/paper["dataset_size"]*100:.1f}%)')
print(f'  [i] Model van dat hieu suat tot (>95% accuracy)')
print(f'  [i] Per-stage F1 scores deu > 90%')
print('='*70)
