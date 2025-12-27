"""
BERT-MLP Fileless Malware Detector Training
Based on: "Unveiling the veiled: An early stage detection of fileless malware"
Singh & Tripathy (2024) - IIT Patna

Key features:
- BERT-base encoder + MLP classifier
- 4-stage attack classification (Initial, Pre-operational, Operational, Final)
- Mixed precision training support
- Early detection focus (59.3% at pre-operational stage in paper)
"""
import json
import os
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple, Dict

import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModel, AutoTokenizer


@dataclass
class TrainConfig:
    """Training configuration matching paper parameters"""
    data_path: str = "events.csv"  # 15K balanced dataset (12%/59.3%/21.1%/7.6%)
    stix_path: Optional[str] = "enterprise-attack.json"
    model_name: str = "bert-base-uncased"  # Paper uses bert-base
    max_len: int = 128  # Paper uses 40, but we use more for better context
    batch_size: int = 16  # Paper uses 16
    lr: float = 2e-5  # Paper uses 2e-5
    epochs: int = 25  # Paper uses 25 epochs
    weight_decay: float = 0.01  # Paper uses 0.01
    num_labels: int = 4  # 4 stages: Initial, Pre-op, Op, Final
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
    seed: int = 42
    fp16: bool = True
    dropout: float = 0.3  # Paper uses 0.3
    freeze_bert: bool = True  # Paper freezes BERT initially
    warmup_ratio: float = 0.1  # 10% warmup


def load_stix_lookup(stix_path: Optional[str]):
    if not stix_path:
        return {}
    try:
        with open(stix_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        lookup = {}
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                tid = obj.get("external_references", [{}])[0].get("external_id")
                if tid:
                    lookup[tid] = obj.get("name", "")
        return lookup
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] could not load STIX: {exc}")
        return {}


class LogDataset(Dataset):
    def __init__(self, df: pd.DataFrame, tokenizer: AutoTokenizer, max_len: int):
        self.df = df.reset_index(drop=True)
        self.tok = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.df)

    def __getitem__(self, idx: int):
        row = self.df.iloc[idx]
        enc = self.tok(
            row["text"],
            max_length=self.max_len,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )
        num_feats = torch.tensor(json.loads(row["num_feats"]), dtype=torch.float)
        label = torch.tensor(int(row["label"]), dtype=torch.long)
        return {k: v.squeeze(0) for k, v in enc.items()}, num_feats, label


class BertFusion(nn.Module):
    """
    BERT-MLP Architecture theo bài báo
    BERT encoder + MLP head với numeric features fusion
    """
    def __init__(self, model_name: str, num_feat_dim: int, num_labels: int, 
                 dropout: float = 0.3, freeze_bert: bool = True):
        super().__init__()
        self.bert = AutoModel.from_pretrained(model_name)
        self.num_labels = num_labels
        
        # Freeze BERT parameters như bài báo
        if freeze_bert:
            for param in self.bert.parameters():
                param.requires_grad = False
        
        # Hidden dimension
        bert_hidden = self.bert.config.hidden_size  # 768 for bert-base
        mlp_hidden = 256
        
        # Numeric feature projection
        self.num_proj = nn.Sequential(
            nn.LayerNorm(num_feat_dim),
            nn.Linear(num_feat_dim, mlp_hidden),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        
        # Attention pooling for BERT output (optional, can use [CLS])
        self.use_attention_pooling = False
        if self.use_attention_pooling:
            self.attention = nn.Linear(bert_hidden, 1)
        
        # Fusion and classification head (MLP)
        fusion_dim = bert_hidden + mlp_hidden
        self.classifier = nn.Sequential(
            nn.Linear(fusion_dim, mlp_hidden),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(mlp_hidden, mlp_hidden // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(mlp_hidden // 2, num_labels),
        )

    def forward(self, input_ids, attention_mask, num_feats, token_type_ids=None):
        # BERT encoding
        bert_kwargs = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
        }
        if token_type_ids is not None:
            bert_kwargs["token_type_ids"] = token_type_ids
        
        bert_out = self.bert(**bert_kwargs)
        
        # Pooling strategy
        if self.use_attention_pooling:
            # Attention-weighted pooling
            hidden_states = bert_out.last_hidden_state
            attention_weights = torch.softmax(
                self.attention(hidden_states).squeeze(-1) + (1 - attention_mask.float()) * -10000,
                dim=-1
            )
            pooled = torch.sum(hidden_states * attention_weights.unsqueeze(-1), dim=1)
        else:
            # [CLS] token pooling (standard)
            pooled = bert_out.last_hidden_state[:, 0]
        
        # Numeric feature projection
        num_h = self.num_proj(num_feats)
        
        # Fusion: concatenate BERT and numeric features
        fused = torch.cat([pooled, num_h], dim=1)
        
        # Classification
        logits = self.classifier(fused)
        
        return logits
    
    def unfreeze_bert(self, num_layers: int = 2):
        """Unfreeze top layers of BERT for fine-tuning"""
        # Unfreeze pooler
        for param in self.bert.pooler.parameters():
            param.requires_grad = True
        
        # Unfreeze top encoder layers
        for layer in self.bert.encoder.layer[-num_layers:]:
            for param in layer.parameters():
                param.requires_grad = True


def split_df(df: pd.DataFrame, train_frac=0.8, val_frac=0.1, seed=42):
    train_df = df.sample(frac=train_frac, random_state=seed)
    tmp_df = df.drop(train_df.index)
    val_df = tmp_df.sample(frac=val_frac / (1 - train_frac), random_state=seed + 1)
    test_df = tmp_df.drop(val_df.index)
    return train_df, val_df, test_df


def run_epoch(model, loader, optim, criterion, device, train: bool = True, 
               scaler=None, fp16: bool = False, scheduler=None):
    """Run one training/validation epoch"""
    model.train() if train else model.eval()
    total_loss = total_correct = total = 0
    
    with torch.set_grad_enabled(train):
        for toks, num_feats, labels in loader:
            toks = {k: v.to(device) for k, v in toks.items()}
            num_feats = num_feats.to(device)
            labels = labels.to(device)

            if train:
                optim.zero_grad()

            use_fp16 = train and fp16 and scaler is not None and device.startswith("cuda")
            if use_fp16:
                with torch.amp.autocast("cuda"):
                    logits = model(**toks, num_feats=num_feats)
                    loss = criterion(logits, labels)
                scaler.scale(loss).backward()
                scaler.unscale_(optim)
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                scaler.step(optim)
                scaler.update()
            else:
                logits = model(**toks, num_feats=num_feats)
                loss = criterion(logits, labels)
                if train:
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                    optim.step()
            
            # Update scheduler after each step (not epoch)
            if train and scheduler is not None:
                scheduler.step()

            total_loss += loss.item() * labels.size(0)
            preds = logits.argmax(dim=1)
            total_correct += (preds == labels).sum().item()
            total += labels.size(0)

    return total_loss / total, total_correct / total


def eval_metrics(model, loader, device):
    """
    Calculate detailed metrics per stage (matching paper Table 9)
    """
    model.eval()
    all_preds = []
    all_labels = []
    
    with torch.no_grad():
        for toks, num_feats, labels in loader:
            toks = {k: v.to(device) for k, v in toks.items()}
            num_feats = num_feats.to(device)
            preds = model(**toks, num_feats=num_feats).argmax(dim=1)
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels.tolist())
    
    # Calculate per-class metrics
    from sklearn.metrics import precision_recall_fscore_support, confusion_matrix, accuracy_score
    
    precision, recall, f1, support = precision_recall_fscore_support(
        all_labels, all_preds, average=None, zero_division=0
    )
    
    # Overall metrics
    overall_acc = accuracy_score(all_labels, all_preds)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        all_labels, all_preds, average='macro', zero_division=0
    )
    
    # Per-stage metrics (matching paper format)
    stage_names = {0: "Initial", 1: "Pre-operational", 2: "Operational", 3: "Final"}
    per_stage = {}
    for i in range(min(len(precision), 4)):
        per_stage[stage_names.get(i, f"Stage {i}")] = {
            'precision': precision[i] if i < len(precision) else 0,
            'recall': recall[i] if i < len(recall) else 0,
            'f1': f1[i] if i < len(f1) else 0,
            'support': support[i] if i < len(support) else 0,
        }
    
    cm = confusion_matrix(all_labels, all_preds)
    
    return {
        'accuracy': overall_acc,
        'macro_precision': macro_p,
        'macro_recall': macro_r,
        'macro_f1': macro_f1,
        'per_stage': per_stage,
        'confusion_matrix': cm.tolist(),
        'all_preds': all_preds,
        'all_labels': all_labels,
    }


def main(cfg: TrainConfig):
    """
    Main training loop theo methodology của bài báo
    """
    print("="*60)
    print("BERT-MLP FILELESS MALWARE DETECTOR")
    print("Based on: Singh & Tripathy (2024)")
    print("="*60)
    
    assert os.path.exists(cfg.data_path), f"missing data file {cfg.data_path}"
    df = pd.read_csv(cfg.data_path)
    # Rename columns to match expected format
    if 'sentence' in df.columns:
        df = df.rename(columns={'sentence': 'text'})
    if 'stage' in df.columns:
        df = df.rename(columns={'stage': 'label'})
    
    print(f"\nConfiguration:")
    print(f"  Model: {cfg.model_name}")
    print(f"  Epochs: {cfg.epochs}")
    print(f"  Batch size: {cfg.batch_size}")
    print(f"  Learning rate: {cfg.lr}")
    print(f"  Num labels: {cfg.num_labels}")
    print(f"  Device: {cfg.device}")
    
    # Initialize tokenizer
    tok = AutoTokenizer.from_pretrained(cfg.model_name)
    num_feat_dim = len(json.loads(df.iloc[0]["num_feats"]))
    print(f"  Numeric feature dim: {num_feat_dim}")
    
    # Stratified split
    train_df, val_df, test_df = split_df(df, seed=cfg.seed)
    print(f"\nDataset split:")
    print(f"  Train: {len(train_df)} samples")
    print(f"  Val: {len(val_df)} samples")
    print(f"  Test: {len(test_df)} samples")
    
    # Print label distribution
    print(f"\nLabel distribution (train):")
    for lbl, count in train_df['label'].value_counts().sort_index().items():
        print(f"  Stage {lbl}: {count} ({count/len(train_df)*100:.1f}%)")

    train_ds = LogDataset(train_df, tok, cfg.max_len)
    val_ds = LogDataset(val_df, tok, cfg.max_len)
    test_ds = LogDataset(test_df, tok, cfg.max_len)

    train_loader = DataLoader(train_ds, batch_size=cfg.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=cfg.batch_size)
    test_loader = DataLoader(test_ds, batch_size=cfg.batch_size)

    # Initialize model
    model = BertFusion(
        cfg.model_name, 
        num_feat_dim, 
        cfg.num_labels,
        dropout=cfg.dropout,
        freeze_bert=cfg.freeze_bert
    ).to(cfg.device)
    
    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"\nModel parameters:")
    print(f"  Total: {total_params:,}")
    print(f"  Trainable: {trainable_params:,}")
    
    # Optimizer with warmup
    optim = torch.optim.AdamW(
        model.parameters(), 
        lr=cfg.lr, 
        betas=(0.9, 0.999),
        weight_decay=cfg.weight_decay
    )
    
    # Learning rate scheduler with warmup
    total_steps = len(train_loader) * cfg.epochs
    warmup_steps = int(total_steps * cfg.warmup_ratio)
    
    from transformers import get_linear_schedule_with_warmup
    scheduler = get_linear_schedule_with_warmup(
        optim,
        num_warmup_steps=warmup_steps,
        num_training_steps=total_steps
    )
    
    scaler = torch.amp.GradScaler("cuda") if cfg.fp16 and cfg.device.startswith("cuda") else None
    criterion = nn.CrossEntropyLoss()

    print(f"\nTraining:")
    print(f"  Total steps: {total_steps}")
    print(f"  Warmup steps: {warmup_steps}")
    
    # Training loop
    best_val_acc = 0
    best_metrics = None
    train_losses = []
    val_losses = []
    val_accuracies = []
    
    for epoch in range(cfg.epochs):
        tr_loss, tr_acc = run_epoch(
            model, train_loader, optim, criterion, cfg.device, 
            train=True, scaler=scaler, fp16=cfg.fp16, scheduler=scheduler
        )
        va_loss, va_acc = run_epoch(
            model, val_loader, optim, criterion, cfg.device, 
            train=False, scaler=scaler, fp16=cfg.fp16
        )
        
        train_losses.append(tr_loss)
        val_losses.append(va_loss)
        val_accuracies.append(va_acc)
        
        # Save best model
        if va_acc > best_val_acc:
            best_val_acc = va_acc
            torch.save(model.state_dict(), "fileless_detector.pt")
            best_metrics = eval_metrics(model, val_loader, cfg.device)
        
        print(f"Epoch {epoch+1}/{cfg.epochs}: "
              f"train loss {tr_loss:.4f} acc {tr_acc:.3f} | "
              f"val loss {va_loss:.4f} acc {va_acc:.3f}")
        
        # Unfreeze BERT after some epochs (optional fine-tuning)
        if epoch == cfg.epochs // 2 and cfg.freeze_bert:
            print("  -> Unfreezing top 2 BERT layers for fine-tuning")
            model.unfreeze_bert(num_layers=2)
            # Reduce learning rate
            for param_group in optim.param_groups:
                param_group['lr'] = cfg.lr / 10

    # Final evaluation on test set
    print("\n" + "="*60)
    print("EVALUATION RESULTS")
    print("="*60)
    
    # Load best model
    model.load_state_dict(torch.load("fileless_detector.pt"))
    
    te_loss, te_acc = run_epoch(
        model, test_loader, optim, criterion, cfg.device, 
        train=False, scaler=scaler, fp16=cfg.fp16
    )
    test_metrics = eval_metrics(model, test_loader, cfg.device)
    
    print(f"\nTest Results:")
    print(f"  Accuracy: {test_metrics['accuracy']:.4f}")
    print(f"  Macro Precision: {test_metrics['macro_precision']:.4f}")
    print(f"  Macro Recall: {test_metrics['macro_recall']:.4f}")
    print(f"  Macro F1: {test_metrics['macro_f1']:.4f}")
    
    print(f"\nPer-Stage Results (Paper Format - Table 9):")
    print("-"*50)
    print(f"{'Stage':<20} {'Precision':<12} {'Recall':<12} {'F1':<12}")
    print("-"*50)
    for stage_name, metrics in test_metrics['per_stage'].items():
        print(f"{stage_name:<20} {metrics['precision']:.4f}       "
              f"{metrics['recall']:.4f}       {metrics['f1']:.4f}")
    print("-"*50)
    
    # Comparison with paper
    print(f"\nComparison with Paper Results:")
    print(f"  Paper Overall Accuracy: 0.9705")
    print(f"  Our Overall Accuracy:   {test_metrics['accuracy']:.4f}")
    print(f"  Difference: {abs(test_metrics['accuracy'] - 0.9705):.4f}")

    # Save results
    torch.save(model.state_dict(), "fileless_detector.pt")
    
    results = {
        'config': asdict(cfg),
        'best_val_accuracy': best_val_acc,
        'test_accuracy': test_metrics['accuracy'],
        'test_metrics': {
            'accuracy': test_metrics['accuracy'],
            'macro_precision': test_metrics['macro_precision'],
            'macro_recall': test_metrics['macro_recall'],
            'macro_f1': test_metrics['macro_f1'],
        },
        'per_stage_metrics': test_metrics['per_stage'],
        'training_history': {
            'train_losses': train_losses,
            'val_losses': val_losses,
            'val_accuracies': val_accuracies,
        },
        'paper_comparison': {
            'paper_accuracy': 0.9705,
            'our_accuracy': test_metrics['accuracy'],
            'difference': abs(test_metrics['accuracy'] - 0.9705)
        }
    }
    
    with open("fileless_detector_cfg.json", "w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, indent=2)
    
    with open("training_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)

    stix_lookup = load_stix_lookup(cfg.stix_path)
    if stix_lookup:
        print(f"\nLoaded {len(stix_lookup)} ATT&CK techniques for reference")
    
    print(f"\n✓ Model saved to fileless_detector.pt")
    print(f"✓ Results saved to training_results.json")


if __name__ == "__main__":
    cfg = TrainConfig()
    main(cfg)
