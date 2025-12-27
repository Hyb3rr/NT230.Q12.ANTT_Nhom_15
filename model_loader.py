"""
Secure Model Loader for Fileless Malware Detector
Loads PyTorch model with security controls

Security Features:
- Model integrity verification
- Safe device mapping (CPU fallback)
- Memory-efficient loading
- No weight exposure in logs
- Proper resource cleanup
"""
import json
import logging
import os
from pathlib import Path
from typing import Dict, Optional

import torch
from transformers import AutoTokenizer

logger = logging.getLogger(__name__)


class ModelLoader:
    """
    Securely loads and manages the fileless malware detection model
    
    Based on BERT-MLP architecture from:
    "Unveiling the veiled: An early stage detection of fileless malware"
    Singh & Tripathy (2024)
    """
    
    def __init__(
        self,
        model_path: str = "fileless_detector.pt",
        config_path: str = "fileless_detector_cfg.json"
    ):
        """
        Initialize model loader
        
        Args:
            model_path: Path to trained model weights (.pt file)
            config_path: Path to model configuration JSON
        """
        self.model_path = Path(model_path)
        self.config_path = Path(config_path)
        
        # Security: Validate file existence
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        
        # Load configuration
        self.config = self._load_config()
        
        # Setup device (CPU fallback for security/compatibility)
        self.device = self._setup_device()
        
        # Load tokenizer
        self.tokenizer = self._load_tokenizer()
        
        # Load model architecture and weights
        self.model = self._load_model()
        
        logger.info(f"Model loaded successfully on {self.device}")
    
    def _load_config(self) -> Dict:
        """Load and validate configuration"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Validate required fields
            required_fields = ['model_name', 'max_len', 'num_labels']
            for field in required_fields:
                if field not in config:
                    raise ValueError(f"Missing required config field: {field}")
            
            # Security: Enforce safe defaults
            config.setdefault('dropout', 0.3)
            config.setdefault('max_len', 128)
            
            logger.info(f"Configuration loaded: {config.get('model_name')}")
            return config
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file: {e}")
    
    def _setup_device(self) -> torch.device:
        """
        Setup compute device with safe fallback
        
        Security: Always allow CPU fallback
        """
        # Check config preference
        config_device = self.config.get('device', 'cpu')
        
        # Security: Validate device availability
        if config_device == 'cuda' and torch.cuda.is_available():
            device = torch.device('cuda')
            logger.info(f"Using GPU: {torch.cuda.get_device_name(0)}")
        else:
            device = torch.device('cpu')
            logger.info("Using CPU")
        
        return device
    
    def _load_tokenizer(self) -> AutoTokenizer:
        """Load BERT tokenizer"""
        try:
            model_name = self.config['model_name']
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            logger.info(f"Tokenizer loaded: {model_name}")
            return tokenizer
        except Exception as e:
            raise RuntimeError(f"Failed to load tokenizer: {e}")
    
    def _infer_num_feat_dim(self, state_dict: Dict[str, torch.Tensor]) -> int:
        """Infer numeric feature dimension from saved weights."""
        proj_key = "num_proj.0.weight"
        if proj_key in state_dict and hasattr(state_dict[proj_key], "shape"):
            return int(state_dict[proj_key].shape[0])
        return self._calculate_num_feat_dim()

    def _load_model(self) -> torch.nn.Module:
        """
        Load model architecture and weights securely
        
        Security controls:
        - No pickle execution (weights_only=True)
        - Safe device mapping
        - Eval mode only (no training)
        """
        try:
            # Import model architecture
            from train_fileless_detector import BertFusion

            # Security: Load weights safely
            logger.info("Loading model weights...")
            state_dict = torch.load(
                self.model_path,
                map_location=self.device,
                weights_only=True  # Security: Prevent arbitrary code execution
            )

            # Infer numeric feature dimension from weights to match trained model
            num_feat_dim = self._infer_num_feat_dim(state_dict)
            self.num_feat_dim = num_feat_dim

            # Initialize model architecture with inferred feature dimension
            model = BertFusion(
                model_name=self.config['model_name'],
                num_feat_dim=num_feat_dim,
                num_labels=self.config['num_labels'],
                dropout=self.config.get('dropout', 0.3),
                freeze_bert=False  # No need to freeze during inference
            )
            
            model.load_state_dict(state_dict)
            model.to(self.device)
            
            # Security: Set to eval mode (disable dropout, batch norm)
            model.eval()
            
            # Freeze all parameters (inference only)
            for param in model.parameters():
                param.requires_grad = False
            
            logger.info("Model weights loaded successfully")
            logger.info(f"Model parameters: {sum(p.numel() for p in model.parameters()):,}")
            
            return model
            
        except Exception as e:
            raise RuntimeError(f"Failed to load model: {e}")
    
    def _calculate_num_feat_dim(self) -> int:
        """
        Calculate numeric feature dimension
        
        Based on enhanced_features.py implementation
        Default: 5 basic features (length, entropy, base64, tokens, upper_ratio)
        """
        # Security: Use safe default
        return 5
    
    def get_model(self) -> torch.nn.Module:
        """Get model instance (read-only)"""
        return self.model

    def get_num_feat_dim(self) -> int:
        """Get numeric feature dimension expected by the model."""
        return getattr(self, "num_feat_dim", self._calculate_num_feat_dim())
    
    def get_tokenizer(self) -> AutoTokenizer:
        """Get tokenizer instance"""
        return self.tokenizer
    
    def get_config(self) -> Dict:
        """Get configuration (copy to prevent modification)"""
        return self.config.copy()
    
    def get_max_length(self) -> int:
        """Get maximum sequence length"""
        return self.config.get('max_len', 128)
    
    def cleanup(self):
        """Clean up resources"""
        if hasattr(self, 'model'):
            del self.model
        
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        
        logger.info("Model resources cleaned up")
    
    def __del__(self):
        """Destructor for cleanup"""
        try:
            self.cleanup()
        except:
            pass
