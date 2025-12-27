"""
Pydantic Schemas for API Request/Response Validation

Security Features:
- Input size validation
- Type enforcement
- Automatic sanitization
- Default value safety
"""
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator


class BaseSchema(BaseModel):
    """Base schema with Pydantic v2-safe config"""

    model_config = {
        "protected_namespaces": (),
        "json_schema_extra": None,
    }


class DetectionRequest(BaseSchema):
    """
    Request schema for malware detection
    
    Security:
    - Max text length: 10,000 chars (prevent DoS)
    - Max numeric features: 100
    - Validated types
    """
    text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Memory forensics artifacts, process behavior description, or system event logs"
    )
    
    numeric_features: Optional[List[float]] = Field(
        None,
        max_items=100,
        description="Optional numeric features (auto-extracted if not provided). "
                    "Default features: [text_length, entropy, has_base64, token_count, uppercase_ratio]"
    )
    
    threshold: float = Field(
        0.5,
        ge=0.0,
        le=1.0,
        description="Confidence threshold for malicious classification (0.0-1.0)"
    )
    
    @validator('text')
    def sanitize_text(cls, v):
        """Sanitize text input"""
        if not v or not v.strip():
            raise ValueError("Text cannot be empty or whitespace only")
        return v.strip()
    
    @validator('numeric_features')
    def validate_numeric_features(cls, v):
        """Validate numeric features"""
        if v is None:
            return v
        
        # Check for invalid values
        import math
        for i, feat in enumerate(v):
            if not isinstance(feat, (int, float)):
                raise ValueError(f"Feature at index {i} must be numeric")
            if math.isnan(feat) or math.isinf(feat):
                raise ValueError(f"Feature at index {i} is invalid (NaN or Inf)")
        
        return v
    
    model_config = {
        **BaseSchema.model_config,
        "json_schema_extra": {
            "example": {
                "text": "mshta.exe executing JavaScript with WScript.Shell object accessing HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key",
                "numeric_features": [145, 4.2, 0, 15, 0.12],
                "threshold": 0.5
            }
        },
    }


class DetectionResponse(BaseSchema):
    """
    Response schema for malware detection
    
    Contains:
    - Verdict (malicious/benign)
    - Confidence score
    - Attack stage
    - MITRE ATT&CK mapping
    - Recommendations
    """
    verdict: str = Field(
        ...,
        description="Detection verdict: 'malicious' or 'benign'"
    )
    
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score for the prediction (0.0-1.0)"
    )
    
    stage: int = Field(
        ...,
        ge=0,
        le=3,
        description="Attack stage: 0=Initial, 1=Pre-operational, 2=Operational, 3=Final"
    )
    
    stage_name: str = Field(
        ...,
        description="Human-readable stage name"
    )
    
    probabilities: Dict[str, float] = Field(
        ...,
        description="Probability distribution over all stages"
    )
    
    tactics: List[str] = Field(
        ...,
        description="MITRE ATT&CK tactics associated with this stage"
    )
    
    common_techniques: List[str] = Field(
        ...,
        description="Common MITRE ATT&CK techniques for this stage"
    )
    
    threshold: float = Field(
        ...,
        description="Threshold used for classification"
    )
    
    recommendation: str = Field(
        ...,
        description="Security recommendation based on detection"
    )
    
    warning: Optional[str] = Field(
        None,
        description="Warning message for low confidence detections"
    )
    
    inference_time_ms: Optional[float] = Field(
        None,
        description="Inference time in milliseconds"
    )
    
    model_version: Optional[str] = Field(
        None,
        description="Model version used for detection"
    )
    
    model_config = {
        **BaseSchema.model_config,
        "json_schema_extra": {
            "example": {
                "verdict": "malicious",
                "confidence": 0.87,
                "stage": 1,
                "stage_name": "Pre-operational",
                "probabilities": {
                    "Initial": 0.05,
                    "Pre-operational": 0.87,
                    "Operational": 0.06,
                    "Final": 0.02
                },
                "tactics": ["Execution", "Persistence", "Privilege Escalation"],
                "common_techniques": ["T1059.001", "T1112", "T1053.005", "T1055"],
                "threshold": 0.5,
                "recommendation": "Pre-operational stage detected. Check for unauthorized persistence mechanisms, scheduled tasks, and registry modifications.",
                "inference_time_ms": 45.2,
                "model_version": "1.0.0"
            }
        },
    }


class HealthResponse(BaseSchema):
    """Health check response"""
    status: str = Field(..., description="Service status")
    model_loaded: bool = Field(..., description="Whether model is loaded")
    device: str = Field(..., description="Compute device (CPU/CUDA)")
    model_architecture: str = Field(..., description="Model architecture description")
    version: str = Field(..., description="API version")
    
    model_config = {
        **BaseSchema.model_config,
        "json_schema_extra": {
            "example": {
                "status": "healthy",
                "model_loaded": True,
                "device": "cuda",
                "model_architecture": "BERT-MLP (4-stage classifier)",
                "version": "1.0.0"
            }
        },
    }


class StageInfo(BaseSchema):
    """Information about an attack stage"""
    stage_id: int = Field(..., ge=0, le=3, description="Stage ID (0-3)")
    stage_name: str = Field(..., description="Stage name")
    description: str = Field(..., description="Stage description")
    tactics: List[str] = Field(..., description="MITRE ATT&CK tactics")
    typical_techniques: List[str] = Field(..., description="Common techniques")
    
    model_config = {
        **BaseSchema.model_config,
        "json_schema_extra": {
            "example": {
                "stage_id": 1,
                "stage_name": "Pre-operational",
                "description": "Execution, persistence establishment, and privilege escalation",
                "tactics": ["Execution", "Persistence", "Privilege Escalation"],
                "typical_techniques": [
                    "T1059.001 - PowerShell",
                    "T1112 - Modify Registry",
                    "T1053.005 - Scheduled Task"
                ]
            }
        },
    }


class TechniqueInfo(BaseSchema):
    """Information about MITRE ATT&CK technique"""
    name: str = Field(..., description="Technique name")
    tactic: str = Field(..., description="Associated tactic")
    description: str = Field(..., description="Technique description")
    detection: str = Field(..., description="Detection guidance")
    
    model_config = {
        **BaseSchema.model_config,
        "json_schema_extra": {
            "example": {
                "name": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "description": "Adversaries abuse PowerShell to execute malicious commands",
                "detection": "Monitor PowerShell execution, script block logging, encoded commands"
            }
        },
    }


class BatchDetectionRequest(BaseSchema):
    """
    Batch detection request
    
    Security: Limited to 32 items to prevent resource exhaustion
    """
    texts: List[str] = Field(
        ...,
        min_items=1,
        max_items=32,
        description="List of texts to analyze"
    )
    
    numeric_features_list: Optional[List[List[float]]] = Field(
        None,
        max_items=32,
        description="Optional numeric features for each text"
    )
    
    threshold: float = Field(
        0.5,
        ge=0.0,
        le=1.0,
        description="Confidence threshold"
    )
    
    @validator('texts')
    def validate_texts(cls, v):
        """Validate all texts"""
        for i, text in enumerate(v):
            if not text or not text.strip():
                raise ValueError(f"Text at index {i} is empty")
            if len(text) > 10000:
                raise ValueError(f"Text at index {i} exceeds maximum length")
        return v
    
    @validator('numeric_features_list')
    def validate_features_list(cls, v, values):
        """Validate features list length matches texts"""
        if v is not None:
            if 'texts' in values and len(v) != len(values['texts']):
                raise ValueError("numeric_features_list length must match texts length")
        return v


class BatchDetectionResponse(BaseModel):
    """Batch detection response"""
    results: List[DetectionResponse] = Field(..., description="Detection results for each input")
    total_processed: int = Field(..., description="Total number of items processed")
    total_time_ms: float = Field(..., description="Total processing time")
