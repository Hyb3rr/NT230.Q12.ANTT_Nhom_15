"""
Fileless Malware Detection API
"""
import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from schemas import (
    DetectionRequest,
    DetectionResponse,
    HealthResponse,
    StageInfo,
    TechniqueInfo,
)
from model_loader import ModelLoader
from inference import FilelessDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fileless_detector_api.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global model loader
model_loader: Optional[ModelLoader] = None
detector: Optional[FilelessDetector] = None
process_monitor: Optional['ProcessMonitor'] = None

# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global model_loader, detector, process_monitor
    
    logger.info("Starting Fileless Malware Detection API")
    logger.info("Loading model weights...")
    
    try:
        model_loader = ModelLoader(
            model_path="fileless_detector.pt",
            config_path="fileless_detector_cfg.json"
        )
        detector = FilelessDetector(model_loader)
        logger.info("Model loaded successfully")
        logger.info(f"Device: {model_loader.device}")
        logger.info(f"Model architecture: BERT-MLP (4-stage classifier)")
        
        # Initialize process monitor
        logger.info("Initializing automatic process monitor...")
        from process_monitor import ProcessMonitor
        process_monitor = ProcessMonitor(detector=detector)
        
        # Auto-start monitoring if enabled
        import os
        if os.getenv("AUTO_MONITOR", "true").lower() == "true":
            logger.info("Starting automatic Windows process monitoring ")
            process_monitor.start()
            logger.info("Auto-monitoring ENABLED - Scanning Windows processes in real-time")
        else:
            logger.info("Auto-monitoring DISABLED - Use /monitor/start to enable")
        
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        raise RuntimeError(f"Model initialization failed: {e}")
    
    yield
    
    logger.info("Shutting down API")
    
    # Stop process monitor
    if process_monitor:
        logger.info("Stopping process monitor...")
        process_monitor.stop()
    
    # Cleanup if needed
    if model_loader:
        model_loader.cleanup()


# Initialize FastAPI app
app = FastAPI(
    title="Fileless Malware Detection API",
    description="Early-stage detection of fileless malware",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware (restrict in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:5173",  # Vite dev server
    ],  # Whitelist only
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests for audit trail"""
    start_time = time.time()
    
    # Log request
    logger.info(f"Request: {request.method} {request.url.path} from {request.client.host}")
    
    response = await call_next(request)
    
    # Log response
    duration = time.time() - start_time
    logger.info(f"Response: {response.status_code} - Duration: {duration:.3f}s")
    
    return response


@app.get("/", response_model=Dict[str, str])
async def root():
    """API root endpoint"""
    return {
        "service": "Fileless Malware Detection API",
        "version": "1.0.0",
        "status": "operational",
        "purpose": "Defensive blue team operations - early detection of fileless malware",
        "docs": "/docs"
    }


@app.get("/health", response_model=HealthResponse)
@limiter.limit("30/minute")
async def health_check(request: Request):
    """Health check endpoint"""
    if model_loader is None or detector is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model not loaded"
        )
    
    return HealthResponse(
        status="healthy",
        model_loaded=True,
        device=str(model_loader.device),
        model_architecture="BERT-MLP (4-stage classifier)",
        version="1.0.0"
    )


@app.post("/detect", response_model=DetectionResponse)
@limiter.limit("10/minute")  # Rate limiting to prevent abuse
async def detect_malware(request: Request, detection_request: DetectionRequest):
    """
    Detect fileless malware from process memory features
    """
    if detector is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detector not initialized"
        )
    
    # Security: Log detection request (for audit)
    logger.info(f"Detection request from {request.client.host}")
    logger.info(f"Input length: {len(detection_request.text)} chars")
    
    try:
        # Perform detection
        start_time = time.time()
        result = detector.detect(
            text=detection_request.text,
            numeric_features=detection_request.numeric_features,
            threshold=detection_request.threshold
        )
        inference_time = time.time() - start_time
        
        # Log results
        logger.info(f"Detection result: {result['verdict']} "
                   f"(confidence: {result['confidence']:.2%}, "
                   f"stage: {result['stage_name']}, "
                   f"time: {inference_time:.3f}s)")
        
        # Add metadata
        result['inference_time_ms'] = round(inference_time * 1000, 2)
        result['model_version'] = "1.0.0"
        
        return DetectionResponse(**result)
        
    except ValueError as e:
        logger.warning(f"Invalid input: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid input: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Detection error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal detection error"
        )


@app.get("/stages", response_model=Dict[int, StageInfo])
@limiter.limit("30/minute")
async def get_stage_info(request: Request):
    """
    Get information about attack stages
    
    Returns MITRE ATT&CK tactics mapped to each stage:
    - Stage 0 (Initial): Reconnaissance, Initial Access
    - Stage 1 (Pre-operational): Execution, Persistence, Privilege Escalation
    - Stage 2 (Operational): Defense Evasion, Credential Access, Discovery, Lateral Movement
    - Stage 3 (Final): Collection, Command & Control, Exfiltration, Impact
    """
    return {
        0: StageInfo(
            stage_id=0,
            stage_name="Initial",
            description="Initial access and reconnaissance phase",
            tactics=["Reconnaissance", "Initial Access"],
            typical_techniques=[
                "T1566.001 - Phishing: Spearphishing Attachment",
                "T1566.002 - Phishing: Spearphishing Link",
                "T1190 - Exploit Public-Facing Application"
            ]
        ),
        1: StageInfo(
            stage_id=1,
            stage_name="Pre-operational",
            description="Execution, persistence establishment, and privilege escalation",
            tactics=["Execution", "Persistence", "Privilege Escalation"],
            typical_techniques=[
                "T1059.001 - PowerShell",
                "T1112 - Modify Registry",
                "T1053.005 - Scheduled Task",
                "T1055 - Process Injection"
            ]
        ),
        2: StageInfo(
            stage_id=2,
            stage_name="Operational",
            description="Active malicious operations and lateral movement",
            tactics=["Defense Evasion", "Credential Access", "Discovery", "Lateral Movement"],
            typical_techniques=[
                "T1027 - Obfuscated Files or Information",
                "T1140 - Deobfuscate/Decode Files",
                "T1003 - OS Credential Dumping",
                "T1057 - Process Discovery",
                "T1021.006 - Windows Remote Management"
            ]
        ),
        3: StageInfo(
            stage_id=3,
            stage_name="Final",
            description="Data collection, exfiltration, and impact",
            tactics=["Collection", "Command and Control", "Exfiltration", "Impact"],
            typical_techniques=[
                "T1005 - Data from Local System",
                "T1071.001 - Web Protocols",
                "T1041 - Exfiltration Over C2 Channel",
                "T1486 - Data Encrypted for Impact"
            ]
        )
    }


@app.get("/techniques/{technique_id}", response_model=TechniqueInfo)
@limiter.limit("30/minute")
async def get_technique_details(request: Request, technique_id: str):
    """
    Get details about a specific MITRE ATT&CK technique
    
    Example: /techniques/T1059.001
    """
    if detector is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detector not initialized"
        )
    
    try:
        technique_info = detector.get_technique_info(technique_id)
        if not technique_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Technique {technique_id} not found"
            )
        
        return technique_info
    
    except Exception as e:
        logger.error(f"Error retrieving technique {technique_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve technique information: {str(e)}"
        )


# ===============================
# PROCESS MONITOR ENDPOINTS (NEW)
# ===============================

@app.post("/monitor/start")
@limiter.limit("5/minute")
async def start_monitoring(request: Request):
    """
    Start automatic process monitoring
    
    Enables real-time Windows process scanning for suspicious activity
    """
    global process_monitor
    
    if process_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Process monitor not initialized"
        )
    
    try:
        process_monitor.start()
        return {
            "status": "started",
            "message": "Automatic process monitoring enabled",
            "mode": "real-time",
            "scan_interval": f"{process_monitor.SCAN_INTERVAL}s"
        }
    except Exception as e:
        logger.error(f"Failed to start monitor: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start monitoring: {str(e)}"
        )


@app.post("/monitor/stop")
@limiter.limit("5/minute")
async def stop_monitoring(request: Request):
    """Stop automatic process monitoring"""
    global process_monitor
    
    if process_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Process monitor not initialized"
        )
    
    try:
        process_monitor.stop()
        return {
            "status": "stopped",
            "message": "Automatic process monitoring disabled"
        }
    except Exception as e:
        logger.error(f"Failed to stop monitor: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop monitoring: {str(e)}"
        )


@app.get("/monitor/stats")
@limiter.limit("20/minute")
async def get_monitor_stats(request: Request):
    """
    Get process monitoring statistics
    
    Returns:
    - Total processes scanned
    - Suspicious processes found
    - Malware detections
    - Current queue size
    """
    global process_monitor
    
    if process_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Process monitor not initialized"
        )
    
    try:
        stats = process_monitor.get_stats()
        return {
            "monitoring_stats": stats,
            "status": "active" if process_monitor.monitor_thread and process_monitor.monitor_thread.is_alive() else "inactive"
        }
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve stats: {str(e)}"
        )


@app.get("/monitor/detections")
@limiter.limit("20/minute")
async def get_detected_malware(request: Request):
    """
    Get list of all detected malware from automatic monitoring
    
    Returns complete detection history with process info and MITRE mapping
    """
    global process_monitor
    
    if process_monitor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Process monitor not initialized"
        )
    
    try:
        detections = process_monitor.get_detected_malware()
        return {
            "total_detections": len(detections),
            "detections": detections
        }
    except Exception as e:
        logger.error(f"Failed to get detections: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve detections: {str(e)}"
        )
        return TechniqueInfo(**technique_info)
    except Exception as e:
        logger.error(f"Error fetching technique {technique_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving technique information"
        )


if __name__ == "__main__":
    import uvicorn
    
    # Production configuration
    uvicorn.run(
        "app:app",
        host="127.0.0.1",  # Localhost only for security
        port=8000,
        log_level="info",
        access_log=True,
        workers=1  # Single worker to avoid model duplication
    )
