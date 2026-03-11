"""
SC-Guard REST API

FastAPI application providing RESTful access to sc-guard functionality.

Endpoints:
    POST /api/v1/scan - Scan a Solidity contract
    GET  /api/v1/health - Health check
    GET  /api/v1/version - Version information
    GET  /docs - Interactive API documentation (Swagger UI)
    GET  /redoc - Alternative API documentation (ReDoc)
"""

import sys
import tempfile
import time
from pathlib import Path
from datetime import datetime
from typing import Optional
import platform

from fastapi import FastAPI, HTTPException, Depends, Request, status, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

# Import sc-guard modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.schemas import (
    ScanRequest,
    ScanResult,
    HealthResponse,
    VersionResponse,
    ErrorResponse,
    RateLimitResponse,
    MLPrediction,
    RiskAssessment,
    SecurityFeatures
)
from api.auth import verify_api_key, api_key_manager
from api.rate_limit import limiter, rate_limit_handler

from src.analyzers.slither_analyzer import SlitherAnalyzer
from src.analyzers.ast_extractor import ASTFeatureExtractor
from src.analyzers.graph_builder import CallGraphBuilder
from src.ml.train_model import VulnerabilityClassifier
from src.scoring.risk_engine import RiskScoringEngine
from src.enforcement.policy import PolicyEngine

# ============================================================================
# FastAPI Application Setup
# ============================================================================

app = FastAPI(
    title="SC-Guard API",
    description="""
    🛡️ **Smart Contract Vulnerability Detection API**
    
    Analyze Solidity smart contracts for security vulnerabilities using 
    static analysis and machine learning. 
    
    ## Features
    
    - **Static Analysis**: Powered by Slither
    - **ML Detection**: 4 Random Forest models for vulnerability classification
    - **Risk Scoring**: Weighted risk assessment (0-10 scale)
    - **Policy Enforcement**: ALLOW/WARN/BLOCK decisions
        
    ## Authentication
    
    All endpoints require an API key. Include it in the `X-API-Key` header:
    
    ```bash
    curl -H "X-API-Key: your-key-here" -X POST https://api.sc-guard.com/api/v1/scan
    ```
    
    ## Rate Limiting
    
    - **Free tier**: 10 requests/minute
    - **Authenticated**: 60 requests/minute
    
    Contact us for higher limits.
    """,
    version="0.1.0",
    contact={
        "name": "SC-Guard Team",
        "url": "https://github.com/your-org/sc-guard",
        "email": "support@sc-guard.com"
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT"
    },
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "scanning",
            "description": "Contract vulnerability scanning endpoints"
        },
        {
            "name": "system",
            "description": "System health and version information"
        }
    ]
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# Startup/Shutdown Events
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Load ML models and perform initialization."""
    print("🚀 Starting SC-Guard API...")
    print("📁 Loading ML models...")
    
    # Verify models exist
    models_dir = Path("models/")
    model_files = [
        "reentrancy_rf.pkl",
        "access_control_rf.pkl",
        "unchecked_external_call_rf.pkl",
        "dangerous_construct_rf.pkl"
    ]
    
    app.state.models_loaded = all((models_dir / f).exists() for f in model_files)
    
    if app.state.models_loaded:
        print("✅ All ML models loaded successfully")
    else:
        print("⚠️  Warning: Some ML models not found. Scanning may be limited.")
    
    print("✨ SC-Guard API ready!")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    print("👋 Shutting down SC-Guard API...")


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", tags=["system"])
async def root():
    """Root endpoint - API information."""
    return {
        "name": "SC-Guard API",
        "version": "0.1.0",
        "status": "operational",
        "documentation": "/docs",
        "health_check": "/api/v1/health"
    }


@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["system"],
    summary="Health check endpoint"
)
@limiter.limit("60/minute")
async def health_check(request: Request):
    """
    Check API health status.
    
    Returns service health, version, and model loading status.
    No authentication required.
    """
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        models_loaded=getattr(app.state, 'models_loaded', False),
        timestamp=datetime.utcnow().isoformat()
    )


@app.get(
    "/api/v1/version",
    response_model=VersionResponse,
    tags=["system"],
    summary="Get version information"
)
@limiter.limit("60/minute")
async def get_version(request: Request):
    """
    Get detailed version information.
    
    Returns versions of API, CLI, Python, and key dependencies.
    No authentication required.
    """
    import sklearn
    import slither
    
    return VersionResponse(
        api_version="0.1.0",
        cli_version="0.1.0",
        python_version=platform.python_version(),
        dependencies={
            "scikit-learn": sklearn.__version__,
            "slither-analyzer": slither.__version__ if hasattr(slither, '__version__') else "unknown",
            "fastapi": "0.104.0",
            "pydantic": "2.0.0"
        }
    )


@app.post(
    "/api/v1/scan",
    response_model=ScanResult,
    tags=["scanning"],
    summary="Scan Solidity contract for vulnerabilities",
    responses={
        200: {"description": "Scan completed successfully"},
        401: {"model": ErrorResponse, "description": "Authentication failed"},
        422: {"model": ErrorResponse, "description": "Invalid input"},
        429: {"model": RateLimitResponse, "description": "Rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal server error"}
    }
)
@limiter.limit("10/minute")
async def scan_contract(
    request: Request,
    scan_request: ScanRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Scan a Solidity contract for security vulnerabilities.
    
    **Required**: API key in `X-API-Key` header
    
    **Process**:
    1. Static analysis with Slither
    2. Feature extraction (16 dimensions)
    3. ML prediction (4 vulnerability types)
    4. Risk scoring (0-10 scale)
    5. Policy enforcement (ALLOW/WARN/BLOCK)
    
    **Parameters**:
    - `contract_code`: Solidity source code (required)
    - `filename`: Contract filename (default: "contract.sol")
    - `verbose`: Include detailed analysis (default: false)
    
    **Example Request**:
    ```json
    {
        "contract_code": "pragma solidity ^0.8.0; contract MyContract { ... }",
        "filename": "MyContract.sol",
        "verbose": true
    }
    ```
    
    **Returns**: Complete scan result with decision, risk score, and recommendations.
    """
    start_time = time.time()
    
    # Track API usage
    api_key_manager.increment_usage(api_key)
    
    try:
        # Create temporary file for contract
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.sol',
            delete=False,
            encoding='utf-8'
        ) as tmp_file:
            tmp_file.write(scan_request.contract_code)
            tmp_path = tmp_file.name
        
        try:
            # Phase 1: Static Analysis
            analyzer = SlitherAnalyzer(tmp_path)
            findings = analyzer.analyze()
            
            # Phase 2: Feature Extraction
            extractor = ASTFeatureExtractor(analyzer.slither)
            features = extractor.extract()
            
            # Phase 3: Graph Analysis
            graph_builder = CallGraphBuilder(analyzer.slither)
            graph_features = graph_builder.analyze()
            features.max_call_depth = graph_features.max_call_depth
            features.has_cycle_with_external_call = (
                graph_features.has_cycles and graph_features.external_calls_in_cycles > 0
            )
            features.external_calls_in_cycles = graph_features.external_calls_in_cycles
            
            feature_vector = features.to_vector().reshape(1, -1)
            
            # Phase 4: ML Prediction
            models_dir = Path("models/")
            model_files = {
                "reentrancy": "reentrancy_rf.pkl",
                "access_control": "access_control_rf.pkl",
                "unchecked_call": "unchecked_external_call_rf.pkl",
                "dangerous_construct": "dangerous_construct_rf.pkl"
            }
            
            ml_predictions = {}
            for vuln_type, filename in model_files.items():
                model_path = models_dir / filename
                if model_path.exists():
                    try:
                        model = VulnerabilityClassifier.load_model(str(model_path))
                        proba = model.predict_proba(feature_vector)
                        proba_vuln = proba[0] if len(proba.shape) > 1 else (proba[0] if proba[0] < 1 else 0.5)
                        prediction = 1 if proba_vuln >= 0.5 else 0
                        
                        ml_predictions[vuln_type] = MLPrediction(
                            prediction=prediction,
                            proba_vuln=proba_vuln,
                            confidence=proba_vuln if prediction == 1 else (1 - proba_vuln)
                        )
                    except Exception as e:
                        print(f"Warning: Could not load {vuln_type} model: {e}")
            
            # Phase 5: Risk Scoring
            risk_engine = RiskScoringEngine()
            probabilities = {k: v.proba_vuln for k, v in ml_predictions.items()}
            risk_obj = risk_engine.calculate_risk(probabilities)
            
            risk_category_str = (
                "HIGH" if risk_obj.overall_risk_score >= 7
                else ("MEDIUM" if risk_obj.overall_risk_score >= 4 else "LOW")
            )
            
            risk_assessment = RiskAssessment(
                risk_score=risk_obj.overall_risk_score,
                risk_category=risk_category_str,
                components={
                    k: v * RiskScoringEngine.VULNERABILITY_WEIGHTS.get(k, 1.0)
                    for k, v in probabilities.items()
                },
                confidence=risk_obj.confidence
            )
            
            # Phase 6: Enforcement
            policy_engine = PolicyEngine()
            result_obj = policy_engine.enforce(
                risk_score=risk_obj.overall_risk_score,
                risk_category=risk_category_str,
                vulnerability_probabilities=probabilities,
                static_findings=findings
            )
            result_dict = result_obj.to_dict()
            
            # Build response
            scan_time = time.time() - start_time
            
            response = ScanResult(
                decision=result_dict["decision"],
                risk_score=result_dict["risk_score"],
                risk_category=result_dict["risk_category"],
                detected_vulnerabilities=result_dict.get("detected_vulnerabilities", []),
                justification=result_dict["justification"],
                recommendations=result_dict.get("recommendations", []),
                scan_time_seconds=round(scan_time, 3)
            )
            
            # Add verbose details if requested
            if scan_request.verbose:
                response.ml_predictions = ml_predictions
                response.risk_assessment = risk_assessment
                response.features = SecurityFeatures(
                    external_call_count=features.external_call_count,
                    delegatecall_count=features.delegatecall_count,
                    send_transfer_count=features.send_transfer_count,
                    state_writes_before_call=features.state_writes_before_call,
                    state_writes_after_call=features.state_writes_after_call,
                    public_function_count=features.public_function_count,
                    external_function_count=features.external_function_count,
                    private_function_count=features.private_function_count,
                    has_access_control_modifier=features.has_access_control_modifier,
                    has_reentrancy_guard=features.has_reentrancy_guard,
                    uses_tx_origin=features.uses_tx_origin,
                    has_selfdestruct=features.has_selfdestruct,
                    unchecked_call_count=features.unchecked_call_count,
                    max_call_depth=features.max_call_depth,
                    has_cycle_with_external_call=features.has_cycle_with_external_call,
                    external_calls_in_cycles=features.external_calls_in_cycles
                )
            
            return response
            
        finally:
            # Cleanup temporary file
            Path(tmp_path).unlink(missing_ok=True)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )


@app.post(
    "/api/v1/scan/upload",
    response_model=ScanResult,
    tags=["scanning"],
    summary="Upload and scan Solidity file"
)
@limiter.limit("10/minute")
async def scan_uploaded_file(
    request: Request,
    file: UploadFile = File(..., description="Solidity contract file (.sol)"),
    verbose: bool = False,
    api_key: str = Depends(verify_api_key)
):
    """
    Upload a Solidity file and scan for vulnerabilities.
    
    **Required**: API key in `X-API-Key` header
    
    **Parameters**:
    - `file`: Solidity file upload (.sol extension required)
    - `verbose`: Include detailed analysis (query parameter)
    
    **Example**:
    ```bash
    curl -X POST "http://localhost:8000/api/v1/scan/upload?verbose=true" \\
        -H "X-API-Key: your-key" \\
        -F "file=@MyContract.sol"
    ```
    """
    # Validate file extension
    if not file.filename.endswith('.sol'):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File must be a Solidity contract (.sol extension)"
        )
    
    # Read file content
    try:
        content = await file.read()
        contract_code = content.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File must be valid UTF-8 encoded text"
        )
    
    # Create scan request and delegate to main scan endpoint
    scan_request = ScanRequest(
        contract_code=contract_code,
        filename=file.filename,
        verbose=verbose
    )
    
    return await scan_contract(request, scan_request, api_key)


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom handler for HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            detail=exc.detail,
            error_code=f"HTTP_{exc.status_code}",
            timestamp=datetime.utcnow().isoformat()
        ).dict()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handler for unexpected exceptions."""
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            detail="Internal server error",
            error_code="INTERNAL_ERROR",
            timestamp=datetime.utcnow().isoformat()
        ).dict()
    )


# ============================================================================
# Run Application
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting SC-Guard API Server...")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("🔍 ReDoc Documentation: http://localhost:8000/redoc")
    print("💡 Health Check: http://localhost:8000/api/v1/health\n")
    
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Enable auto-reload during development
        log_level="info"
    )
