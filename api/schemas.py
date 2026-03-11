"""
Pydantic schemas for API request/response validation.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, validator
from enum import Enum


class VulnerabilityType(str, Enum):
    """Supported vulnerability types."""
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    UNCHECKED_CALL = "unchecked_call"
    DANGEROUS_CONSTRUCT = "dangerous_construct"


class RiskCategory(str, Enum):
    """Risk classification levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Decision(str, Enum):
    """Enforcement policy decisions."""
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


# ============================================================================
# Request Models
# ============================================================================

class ScanRequest(BaseModel):
    """Request model for contract scanning."""
    contract_code: str = Field(
        ...,
        description="Solidity contract source code",
        min_length=1,
        max_length=100000
    )
    filename: str = Field(
        default="contract.sol",
        description="Contract filename",
        pattern=r"^[\w\-. ]+\.sol$"
    )
    verbose: bool = Field(
        default=False,
        description="Include detailed analysis in response"
    )

    @validator('contract_code')
    def validate_solidity_code(cls, v):
        """Ensure the code looks like Solidity."""
        if 'contract' not in v and 'pragma' not in v:
            raise ValueError("Input must be valid Solidity code")
        return v


# ============================================================================
# Response Models
# ============================================================================

class MLPrediction(BaseModel):
    """ML model prediction for a specific vulnerability."""
    prediction: int = Field(..., description="0=safe, 1=vulnerable", ge=0, le=1)
    proba_vuln: float = Field(..., description="Probability of vulnerability", ge=0, le=1)
    confidence: float = Field(..., description="Model confidence", ge=0, le=1)


class RiskAssessment(BaseModel):
    """Overall risk score and components."""
    risk_score: float = Field(..., description="Overall risk score (0-10)", ge=0, le=10)
    risk_category: RiskCategory = Field(..., description="Risk classification")
    components: Dict[str, float] = Field(..., description="Individual vulnerability contributions")
    confidence: float = Field(..., description="Overall confidence", ge=0, le=1)


class SecurityFeatures(BaseModel):
    """Extracted security features from contract."""
    external_call_count: int = Field(..., ge=0)
    delegatecall_count: int = Field(..., ge=0)
    send_transfer_count: int = Field(..., ge=0)
    state_writes_before_call: int = Field(..., ge=0)
    state_writes_after_call: int = Field(..., ge=0)
    public_function_count: int = Field(..., ge=0)
    external_function_count: int = Field(..., ge=0)
    private_function_count: int = Field(..., ge=0)
    has_access_control_modifier: int = Field(..., ge=0, le=1)
    has_reentrancy_guard: int = Field(..., ge=0, le=1)
    uses_tx_origin: int = Field(..., ge=0, le=1)
    has_selfdestruct: int = Field(..., ge=0, le=1)
    unchecked_call_count: int = Field(..., ge=0)
    max_call_depth: int = Field(..., ge=0)
    has_cycle_with_external_call: int = Field(..., ge=0, le=1)
    external_calls_in_cycles: int = Field(..., ge=0)


class ScanResult(BaseModel):
    """Complete scan result."""
    decision: Decision = Field(..., description="Enforcement decision")
    risk_score: float = Field(..., description="Overall risk score", ge=0, le=10)
    risk_category: RiskCategory = Field(..., description="Risk classification")
    detected_vulnerabilities: List[str] = Field(
        default_factory=list,
        description="List of detected vulnerability types"
    )
    justification: str = Field(..., description="Explanation for the decision")
    recommendations: List[str] = Field(
        default_factory=list,
        description="Security recommendations"
    )
    ml_predictions: Optional[Dict[str, MLPrediction]] = Field(
        None,
        description="ML model predictions (verbose mode only)"
    )
    risk_assessment: Optional[RiskAssessment] = Field(
        None,
        description="Detailed risk breakdown (verbose mode only)"
    )
    features: Optional[SecurityFeatures] = Field(
        None,
        description="Extracted security features (verbose mode only)"
    )
    scan_time_seconds: Optional[float] = Field(
        None,
        description="Time taken to complete scan",
        ge=0
    )

    class Config:
        schema_extra = {
            "example": {
                "decision": "WARN",
                "risk_score": 5.2,
                "risk_category": "MEDIUM",
                "detected_vulnerabilities": ["reentrancy", "access_control"],
                "justification": "Risk score 5.2/10 indicates moderate risk...",
                "recommendations": [
                    "Implement checks-effects-interactions pattern",
                    "Add ReentrancyGuard modifier"
                ],
                "scan_time_seconds": 1.23
            }
        }


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(default="healthy", description="Service status")
    version: str = Field(..., description="API version")
    models_loaded: bool = Field(..., description="Whether ML models are loaded")
    timestamp: str = Field(..., description="Server timestamp")


class VersionResponse(BaseModel):
    """Version information response."""
    api_version: str = Field(..., description="API version")
    cli_version: str = Field(..., description="CLI version")
    python_version: str = Field(..., description="Python interpreter version")
    dependencies: Dict[str, str] = Field(..., description="Key dependency versions")


class ErrorResponse(BaseModel):
    """Error response model."""
    detail: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Error code for programmatic handling")
    timestamp: str = Field(..., description="Error timestamp")

    class Config:
        schema_extra = {
            "example": {
                "detail": "Invalid Solidity code provided",
                "error_code": "INVALID_INPUT",
                "timestamp": "2026-03-09T10:30:00Z"
            }
        }


class RateLimitResponse(BaseModel):
    """Rate limit information."""
    detail: str = Field(..., description="Rate limit message")
    retry_after: int = Field(..., description="Seconds until retry is allowed", ge=0)

    class Config:
        schema_extra = {
            "example": {
                "detail": "Rate limit exceeded. Please try again later.",
                "retry_after": 60
            }
        }
