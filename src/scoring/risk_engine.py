"""
Risk Scoring Engine

Aggregates ML probabilities into a unified 0-10 risk score.

Why Risk Scoring?
- ML outputs probabilities (0.0-1.0) for each vulnerability type
- Users need a single, interpretable number: "How risky is this contract?"
- Different vulnerabilities have different severity levels
- Risk score enables policy-based enforcement

Scoring Formula:
    risk_score = Σ (probability_i × weight_i × 10)
    
Weights (based on security impact):
- Reentrancy:             3.0  (critical: can drain funds)
- Unchecked External Call: 2.0  (high: can cause silent failures)
- Access Control:          2.5  (high: unauthorized actions)
- Dangerous Constructs:    2.5  (high: tx.origin, selfdestruct)

Normalization: Divide by sum of weights to ensure 0-10 range

Example:
    If probabilities = [0.9 (reentrancy), 0.2, 0.1, 0.0]
    risk_score = (0.9×3.0 + 0.2×2.0 + 0.1×2.5 + 0.0×2.5) / 10 × 10
               = (2.7 + 0.4 + 0.25) / 1.0 × 10
               = 3.35 × 10 = 8.4 / 10
"""

from typing import Dict, List
from dataclasses import dataclass
import numpy as np


@dataclass
class RiskAssessment:
    """
    Comprehensive risk assessment for a contract.
    
    Attributes:
        overall_risk_score: Aggregated risk (0-10)
        vulnerability_probabilities: Dict of ML probabilities per vuln type
        top_risk_factors: List of most significant risk contributors
        confidence: Model confidence (based on prediction consistency)
    """
    overall_risk_score: float
    vulnerability_probabilities: Dict[str, float]
    top_risk_factors: List[str]
    confidence: float


class RiskScoringEngine:
    """
    Converts ML predictions into risk scores.
    
    Usage:
        engine = RiskScoringEngine()
        risk = engine.calculate_risk(
            probabilities={
                "reentrancy": 0.85,
                "unchecked_external_call": 0.32,
                "access_control": 0.10,
                "dangerous_construct": 0.05
            },
            feature_importance={"has_cycle_with_external_call": 0.35, ...}
        )
        print(f"Risk Score: {risk.overall_risk_score:.1f}/10")
    """
    
    # Severity weights (tuned based on DASP10 and OWASP rankings)
    VULNERABILITY_WEIGHTS = {
        "reentrancy": 3.0,              # Critical: The DAO hack, Parity wallet
        "unchecked_external_call": 2.0,  # High: Silent failures
        "access_control": 2.5,           # High: Unauthorized control
        "dangerous_construct": 2.5       # High: tx.origin phishing, selfdestruct
    }
    
    def __init__(self):
        """Initialize risk scoring engine."""
        self.total_weight = sum(self.VULNERABILITY_WEIGHTS.values())
    
    def calculate_risk(
        self, 
        vulnerability_probabilities: Dict[str, float],
        feature_importance: Dict[str, float] = None
    ) -> RiskAssessment:
        """
        Calculate overall risk score from ML probabilities.
        
        Args:
            vulnerability_probabilities: Dict mapping vuln type to probability (0-1)
            feature_importance: Optional feature importance from Random Forest
            
        Returns:
            RiskAssessment object with risk score and explanation
        """
        # Weighted sum of probabilities
        weighted_sum = 0.0
        for vuln_type, probability in vulnerability_probabilities.items():
            weight = self.VULNERABILITY_WEIGHTS.get(vuln_type, 1.0)
            weighted_sum += probability * weight
        
        # Normalize to 0-10 scale
        risk_score = (weighted_sum / self.total_weight) * 10
        risk_score = min(max(risk_score, 0.0), 10.0)  # Clamp to [0, 10]
        
        # Identify top risk factors
        top_risks = self._identify_top_risks(
            vulnerability_probabilities,
            feature_importance
        )
        
        # Calculate confidence (based on probability variance)
        confidence = self._calculate_confidence(vulnerability_probabilities)
        
        return RiskAssessment(
            overall_risk_score=risk_score,
            vulnerability_probabilities=vulnerability_probabilities,
            top_risk_factors=top_risks,
            confidence=confidence
        )
    
    def _identify_top_risks(
        self, 
        probabilities: Dict[str, float],
        feature_importance: Dict[str, float] = None
    ) -> List[str]:
        """
        Identify the most significant risk contributors.
        
        Args:
            probabilities: Vulnerability probabilities
            feature_importance: Feature importance scores
            
        Returns:
            List of risk factors (vulnerability types + important features)
        """
        risk_factors = []
        
        # Add vulnerabilities with probability > 0.5
        for vuln_type, prob in probabilities.items():
            if prob > 0.5:
                risk_factors.append(f"{vuln_type} (prob={prob:.2f})")
        
        # Add top 3 important features
        if feature_importance:
            top_features = sorted(
                feature_importance.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:3]
            for feature, importance in top_features:
                if importance > 0.1:  # Only significant features
                    risk_factors.append(f"{feature} (importance={importance:.2f})")
        
        return risk_factors
    
    def _calculate_confidence(self, probabilities: Dict[str, float]) -> float:
        """
        Calculate model confidence based on probability distribution.
        
        High confidence = probabilities close to 0 or 1 (decisive)
        Low confidence = probabilities near 0.5 (uncertain)
        
        Args:
            probabilities: Vulnerability probabilities
            
        Returns:
            Confidence score (0-1)
        """
        if not probabilities:
            return 0.0
        
        # Distance from 0.5 (uncertainty threshold)
        distances = [abs(p - 0.5) for p in probabilities.values()]
        avg_distance = np.mean(distances)
        
        # Normalize to 0-1 (max distance is 0.5)
        confidence = avg_distance / 0.5
        
        return confidence
    
    def get_risk_category(self, risk_score: float) -> str:
        """
        Map numeric risk score to categorical risk level.
        
        Args:
            risk_score: Risk score (0-10)
            
        Returns:
            Risk category: "LOW", "MEDIUM", "HIGH", "CRITICAL"
        """
        if risk_score < 3.0:
            return "LOW"
        elif risk_score < 5.0:
            return "MEDIUM"
        elif risk_score < 7.0:
            return "HIGH"
        else:
            return "CRITICAL"
