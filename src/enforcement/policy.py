"""
Policy Enforcement Engine

Makes deployment decisions based on risk scores.

Why Enforcement?
- Academic project must demonstrate practical impact
- Risk scores alone don't prevent deployment of vulnerable contracts
- Policy-based enforcement provides clear decision + explanation

Enforcement Policies:
    Risk 0-3:  ALLOW    (Low risk, safe to deploy)
    Risk 4-6:  WARN     (Medium risk, deploy with caution)
    Risk 7-10: BLOCK    (High risk, prevent deployment)

Decision Justification:
- ALLOW: No significant vulnerabilities detected by static analysis or ML
- WARN: Moderate signals, may be false positive, human review recommended
- BLOCK: Strong evidence of critical vulnerabilities (reentrancy, access control)

Output Format:
{
    "decision": "BLOCK",
    "risk_score": 8.4,
    "risk_category": "CRITICAL",
    "justification": "High probability of reentrancy vulnerability",
    "recommendations": [
        "Implement checks-effects-interactions pattern",
        "Add ReentrancyGuard modifier",
        "Review function: withdraw()"
    ]
}
"""

from typing import Dict, List
from dataclasses import dataclass
from enum import Enum


class DeploymentDecision(Enum):
    """Deployment decision types."""
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass
class EnforcementResult:
    """
    Enforcement decision with explanation.
    
    Attributes:
        decision: ALLOW, WARN, or BLOCK
        risk_score: Overall risk score (0-10)
        risk_category: LOW, MEDIUM, HIGH, CRITICAL
        justification: Explanation of decision
        recommendations: List of remediation actions
        detected_vulnerabilities: List of specific vulnerabilities found
    """
    decision: DeploymentDecision
    risk_score: float
    risk_category: str
    justification: str
    recommendations: List[str]
    detected_vulnerabilities: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "decision": self.decision.value,
            "risk_score": round(self.risk_score, 2),
            "risk_category": self.risk_category,
            "justification": self.justification,
            "recommendations": self.recommendations,
            "detected_vulnerabilities": self.detected_vulnerabilities
        }


class PolicyEngine:
    """
    Enforces deployment policies based on risk assessment.
    
    Usage:
        engine = PolicyEngine()
        result = engine.enforce(risk_assessment)
        
        if result.decision == DeploymentDecision.BLOCK:
            print("Deployment blocked!")
            print(result.justification)
    """
    
    # Risk thresholds
    ALLOW_THRESHOLD = 3.0
    WARN_THRESHOLD = 7.0
    
    # Remediation templates
    RECOMMENDATIONS = {
        "reentrancy": [
            "Implement checks-effects-interactions pattern (update state before external calls)",
            "Add ReentrancyGuard modifier from OpenZeppelin",
            "Use transfer() instead of call() for ETH transfers",
            "Review all functions with external calls"
        ],
        "unchecked_external_call": [
            "Check return values of call(), send(), delegatecall()",
            "Use require() to handle failures explicitly",
            "Consider using OpenZeppelin's Address.sendValue()",
            "Add event logging for all external calls"
        ],
        "access_control": [
            "Add onlyOwner or role-based access control modifiers",
            "Never use tx.origin for authentication (use msg.sender)",
            "Implement OpenZeppelin's Ownable or AccessControl",
            "Review constructor naming (should match contract name)"
        ],
        "dangerous_construct": [
            "Replace tx.origin with msg.sender for authentication",
            "Remove selfdestruct() or add strict access controls",
            "Document why dangerous construct is necessary",
            "Consider alternative architectures"
        ]
    }
    
    def __init__(self):
        """Initialize policy engine."""
        pass
    
    def enforce(
        self, 
        risk_score: float,
        risk_category: str,
        vulnerability_probabilities: Dict[str, float],
        static_findings: List[str] = None
    ) -> EnforcementResult:
        """
        Make deployment decision based on risk assessment.
        
        Args:
            risk_score: Overall risk score (0-10)
            risk_category: LOW, MEDIUM, HIGH, CRITICAL
            vulnerability_probabilities: ML probabilities per vuln type
            static_findings: Optional list of Slither detector findings
            
        Returns:
            EnforcementResult with decision and explanation
        """
        # Determine decision
        if risk_score < self.ALLOW_THRESHOLD:
            decision = DeploymentDecision.ALLOW
        elif risk_score < self.WARN_THRESHOLD:
            decision = DeploymentDecision.WARN
        else:
            decision = DeploymentDecision.BLOCK
        
        # Generate justification
        justification = self._generate_justification(
            decision, 
            risk_score, 
            vulnerability_probabilities
        )
        
        # Identify detected vulnerabilities
        detected_vulns = [
            vuln_type 
            for vuln_type, prob in vulnerability_probabilities.items() 
            if prob > 0.5
        ]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(detected_vulns)
        
        return EnforcementResult(
            decision=decision,
            risk_score=risk_score,
            risk_category=risk_category,
            justification=justification,
            recommendations=recommendations,
            detected_vulnerabilities=detected_vulns
        )
    
    def _generate_justification(
        self, 
        decision: DeploymentDecision,
        risk_score: float,
        probabilities: Dict[str, float]
    ) -> str:
        """
        Generate human-readable justification.
        
        Args:
            decision: ALLOW, WARN, or BLOCK
            risk_score: Risk score
            probabilities: Vulnerability probabilities
            
        Returns:
            Justification string
        """
        if decision == DeploymentDecision.ALLOW:
            return (
                f"Risk score {risk_score:.1f}/10 is below threshold. "
                "No significant vulnerabilities detected by static analysis or ML models."
            )
        
        elif decision == DeploymentDecision.WARN:
            high_prob_vulns = [
                f"{vuln} ({prob:.0%})"
                for vuln, prob in probabilities.items()
                if prob > 0.3
            ]
            return (
                f"Risk score {risk_score:.1f}/10 indicates moderate risk. "
                f"Potential vulnerabilities: {', '.join(high_prob_vulns)}. "
                "Manual review recommended before deployment."
            )
        
        else:  # BLOCK
            critical_vulns = [
                f"{vuln} ({prob:.0%})"
                for vuln, prob in probabilities.items()
                if prob > 0.5
            ]
            return (
                f"Risk score {risk_score:.1f}/10 exceeds safety threshold. "
                f"High probability of: {', '.join(critical_vulns)}. "
                "Deployment blocked to prevent potential exploits."
            )
    
    def _generate_recommendations(self, detected_vulnerabilities: List[str]) -> List[str]:
        """
        Generate remediation recommendations.
        
        Args:
            detected_vulnerabilities: List of vulnerability types
            
        Returns:
            List of actionable recommendations
        """
        if not detected_vulnerabilities:
            return ["No specific recommendations. Continue monitoring for new vulnerabilities."]
        
        recommendations = []
        for vuln_type in detected_vulnerabilities:
            if vuln_type in self.RECOMMENDATIONS:
                recommendations.extend(self.RECOMMENDATIONS[vuln_type])
        
        # Deduplicate
        recommendations = list(dict.fromkeys(recommendations))
        
        return recommendations[:5]  # Top 5 recommendations
