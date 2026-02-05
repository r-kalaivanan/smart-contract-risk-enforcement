"""
Label Generation Module

Parses vulnerabilities.json from SmartBugs dataset and generates ML labels.

Why Label Generation?
- Supervised ML requires ground truth labels
- SmartBugs provides line-level vulnerability annotations
- We convert these to binary labels per vulnerability type

Label Schema:
- reentrancy: 1 if contract has reentrancy vulnerability, else 0
- unchecked_external_call: 1 if unchecked call/send/delegatecall exists
- access_control: 1 if missing access controls (tx.origin, wrong constructor)
- dangerous_construct: 1 if tx.origin or selfdestruct present
- overall_vulnerable: 1 if ANY vulnerability exists

Output Format:
{
    "contract_name": "mycontract.sol",
    "labels": {
        "reentrancy": 1,
        "unchecked_external_call": 0,
        "access_control": 0,
        "dangerous_construct": 0,
        "overall_vulnerable": 1
    }
}
"""

import json
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass


@dataclass
class ContractLabel:
    """
    Ground truth labels for a single contract.
    
    Attributes:
        contract_name: Filename (e.g., "dao.sol")
        reentrancy: Binary label for reentrancy vulnerability
        unchecked_external_call: Binary label for unchecked calls
        access_control: Binary label for access control issues
        dangerous_construct: Binary label for tx.origin/selfdestruct
        overall_vulnerable: 1 if any vulnerability present
    """
    contract_name: str
    reentrancy: int = 0
    unchecked_external_call: int = 0
    access_control: int = 0
    dangerous_construct: int = 0
    overall_vulnerable: int = 0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "contract_name": self.contract_name,
            "labels": {
                "reentrancy": self.reentrancy,
                "unchecked_external_call": self.unchecked_external_call,
                "access_control": self.access_control,
                "dangerous_construct": self.dangerous_construct,
                "overall_vulnerable": self.overall_vulnerable,
            }
        }


class LabelGenerator:
    """
    Generates training labels from SmartBugs vulnerabilities.json.
    
    Usage:
        generator = LabelGenerator("datasets/smartbugs-curated/vulnerabilities.json")
        labels = generator.generate_labels()
    """
    
    # Map SmartBugs categories to our vulnerability types
    CATEGORY_MAPPING = {
        "reentrancy": "reentrancy",
        "access_control": "access_control",
        "unchecked_low_level_calls": "unchecked_external_call",
        # tx.origin and selfdestruct are in access_control in SmartBugs
        # We'll also detect them via AST analysis
    }
    
    def __init__(self, vulnerabilities_json_path: str):
        """
        Initialize label generator.
        
        Args:
            vulnerabilities_json_path: Path to vulnerabilities.json from SmartBugs
        """
        self.vulnerabilities_path = Path(vulnerabilities_json_path)
        self.data = None
        
    def load_vulnerabilities(self) -> List[Dict]:
        """
        Load vulnerabilities.json.
        
        Returns:
            List of contract vulnerability records
        """
        with open(self.vulnerabilities_path, 'r') as f:
            self.data = json.load(f)
        return self.data
    
    def generate_labels(self) -> List[ContractLabel]:
        """
        Generate binary labels for all contracts.
        
        Returns:
            List of ContractLabel objects
        """
        if self.data is None:
            self.load_vulnerabilities()
        
        labels = []
        for contract_record in self.data:
            label = self._create_label_for_contract(contract_record)
            labels.append(label)
        
        return labels
    
    def _create_label_for_contract(self, record: Dict) -> ContractLabel:
        """
        Create label object for a single contract.
        
        Args:
            record: Single contract record from vulnerabilities.json
            
        Returns:
            ContractLabel with binary labels
        """
        label = ContractLabel(contract_name=record["name"])
        
        # Parse vulnerabilities list
        for vuln in record.get("vulnerabilities", []):
            category = vuln.get("category", "")
            
            # Map to our vulnerability types
            if category == "reentrancy":
                label.reentrancy = 1
            elif category == "access_control":
                label.access_control = 1
                # Check if it's specifically tx.origin or selfdestruct
                # (This requires additional AST analysis in practice)
            elif category == "unchecked_low_level_calls":
                label.unchecked_external_call = 1
        
        # Set overall vulnerable flag
        label.overall_vulnerable = int(
            label.reentrancy or 
            label.unchecked_external_call or 
            label.access_control or 
            label.dangerous_construct
        )
        
        return label
    
    def save_labels(self, output_path: str):
        """
        Save generated labels to JSON file.
        
        Args:
            output_path: Path to save labels.json
        """
        labels = self.generate_labels()
        output_data = [label.to_dict() for label in labels]
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"[LabelGenerator] Saved {len(labels)} labels to {output_path}")
