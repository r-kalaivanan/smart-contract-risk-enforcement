"""
Label Encoder Module

Converts SmartBugs vulnerability labels into binary ML labels.

Takes vulnerabilities.json entries and produces:
- Binary labels for 4 vulnerability types
- Compatible with Random Forest classifier
"""

from typing import Dict, List
from dataclasses import dataclass
import numpy as np


@dataclass
class ContractLabels:
    """
    Binary labels for a contract (ground truth).
    
    All labels are 0 (safe) or 1 (vulnerable).
    """
    reentrancy: int = 0
    access_control: int = 0
    unchecked_external_call: int = 0
    dangerous_construct: int = 0
    
    def to_array(self) -> np.ndarray:
        """Convert to numpy array for ML training."""
        return np.array([
            self.reentrancy,
            self.access_control,
            self.unchecked_external_call,
            self.dangerous_construct
        ], dtype=np.int32)
    
    @staticmethod
    def label_names() -> List[str]:
        """Return list of label names."""
        return [
            "reentrancy",
            "access_control",
            "unchecked_external_call",
            "dangerous_construct"
        ]


class LabelEncoder:
    """
    Encodes vulnerability labels from SmartBugs JSON format.
    
    SmartBugs Category Mapping:
        - reentrancy -> reentrancy
        - access_control -> access_control
        - unchecked_low_level_calls -> unchecked_external_call
        - arithmetic, bad_randomness, etc. -> dangerous_construct
    """
    
    # Map SmartBugs directory names to our labels
    CATEGORY_MAP = {
        'reentrancy': 'reentrancy',
        'access_control': 'access_control',
        'unchecked_low_level_calls': 'unchecked_external_call',
        'arithmetic': 'dangerous_construct',
        'bad_randomness': 'dangerous_construct',
        'denial_of_service': 'dangerous_construct',
        'front_running': 'dangerous_construct',
        'time_manipulation': 'dangerous_construct',
        'short_addresses': 'dangerous_construct',
        'other': 'dangerous_construct',
    }
    
    @staticmethod
    def encode_from_json(vuln_entry: Dict) -> ContractLabels:
        """
        Encode labels from vulnerabilities.json entry.
        
        Args:
            vuln_entry: Dict from vulnerabilities.json with 'vulnerabilities' key
            
        Returns:
            ContractLabels object
        """
        labels = ContractLabels()
        
        if not vuln_entry or 'vulnerabilities' not in vuln_entry:
            return labels
        
        # Process each vulnerability in the entry
        for vuln in vuln_entry['vulnerabilities']:
            category = vuln.get('category', '')
            
            if category == 'reentrancy':
                labels.reentrancy = 1
            elif category == 'access_control':
                labels.access_control = 1
            elif category == 'unchecked_low_level_calls':
                labels.unchecked_external_call = 1
            elif category in ['arithmetic', 'bad_randomness', 'denial_of_service',
                             'front_running', 'time_manipulation', 'short_addresses',
                             'other']:
                labels.dangerous_construct = 1
        
        return labels
    
    @staticmethod
    def encode_from_category(category: str) -> ContractLabels:
        """
        Encode labels from directory category (fallback if JSON missing).
        
        Args:
            category: Directory name (e.g., 'reentrancy', 'access_control')
            
        Returns:
            ContractLabels object
        """
        labels = ContractLabels()
        
        mapped = LabelEncoder.CATEGORY_MAP.get(category, None)
        
        if mapped == 'reentrancy':
            labels.reentrancy = 1
        elif mapped == 'access_control':
            labels.access_control = 1
        elif mapped == 'unchecked_external_call':
            labels.unchecked_external_call = 1
        elif mapped == 'dangerous_construct':
            labels.dangerous_construct = 1
        
        return labels
