"""
Configuration Module

Centralized configuration for sc-guard.
"""

import yaml
from pathlib import Path
from typing import Dict
from dataclasses import dataclass


@dataclass
class Config:
    """
    Global configuration for sc-guard.
    
    Attributes:
        models_dir: Directory containing trained ML models
        slither_timeout: Timeout for Slither analysis (seconds)
        risk_thresholds: Risk score thresholds for enforcement
        vulnerability_weights: Weights for risk calculation
    """
    models_dir: str = "models/"
    slither_timeout: int = 60
    risk_thresholds: Dict[str, float] = None
    vulnerability_weights: Dict[str, float] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.risk_thresholds is None:
            self.risk_thresholds = {
                "allow": 3.0,
                "warn": 7.0
            }
        
        if self.vulnerability_weights is None:
            self.vulnerability_weights = {
                "reentrancy": 3.0,
                "unchecked_external_call": 2.0,
                "access_control": 2.5,
                "dangerous_construct": 2.5
            }
    
    @classmethod
    def from_yaml(cls, config_path: str):
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to config.yaml
            
        Returns:
            Config instance
        """
        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
        return cls(**data)
    
    def save_yaml(self, output_path: str):
        """
        Save configuration to YAML file.
        
        Args:
            output_path: Path to save config.yaml
        """
        data = {
            "models_dir": self.models_dir,
            "slither_timeout": self.slither_timeout,
            "risk_thresholds": self.risk_thresholds,
            "vulnerability_weights": self.vulnerability_weights
        }
        
        with open(output_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)


# Default configuration
DEFAULT_CONFIG = Config()
