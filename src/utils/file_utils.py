"""
File Utilities

Helper functions for file handling and validation.
"""

from pathlib import Path
from typing import List
import re


def find_solidity_files(directory: Path, recursive: bool = False) -> List[Path]:
    """
    Find all Solidity files in a directory.
    
    Args:
        directory: Directory to search
        recursive: Whether to search subdirectories
        
    Returns:
        List of .sol file paths
    """
    pattern = "**/*.sol" if recursive else "*.sol"
    return list(directory.glob(pattern))


def extract_solidity_version(contract_path: Path) -> str:
    """
    Extract Solidity version from pragma statement.
    
    Args:
        contract_path: Path to .sol file
        
    Returns:
        Solidity version (e.g., "0.8.0") or "unknown"
    """
    try:
        with open(contract_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Match: pragma solidity ^0.8.0;
        match = re.search(r'pragma\s+solidity\s+[\^>=<]*([0-9.]+)', content)
        if match:
            return match.group(1)
    except:
        pass
    
    return "unknown"


def validate_contract_file(contract_path: Path) -> bool:
    """
    Validate that file is a Solidity contract.
    
    Args:
        contract_path: Path to check
        
    Returns:
        True if valid, False otherwise
    """
    if not contract_path.exists():
        return False
    
    if not contract_path.suffix == '.sol':
        return False
    
    if contract_path.stat().st_size == 0:
        return False
    
    return True
