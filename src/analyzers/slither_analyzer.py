"""
Slither Integration Module

This module integrates Slither static analysis framework to:
1. Detect vulnerabilities using Slither's built-in detectors
2. Extract contract structure (functions, modifiers, state variables)
3. Identify dangerous patterns (tx.origin, selfdestruct, delegatecall)

Why Slither?
- Industry-standard tool (Trail of Bits)
- Provides AST access + high-level abstractions
- Built-in detectors for reentrancy, access control, unchecked calls
- Python API for programmatic access
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import re


@dataclass
class VulnerabilityFinding:
    """
    Represents a single vulnerability detected by Slither.
    
    Attributes:
        type: Vulnerability category (reentrancy, access_control, etc.)
        severity: HIGH, MEDIUM, LOW
        function_name: Function containing the vulnerability
        line_number: Source code line number
        description: Human-readable explanation
    """
    type: str
    severity: str
    function_name: str
    line_number: int
    description: str


class SlitherAnalyzer:
    """
    Wrapper around Slither for vulnerability detection.
    
    Usage:
        analyzer = SlitherAnalyzer("path/to/Contract.sol")
        findings = analyzer.analyze()
    """
    
    def __init__(self, contract_path: str, solc_version: Optional[str] = None):
        """
        Initialize Slither analyzer.
        
        Args:
            contract_path: Path to Solidity contract file
            solc_version: Specific Solidity compiler version (e.g., "0.8.0")
                         If None, auto-detected from pragma statement
        """
        self.contract_path = Path(contract_path)
        self.solc_version = solc_version
        self.slither = None
    
    def _extract_pragma_version(self) -> Optional[str]:
        """
        Extract Solidity version from pragma statement.
        
        Returns:
            Recommended solc version (e.g., '0.4.25' for pragma ^0.4.0)
            None if pragma not found
        """
        try:
            content = self.contract_path.read_text(encoding='utf-8')
            # Match: pragma solidity ^0.4.2; or pragma solidity >=0.4.22 <0.9.0;
            match = re.search(r'pragma\s+solidity\s+([^;]+);', content)
            if not match:
                return None
            
            version_spec = match.group(1).strip()
            
            # Extract major.minor version
            # ^0.4.2 -> 0.4, >=0.5.0 <0.9.0 -> 0.5, 0.8.0 -> 0.8
            if '^' in version_spec:
                # ^0.4.2 -> use 0.4.25 (stable 0.4.x)
                base = version_spec.split('^')[1].strip()
                major_minor = '.'.join(base.split('.')[:2])
                # Map to recommended stable versions
                version_map = {
                    '0.4': '0.4.25',
                    '0.5': '0.5.17',
                    '0.6': '0.6.12',
                    '0.7': '0.7.6',
                    '0.8': '0.8.0'
                }
                return version_map.get(major_minor, '0.8.0')
            elif '>=' in version_spec:
                # >=0.5.0 <0.9.0 -> use lower bound
                base = version_spec.split('>=')[1].split('<')[0].strip()
                major_minor = '.'.join(base.split('.')[:2])
                version_map = {
                    '0.4': '0.4.25',
                    '0.5': '0.5.17',
                    '0.6': '0.6.12',
                    '0.7': '0.7.6',
                    '0.8': '0.8.0'
                }
                return version_map.get(major_minor, '0.8.0')
            else:
                # Exact version specified
                return version_spec.strip()
        except Exception as e:
            print(f"Warning: Could not extract pragma version: {e}")
            return None
        
    def analyze(self) -> List[VulnerabilityFinding]:
        """
        Run Slither analysis and extract vulnerability findings.
        
        Returns:
            List of VulnerabilityFinding objects
            
        Raises:
            FileNotFoundError: If contract file doesn't exist
            SlitherError: If Slither compilation fails
        """
        # STEP 1: Validate contract file exists
        if not self.contract_path.exists():
            raise FileNotFoundError(f"Contract file not found: {self.contract_path}")
        
        # STEP 2: Import Slither and run compilation
        try:
            from slither import Slither
            import subprocess
            
            # Auto-detect solc version from pragma if not specified
            if self.solc_version is None:
                detected_version = self._extract_pragma_version()
                if detected_version:
                    print(f"Auto-detected Solidity version: {detected_version}")
                    self.solc_version = detected_version
            
            # Set global solc version using solc-select if needed
            if self.solc_version:
                try:
                    print(f"Setting global Solidity compiler to: {self.solc_version}")
                    subprocess.run(['solc-select', 'use', self.solc_version], 
                                 check=True, capture_output=True, text=True)
                except subprocess.CalledProcessError as e:
                    print(f"Warning: Could not switch solc version: {e}")
            
            # Compile contract with Slither (using global solc from solc-select)
            self.slither = Slither(str(self.contract_path))
                
        except Exception as e:
            raise RuntimeError(f"Slither compilation failed: {e}")
        
        # STEP 3: Map Slither detector names to our vulnerability categories
        # Slither has 70+ detectors - we focus on our 4 vulnerability types
        DETECTOR_MAPPING = {
            # Reentrancy detectors
            'reentrancy-eth': 'reentrancy',
            'reentrancy-no-eth': 'reentrancy',
            'reentrancy-benign': 'reentrancy',
            'reentrancy-events': 'reentrancy',
            
            # Access control detectors
            'suicidal': 'access_control',  # Unprotected selfdestruct
            'arbitrary-send': 'access_control',  # Unprotected send
            'controlled-delegatecall': 'access_control',  # Unprotected delegatecall
            'tx-origin': 'dangerous_construct',  # tx.origin usage
            
            # Unchecked external call detectors
            'unchecked-send': 'unchecked_external_call',
            'unchecked-lowlevel': 'unchecked_external_call',
            'low-level-calls': 'unchecked_external_call',
            
            # Dangerous constructs
            'delegatecall-loop': 'dangerous_construct',
            'msg-value-loop': 'dangerous_construct',
        }
        
        # STEP 4: Run Slither detectors and extract findings
        findings = []
        
        # Run detectors and get results
        detector_results = self.slither.run_detectors()
        
        # Process each detector result
        for detector_result in detector_results:
            detector_name = detector_result.get('check', '')
            
            # Only process detectors we care about
            if detector_name not in DETECTOR_MAPPING:
                continue
            
            vuln_type = DETECTOR_MAPPING[detector_name]
            impact = detector_result.get('impact', 'UNKNOWN')
            description = detector_result.get('description', '')
            
            # Extract location information
            # Slither provides elements (contract, function, line numbers)
            elements = detector_result.get('elements', [])
            
            for element in elements:
                if element.get('type') == 'function':
                    function_name = element.get('name', 'unknown')
                    # Get source mapping (file:line:column)
                    source_mapping = element.get('source_mapping', {})
                    line_number = source_mapping.get('lines', [0])[0] if source_mapping.get('lines') else 0
                    
                    finding = VulnerabilityFinding(
                        type=vuln_type,
                        severity=impact,
                        function_name=function_name,
                        line_number=line_number,
                        description=description
                    )
                    findings.append(finding)
        
        # STEP 5: Deduplicate findings (same vuln in same function)
        # Keep only unique (type, function_name, line_number) combinations
        unique_findings = []
        seen = set()
        
        for finding in findings:
            key = (finding.type, finding.function_name, finding.line_number)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def get_contract_structure(self) -> Dict:
        """
        Extract contract structure for feature engineering.
        
        Returns:
            Dict containing:
                - functions: List of function names and visibility
                - state_vars: List of state variables
                - modifiers: List of modifier names
                - external_calls: Count of external calls
        """
        # STEP 1: Ensure Slither has been run
        if self.slither is None:
            raise RuntimeError("Must call analyze() before get_contract_structure()")
        
        structure = {
            'functions': [],
            'state_vars': [],
            'modifiers': [],
            'external_calls': 0
        }
        
        # STEP 2: Iterate through all contracts in the file
        # (A .sol file can have multiple contracts)
        for contract in self.slither.contracts:
            
            # Skip interfaces and libraries (focus on actual contracts)
            if contract.is_interface or contract.is_library:
                continue
            
            # STEP 3: Extract functions
            for function in contract.functions:
                func_info = {
                    'name': function.name,
                    'visibility': function.visibility,  # public, external, internal, private
                    'is_payable': function.payable,
                    'is_view': function.view or function.pure,
                    'modifiers': [str(m) for m in function.modifiers]
                }
                structure['functions'].append(func_info)
                
                # Count external calls in this function
                # Slither tracks high-level calls (call, delegatecall, send, transfer)
                structure['external_calls'] += len(function.external_calls_as_expressions)
            
            # STEP 4: Extract state variables
            for state_var in contract.state_variables:
                var_info = {
                    'name': state_var.name,
                    'type': str(state_var.type),
                    'visibility': state_var.visibility
                }
                structure['state_vars'].append(var_info)
            
            # STEP 5: Extract modifiers
            for modifier in contract.modifiers:
                structure['modifiers'].append(modifier.name)
        
        return structure
