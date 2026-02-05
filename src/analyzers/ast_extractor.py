"""
AST Feature Extraction Module

Extracts deterministic security features from Solidity Abstract Syntax Tree.

Why AST analysis?
- Deterministic: Same code → same features (reproducible)
- Granular: Access to exact code patterns (loops, state changes, calls)
- ML-ready: Converts code structure into numeric features

Feature Categories:
1. External Call Patterns
   - Count of call(), delegatecall(), send(), transfer()
   - Position relative to state changes (checks-effects-interactions)
   
2. State Modification Patterns
   - State writes before/after external calls (reentrancy indicator)
   - Storage vs. memory usage
   
3. Function Properties
   - Visibility (public, external, private, internal)
   - Modifiers (onlyOwner, nonReentrant, etc.)
   - Payable functions
   
4. Dangerous Constructs
   - tx.origin usage (authentication vulnerability)
   - selfdestruct presence
   - delegatecall without proper checks
"""

from typing import Dict, List
from dataclasses import dataclass, field
import numpy as np
from analyzers.graph_builder import CallGraphBuilder


@dataclass
class ContractFeatures:
    """
    Numeric feature vector for a single contract.
    
    All features are either:
    - Boolean (0/1): Presence of a pattern
    - Integer: Count of occurrences
    - Float: Normalized ratio
    
    This makes them directly usable by scikit-learn models.
    """
    # External call features
    external_call_count: int = 0
    delegatecall_count: int = 0
    send_transfer_count: int = 0
    
    # State modification features
    state_writes_before_call: int = 0
    state_writes_after_call: int = 0
    
    # Function visibility features
    public_function_count: int = 0
    external_function_count: int = 0
    private_function_count: int = 0
    
    # Modifier features
    has_access_control_modifier: bool = False
    has_reentrancy_guard: bool = False
    
    # Dangerous construct features
    uses_tx_origin: bool = False
    has_selfdestruct: bool = False
    unchecked_call_count: int = 0
    
    # Graph features (will be populated by graph_builder.py)
    max_call_depth: int = 0
    has_cycle_with_external_call: bool = False
    external_calls_in_cycles: int = 0
    
    def to_vector(self) -> np.ndarray:
        """
        Convert features to numpy array for ML training.
        
        Returns:
            1D numpy array of shape (n_features,)
        """
        return np.array([
            self.external_call_count,
            self.delegatecall_count,
            self.send_transfer_count,
            self.state_writes_before_call,
            self.state_writes_after_call,
            self.public_function_count,
            self.external_function_count,
            self.private_function_count,
            int(self.has_access_control_modifier),
            int(self.has_reentrancy_guard),
            int(self.uses_tx_origin),
            int(self.has_selfdestruct),
            self.unchecked_call_count,
            self.max_call_depth,
            int(self.has_cycle_with_external_call),
            self.external_calls_in_cycles,
        ], dtype=np.float32)
    
    @staticmethod
    def feature_names() -> List[str]:
        """Return list of feature names for model interpretation."""
        return [
            "external_call_count",
            "delegatecall_count",
            "send_transfer_count",
            "state_writes_before_call",
            "state_writes_after_call",
            "public_function_count",
            "external_function_count",
            "private_function_count",
            "has_access_control_modifier",
            "has_reentrancy_guard",
            "uses_tx_origin",
            "has_selfdestruct",
            "unchecked_call_count",
            "max_call_depth",
            "has_cycle_with_external_call",
            "external_calls_in_cycles",
        ]


class ASTFeatureExtractor:
    """
    Extracts security-relevant features from Slither's AST representation.
    
    Usage:
        extractor = ASTFeatureExtractor(slither_object)
        features = extractor.extract()
    """
    
    def __init__(self, slither_instance):
        """
        Initialize with a Slither compilation result.
        
        Args:
            slither_instance: Slither object from slither_analyzer.py
        """
        self.slither = slither_instance
        
    def extract(self) -> ContractFeatures:
        """
        Extract all features from the contract.
        
        Returns:
            ContractFeatures object with populated fields
        
        Process:
            1. Count external calls (call, delegatecall, send, transfer)
            2. Analyze state modifications around external calls
            3. Extract function visibility statistics
            4. Detect dangerous patterns (tx.origin, selfdestruct)
            5. Count modifiers (access control, reentrancy guards)
        """
        features = ContractFeatures()
        
        # Extract features from all contracts in the compilation unit
        for contract in self.slither.contracts:
            # Skip interfaces and libraries (focus on concrete contracts)
            if contract.is_interface or contract.is_library:
                continue
            
            # STEP 1: Count external calls
            call_counts = self._count_external_calls(contract)
            features.external_call_count += call_counts['external_calls']
            features.delegatecall_count += call_counts['delegatecalls']
            features.send_transfer_count += call_counts['send_transfer']
            
            # STEP 2: Analyze state modifications
            state_mods = self._analyze_state_modifications(contract)
            features.state_writes_before_call += state_mods['writes_before']
            features.state_writes_after_call += state_mods['writes_after']
            
            # STEP 3: Extract function properties
            func_props = self._extract_function_properties(contract)
            features.public_function_count += func_props['public']
            features.external_function_count += func_props['external']
            features.private_function_count += func_props['private']
            
            # STEP 4: Detect dangerous patterns
            dangerous = self._detect_dangerous_patterns(contract)
            features.uses_tx_origin = features.uses_tx_origin or dangerous['tx_origin']
            features.has_selfdestruct = features.has_selfdestruct or dangerous['selfdestruct']
            features.unchecked_call_count += dangerous['unchecked_calls']
            
            # STEP 5: Detect security modifiers
            modifiers = self._detect_modifiers(contract)
            features.has_access_control_modifier = features.has_access_control_modifier or modifiers['access_control']
            features.has_reentrancy_guard = features.has_reentrancy_guard or modifiers['reentrancy_guard']
        
            # STEP 6: Build call graph metrics and populate graph features
            try:
                builder = CallGraphBuilder(self.slither)
                metrics = builder.analyze()
                features.max_call_depth = metrics.max_call_depth
                features.has_cycle_with_external_call = metrics.has_cycles and metrics.external_calls_in_cycles > 0
                features.external_calls_in_cycles = metrics.external_calls_in_cycles
            except Exception:
                # If graph analysis fails, keep defaults (0 / False)
                pass

            return features
    
    def _count_external_calls(self, contract) -> Dict[str, int]:
        """
        Count call, delegatecall, send, transfer occurrences.
        
        Why this matters:
        - High external call count → increased attack surface
        - delegatecall → can execute arbitrary code in caller's context
        - send/transfer → safer than raw call for ETH transfers
        
        Returns:
            Dict with counts: {'external_calls': int, 'delegatecalls': int, 'send_transfer': int}
        """
        external_calls = 0
        delegatecalls = 0
        send_transfer = 0
        
        for function in contract.functions:
            # Skip constructors and fallback functions
            if function.is_constructor or function.is_fallback:
                continue
            
            # Iterate through all internal calls and operations
            for call in function.internal_calls:
                # Check for low-level calls
                if hasattr(call, 'name'):
                    if 'call' in str(call.name).lower():
                        external_calls += 1
                    elif 'delegatecall' in str(call.name).lower():
                        delegatecalls += 1
            
            # Check for external calls
            for ext_call in function.external_calls_as_expressions:
                external_calls += 1
                
                # Check if it's send/transfer (safer patterns)
                if hasattr(ext_call, 'called') and hasattr(ext_call.called, 'member_name'):
                    member = str(ext_call.called.member_name)
                    if member in ['send', 'transfer']:
                        send_transfer += 1
                    # Check for delegatecall as member call (e.g., delegate.delegatecall(data))
                    elif 'delegatecall' in member.lower():
                        delegatecalls += 1
            
            # Check for high-level calls
            for high_call in function.high_level_calls:
                # high_call is a tuple (contract, function)
                if len(high_call) >= 2:
                    called_func = high_call[1]
                    if hasattr(called_func, 'name'):
                        if 'delegatecall' in str(called_func.name):
                            delegatecalls += 1
            
            # Check for low-level calls in expressions (additional check)
            if hasattr(function, 'calls_as_expression'):
                for call_expr in function.calls_as_expression:
                    call_str = str(call_expr).lower()
                    if 'delegatecall' in call_str:
                        delegatecalls += 1
        
        return {
            'external_calls': external_calls,
            'delegatecalls': delegatecalls,
            'send_transfer': send_transfer
        }
    
    def _analyze_state_modifications(self, contract) -> Dict[str, int]:
        """
        Detect state writes before/after external calls.
        
        Why this matters:
        - State writes BEFORE external calls → Checks-Effects-Interactions pattern (SAFE)
        - State writes AFTER external calls → Reentrancy vulnerability risk (DANGEROUS)
        
        Example vulnerable pattern:
            uint balance = balances[msg.sender];
            msg.sender.call.value(balance)("");  // External call
            balances[msg.sender] = 0;            // State write AFTER call (vulnerable!)
        
        Returns:
            Dict with counts: {'writes_before': int, 'writes_after': int}
        """
        writes_before = 0
        writes_after = 0
        
        for function in contract.functions:
            if function.is_constructor or function.is_fallback:
                continue
            
            # Get all nodes in the function's control flow graph
            nodes = function.nodes if hasattr(function, 'nodes') else []
            
            # Track if we've seen an external call
            seen_external_call = False
            
            for node in nodes:
                # Check if this node contains state variable writes
                has_state_write = False
                if hasattr(node, 'state_variables_written'):
                    has_state_write = len(node.state_variables_written) > 0
                
                # Check if this node contains external calls
                has_external_call = False
                if hasattr(node, 'external_calls_as_expressions'):
                    has_external_call = len(node.external_calls_as_expressions) > 0
                if hasattr(node, 'high_level_calls'):
                    has_external_call = has_external_call or len(node.high_level_calls) > 0
                
                # Count state writes relative to external calls
                if has_state_write:
                    if seen_external_call:
                        writes_after += len(node.state_variables_written)
                    else:
                        writes_before += len(node.state_variables_written)
                
                # Update external call flag
                if has_external_call:
                    seen_external_call = True
        
        return {
            'writes_before': writes_before,
            'writes_after': writes_after
        }
    
    def _extract_function_properties(self, contract) -> Dict:
        """
        Extract visibility and modifier information.
        
        Why this matters:
        - Public/external functions → larger attack surface
        - Private/internal functions → reduced attack surface
        - Proper visibility reduces accidental exposure
        
        Returns:
            Dict with counts: {'public': int, 'external': int, 'private': int}
        """
        public = 0
        external = 0
        private = 0
        
        for function in contract.functions:
            # Skip constructors and special functions
            if function.is_constructor or function.is_fallback or function.is_receive:
                continue
            
            visibility = str(function.visibility)
            
            if visibility == 'public':
                public += 1
            elif visibility == 'external':
                external += 1
            elif visibility == 'private':
                private += 1
            # Note: 'internal' functions are not counted (less relevant for external attacks)
        
        return {
            'public': public,
            'external': external,
            'private': private
        }
    
    def _detect_dangerous_patterns(self, contract) -> Dict[str, bool]:
        """
        Detect tx.origin, selfdestruct, unchecked calls.
        
        Why these are dangerous:
        - tx.origin: Vulnerable to phishing attacks (should use msg.sender)
        - selfdestruct: Can destroy contract permanently
        - unchecked calls: Ignoring return values can hide failures
        
        Returns:
            Dict: {'tx_origin': bool, 'selfdestruct': bool, 'unchecked_calls': int}
        """
        uses_tx_origin = False
        has_selfdestruct = False
        unchecked_calls = 0
        
        for function in contract.functions:
            # Check for tx.origin usage
            if hasattr(function, 'solidity_variables_read'):
                for var in function.solidity_variables_read:
                    if hasattr(var, 'name') and 'tx.origin' in str(var.name):
                        uses_tx_origin = True
            
            # Check for selfdestruct/suicide calls
            for call in function.internal_calls:
                if hasattr(call, 'name'):
                    call_name = str(call.name).lower()
                    if 'selfdestruct' in call_name or 'suicide' in call_name:
                        has_selfdestruct = True
            
            # Check solidity_calls for selfdestruct (built-in function)
            if hasattr(function, 'solidity_calls'):
                for call in function.solidity_calls:
                    call_str = str(call).lower()
                    if 'selfdestruct' in call_str or 'suicide' in call_str:
                        has_selfdestruct = True
            
            # Check all nodes for selfdestruct in expressions
            for node in (function.nodes if hasattr(function, 'nodes') else []):
                if hasattr(node, 'expression'):
                    expr_str = str(node.expression).lower()
                    if 'selfdestruct' in expr_str or 'suicide' in expr_str:
                        has_selfdestruct = True
            
            # Check for unchecked low-level calls
            # A call is unchecked if its return value is not used
            for node in (function.nodes if hasattr(function, 'nodes') else []):
                if hasattr(node, 'calls_as_expression'):
                    for call in node.calls_as_expression:
                        # Check if call result is assigned or checked
                        if hasattr(node, 'expression') and hasattr(node.expression, 'type'):
                            expr_type = str(node.expression.type)
                            # If expression type is not an assignment/condition, call is unchecked
                            if 'call' in str(call).lower() and 'Assignment' not in expr_type:
                                unchecked_calls += 1
        
        return {
            'tx_origin': uses_tx_origin,
            'selfdestruct': has_selfdestruct,
            'unchecked_calls': unchecked_calls
        }
    
    def _detect_modifiers(self, contract) -> Dict[str, bool]:
        """
        Detect security modifiers (access control, reentrancy guards).
        
        Why this matters:
        - Access control modifiers (onlyOwner, onlyAdmin) → prevent unauthorized access
        - Reentrancy guards (nonReentrant, noReentrancy) → prevent reentrancy attacks
        
        Common patterns:
        - onlyOwner, onlyAdmin, onlyRole → access control
        - nonReentrant, noReentrancy, mutex → reentrancy protection
        
        Returns:
            Dict: {'access_control': bool, 'reentrancy_guard': bool}
        """
        has_access_control = False
        has_reentrancy_guard = False
        
        # Check all modifiers in the contract
        for modifier in contract.modifiers:
            modifier_name = str(modifier.name).lower()
            
            # Access control patterns
            if any(pattern in modifier_name for pattern in ['only', 'require', 'auth', 'admin', 'owner']):
                has_access_control = True
            
            # Reentrancy guard patterns
            if any(pattern in modifier_name for pattern in ['nonreentrant', 'noreentrancy', 'mutex', 'lock', 'guard']):
                has_reentrancy_guard = True
        
        return {
            'access_control': has_access_control,
            'reentrancy_guard': has_reentrancy_guard
        }
