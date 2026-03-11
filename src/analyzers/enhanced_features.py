"""
Enhanced Feature Extractor for Better Access Control Detection

Adds 8 new features specifically designed for access control vulnerability detection.
"""

from typing import Dict, List
import numpy as np


def extract_enhanced_access_control_features(slither_instance) -> Dict[str, float]:
    """
    Extract additional features specifically for access control detection.
    
    New Features:
    1. unprotected_critical_functions: Count of critical functions without access modifiers
    2. protected_critical_functions: Count of protected critical functions
    3. delegatecall_without_protection: Delegatecall without access control
    4. tx_origin_in_auth: tx.origin used in require/modifier (very dangerous)
    5. missing_onlyowner_on_selfdestruct: selfdestruct without onlyOwner
    6. public_state_changing_functions: Public functions that modify state
    7. external_payable_functions: Payable external/public functions (entry points for ETH)
    8. missing_constructor_protection: Constructor without proper initialization
    
    Returns:
        Dict with 8 new feature values
    """
    features = {
        'unprotected_critical_functions': 0,
        'protected_critical_functions': 0,
        'delegatecall_without_protection': 0,
        'tx_origin_in_auth': 0,
        'missing_onlyowner_on_selfdestruct': 0,
        'public_state_changing_functions': 0,
        'external_payable_functions': 0,
        'missing_constructor_protection': 0,
    }
    
    for contract in slither_instance.contracts:
        if contract.is_interface or contract.is_library:
            continue
        
        # Get all modifiers defined in the contract
        access_control_modifiers = _get_access_control_modifiers(contract)
        
        for function in contract.functions:
            # Skip constructors and special functions for some checks
            if function.is_constructor:
                # Check constructor protection
                if not function.modifiers and not _has_access_check_in_body(function):
                    features['missing_constructor_protection'] += 1
                continue
            
            if function.is_fallback or function.is_receive:
                continue
            
            # Check if function is critical (modifies state, transfers ETH, or uses dangerous ops)
            is_critical = _is_critical_function(function)
            has_access_modifier = _has_access_control_modifier(function, access_control_modifiers)
            
            # Feature 1 & 2: Critical function protection
            if is_critical:
                if has_access_modifier:
                    features['protected_critical_functions'] += 1
                else:
                    features['unprotected_critical_functions'] += 1
            
            # Feature 3: Delegatecall without protection
            if _uses_delegatecall(function) and not has_access_modifier:
                features['delegatecall_without_protection'] += 1
            
            # Feature 4: tx.origin in authentication
            if _uses_tx_origin_in_auth(function):
                features['tx_origin_in_auth'] += 1
            
            # Feature 5: selfdestruct without onlyOwner
            if _uses_selfdestruct(function) and not has_access_modifier:
                features['missing_onlyowner_on_selfdestruct'] += 1
            
            # Feature 6: Public state-changing functions
            if function.visibility in ['public', 'external'] and function.state_variables_written:
                features['public_state_changing_functions'] += 1
            
            # Feature 7: External payable functions (attack entry points)
            if function.visibility in ['public', 'external'] and function.payable:
                features['external_payable_functions'] += 1
    
    return features


def _get_access_control_modifiers(contract) -> List[str]:
    """Get list of access control modifier names."""
    access_modifiers = []
    for modifier in contract.modifiers:
        name = str(modifier.name).lower()
        # Identify access control patterns
        if any(pattern in name for pattern in ['only', 'require', 'auth', 'admin', 'owner', 'restricted']):
            access_modifiers.append(modifier.name)
    return access_modifiers


def _has_access_control_modifier(function, access_control_modifiers: List[str]) -> bool:
    """Check if function has any access control modifier."""
    for modifier in function.modifiers:
        if modifier.name in access_control_modifiers:
            return True
    
    # Also check for inline require(msg.sender == owner) patterns
    return _has_access_check_in_body(function)


def _has_access_check_in_body(function) -> bool:
    """Check if function body contains access control checks."""
    # Look for require/assert statements that check msg.sender
    for node in (function.nodes if hasattr(function, 'nodes') else []):
        if hasattr(node, 'expression'):
            expr_str = str(node.expression).lower()
            # Check for common access control patterns
            if 'require' in expr_str or 'assert' in expr_str:
                if 'msg.sender' in expr_str and ('owner' in expr_str or 'admin' in expr_str):
                    return True
    return False


def _is_critical_function(function) -> bool:
    """
    Determine if a function is critical (needs access control).
    
    Critical functions:
    - Modify state variables
    - Transfer ETH (send/transfer/call with value)
    - Use selfdestruct
    - Use delegatecall
    - Change ownership
    """
    # Check if modifies state
    if function.state_variables_written:
        # Look for ownership or critical state changes
        for var in function.state_variables_written:
            var_name = str(var.name).lower()
            if any(pattern in var_name for pattern in ['owner', 'admin', 'authorized', 'balance']):
                return True
        # Any state modification with external calls is critical
        if function.external_calls_as_expressions:
            return True
    
    # Check for value transfers
    for node in (function.nodes if hasattr(function, 'nodes') else []):
        if hasattr(node, 'expression'):
            expr_str = str(node.expression).lower()
            if 'value' in expr_str or 'send' in expr_str or 'transfer' in expr_str:
                return True
    
    # Check for dangerous operations
    if _uses_selfdestruct(function) or _uses_delegatecall(function):
        return True
    
    return False


def _uses_delegatecall(function) -> bool:
    """Check if function uses delegatecall."""
    for call in function.internal_calls:
        if hasattr(call, 'name') and 'delegatecall' in str(call.name).lower():
            return True
    for call in function.external_calls_as_expressions:
        if 'delegatecall' in str(call).lower():
            return True
    return False


def _uses_tx_origin_in_auth(function) -> bool:
    """Check if tx.origin is used in authentication (very dangerous!)."""
    uses_tx_origin = False
    in_auth_context = False
    
    for node in (function.nodes if hasattr(function, 'nodes') else []):
        if hasattr(node, 'expression'):
            expr = str(node.expression).lower()
            
            # Check for tx.origin
            if 'tx.origin' in expr:
                uses_tx_origin = True
            
            # Check if in authentication context (require/assert with ==)
            if 'require' in expr or 'assert' in expr:
                if '==' in expr or 'owner' in expr or 'admin' in expr:
                    in_auth_context = True
    
    return uses_tx_origin and in_auth_context


def _uses_selfdestruct(function) -> bool:
    """Check if function uses selfdestruct/suicide."""
    for call in function.internal_calls:
        if hasattr(call, 'name'):
            name = str(call.name).lower()
            if 'selfdestruct' in name or 'suicide' in name:
                return True
    
    for node in (function.nodes if hasattr(function, 'nodes') else []):
        if hasattr(node, 'expression'):
            if 'selfdestruct' in str(node.expression).lower():
                return True
    
    return False


def create_feature_interactions(features_dict: Dict[str, float]) -> Dict[str, float]:
    """
    Create interaction features that may be more predictive.
    
    Key interactions for access control:
    - delegatecall without protection
    - tx.origin usage combined with public visibility
    - state changes without modifiers
    """
    interactions = {}
    
    # Unprotected critical operations (composite risk score)
    interactions['critical_unprotected_ratio'] = (
        features_dict.get('unprotected_critical_functions', 0) / 
        max(features_dict.get('protected_critical_functions', 0) + 
            features_dict.get('unprotected_critical_functions', 0), 1)
    )
    
    # Delegatecall risk score
    interactions['delegatecall_risk'] = (
        features_dict.get('delegatecall_without_protection', 0) * 
        features_dict.get('public_function_count', 0)
    )
    
    # Authentication vulnerability score
    interactions['auth_vulnerability_score'] = (
        features_dict.get('tx_origin_in_auth', 0) * 2 +  # Very dangerous, weight 2x
        features_dict.get('unprotected_critical_functions', 0)
    )
    
    return interactions
