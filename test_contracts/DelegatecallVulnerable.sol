// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Dangerous Delegatecall
 * @notice This contract is DELIBERATELY VULNERABLE for demonstration
 * Vulnerability: Unprotected delegatecall allows attacker to hijack contract
 */
contract DelegatecallVulnerable {
    address public owner;
    uint256 public value;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Anyone can call this with malicious contract address
    // Delegatecall executes in context of THIS contract
    // Attacker can change owner variable!
    function execute(address target, bytes memory data) public {
        // DANGEROUS: No access control on delegatecall!
        target.delegatecall(data);
    }
    
    function setValue(uint256 _value) public {
        require(msg.sender == owner, "Not owner");
        value = _value;
    }
}
