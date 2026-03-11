// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title tx.origin Authentication Vulnerability
 * @notice This contract is DELIBERATELY VULNERABLE for demonstration
 * Vulnerability: Using tx.origin for authentication (phishing attack possible)
 */
contract TxOriginVulnerable {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: Uses tx.origin instead of msg.sender
    // Attacker can trick owner into calling malicious contract
    function withdraw(address payable recipient, uint256 amount) public {
        require(tx.origin == owner, "Not owner"); // WRONG! Use msg.sender
        recipient.transfer(amount);
    }
    
    receive() external payable {}
}
