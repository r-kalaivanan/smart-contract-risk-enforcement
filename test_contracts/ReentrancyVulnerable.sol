// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Classic Reentrancy Vulnerability (DAO-style)
 * @notice This contract is DELIBERATELY VULNERABLE for demonstration
 * Vulnerability: State updated AFTER external call (reentrancy attack possible)
 */
contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: State is updated AFTER external call
    // An attacker can re-enter and withdraw multiple times
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        
        // External call BEFORE state update (DANGEROUS!)
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        
        // State update happens too late - attacker can re-enter
        balances[msg.sender] = 0;
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
