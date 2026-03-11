// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Unchecked Call Return Value
 * @notice This contract is DELIBERATELY VULNERABLE for demonstration
 * Vulnerability: Ignoring return value of low-level call
 */
contract UncheckedCallVulnerable {
    mapping(address => uint256) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: Call return value is ignored
    // If call fails, balance is still updated
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        // DANGEROUS: Ignoring return value!
        // If this fails, user loses their balance
        msg.sender.call{value: amount}("");
    }
    
    receive() external payable {}
}
