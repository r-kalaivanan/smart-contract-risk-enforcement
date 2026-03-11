// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Access Control Vulnerability (No Protection)
 * @notice This contract is DELIBERATELY VULNERABLE for demonstration
 * Vulnerability: Missing access control on critical functions
 */
contract AccessControlVulnerable {
    address public owner;
    mapping(address => uint256) public balances;
    
    constructor() {
        owner = msg.sender;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // VULNERABLE: No access control!
    // Anyone can call this and become owner
    function changeOwner(address newOwner) public {
        owner = newOwner; // DANGER: No require(msg.sender == owner)!
    }
    
    // This function should be protected but ownership can be stolen
    function withdrawAll() public {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }
}
