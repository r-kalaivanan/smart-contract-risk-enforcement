// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title HighRiskMegaVulnerable
 * @notice Deliberately vulnerable contract for SC-GUARD demo purposes.
 *         DO NOT USE IN PRODUCTION.
 */
contract HighRiskMegaVulnerable {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Reentrancy: external call before state update.
    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Send failed");

        balances[msg.sender] = 0;
    }

    // Unchecked low-level call (return value ignored).
    function payoutUnchecked(address payable to, uint256 amount) external {
        to.call{value: amount}("");
    }

    // tx.origin based authorization (phishing-prone).
    function privilegedTxOriginAction() external view returns (bool) {
        return tx.origin == owner;
    }

    // User-controlled delegatecall target and calldata.
    function executeDelegate(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }

    // Anyone can trigger selfdestruct.
    function killContract() external {
        selfdestruct(payable(msg.sender));
    }

    // Additional unsafe money movement pattern to expand attack surface.
    function drainToCaller() external {
        msg.sender.call{value: address(this).balance}("");
    }
}