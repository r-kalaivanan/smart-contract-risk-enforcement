// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DemoVulnerable - ML Detection Showcase
 * @notice This contract contains MULTIPLE KNOWN VULNERABILITIES designed to demonstrate
 *         SC-GUARD's ML-based detection capabilities for your project presentation.
 * 
 * VULNERABILITIES INCLUDED (ML Training Pattern Matches):
 * ========================================================
 * 
 * 1. REENTRANCY (High Risk)
 *    - External call before state update
 *    - Allows attacker to drain funds
 *    - Classic DAO attack pattern
 * 
 * 2. UNCHECKED LOW-LEVEL CALLS (Medium-High Risk)
 *    - Ignoring return values of call()
 *    - Silent failures possible
 * 
 * 3. ACCESS CONTROL ISSUES (High Risk)
 *    - Missing owner checks
 *    - Unprotected critical functions
 * 
 * 4. TX.ORIGIN AUTHENTICATION (Medium Risk)
 *    - Phishing attack vulnerable
 *    - Should use msg.sender
 * 
 * ML FEATURE PROFILE (What the model sees):
 * ==========================================
 * - High external_call_count: 4+
 * - State writes after external calls: 2+
 * - Unchecked calls: 3+
 * - Uses tx.origin: true
 * - Missing access control: multiple functions
 * - Public/external functions: 6+
 * 
 * This pattern combination matches vulnerable contracts in SmartBugs training data,
 * ensuring high ML detection confidence for your demo!
 */

contract DemoVulnerable {
    
    // State variables
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => bool) public authorized;
    uint256 public totalDeposits;
    
    // Events for demo visibility
    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    
    constructor() {
        owner = msg.sender;
        authorized[msg.sender] = true;
    }
    
    // =================================================================
    // VULNERABILITY #1: CLASSIC REENTRANCY
    // =================================================================
    /**
     * @dev CRITICAL VULNERABILITY: Reentrancy Attack
     * 
     * Issue: External call happens BEFORE state update
     * Attack: Malicious contract can re-enter and withdraw multiple times
     * 
     * ML Detection Features Triggered:
     * - external_call_count: +2
     * - state_writes_after_call: +3 (CRITICAL INDICATOR)
     * - unchecked_call_count: +2
     */
    function withdrawAll() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");
        
        // DANGER: Multiple external calls BEFORE state update
        // Attacker can re-enter here!
        msg.sender.call{value: balance}("");  // Unchecked #1
        
        // More state changes after external call (worse!)
        balances[msg.sender] = 0;  // Vulnerable!
        totalDeposits -= balance;
        
        // Another external call with more state changes after
        msg.sender.call{value: 1 wei}("");  // Unchecked #2
        
        // Even more state changes
        balances[owner] += 1;
        
        emit Withdrawal(msg.sender, balance);
    }
    
    // =================================================================
    // VULNERABILITY #2: UNCHECKED CALL RETURN VALUES (Multiple instances)
    // =================================================================
    /**
     * @dev HIGH VULNERABILITY: Unchecked External Call
     * 
     * Issue: Return value of call() is completely ignored (multiple times)
     * Attack: If call fails, state still updates (user loses funds)
     * 
     * ML Detection Features Triggered:
     * - external_call_count: +3
     * - unchecked_call_count: +3
     * - state_writes_before_call: +1
     */
    function emergencyWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount;
        
        // DANGER: Multiple unchecked calls
        msg.sender.call{value: amount}("");  // Unchecked #1
        msg.sender.call{value: 1}("");       // Unchecked #2
        msg.sender.call{value: 1}("");       // Unchecked #3
        
        emit Withdrawal(msg.sender, amount);
    }
    
    /**
     * @dev MEDIUM VULNERABILITY: Batch Unchecked Calls
     * 
     * Issue: Multiple unchecked external calls
     * 
     * ML Detection Features Triggered:
     * - external_call_count: +2
     * - unchecked_call_count: +2
     */
    function transferToMultiple(address payable[] memory recipients, uint256 amount) public {
        require(balances[msg.sender] >= amount * recipients.length, "Insufficient balance");
        
        balances[msg.sender] -= amount * recipients.length;
        
        for (uint i = 0; i < recipients.length; i++) {
            // DANGER: Each call is unchecked
            recipients[i].call{value: amount}("");  // Unchecked!
        }
    }
    
    // =================================================================
    // VULNERABILITY #3: TX.ORIGIN AUTHENTICATION
    // =================================================================
    /**
     * @dev MEDIUM VULNERABILITY: tx.origin for Authentication
     * 
     * Issue: Using tx.origin instead of msg.sender
     * Attack: Phishing - trick owner into calling malicious contract
     * 
     * ML Detection Features Triggered:
     * - uses_tx_origin: true (VULNERABILITY INDICATOR)
     * - has_access_control_modifier: false (missing proper checks)
     */
    function adminWithdraw(address payable recipient, uint256 amount) public {
        // DANGER: tx.origin can be spoofed through intermediate contracts
        require(tx.origin == owner, "Not authorized");  // WRONG! Use msg.sender
        
        // Unchecked call again
        recipient.call{value: amount}("");
        
        emit Withdrawal(recipient, amount);
    }
    
    // =================================================================
    // VULNERABILITY #4: MISSING ACCESS CONTROL
    // =================================================================
    /**
     * @dev CRITICAL VULNERABILITY: No Access Control (multiple functions)
     * 
     * Issue: Anyone can call these and change critical state!
     * Attack: Steal contract ownership and funds
     * 
     * ML Detection Features Triggered:
     * - public_function_count: high
     * - Missing access control on critical functions
     */
    function changeOwner(address newOwner) public {
        // DANGER: No require(msg.sender == owner)!
        // Anyone can become owner!
        address oldOwner = owner;
        owner = newOwner;
        
        emit OwnerChanged(oldOwner, newOwner);
    }
    
    /**
     * @dev HIGH VULNERABILITY: Unprotected Authorization
     * 
     * Issue: Anyone can authorize themselves
     * 
     * ML Detection Features Triggered:
     * - public_function_count: +1
     * - Missing access control
     */
    function authorize(address user) public {
        // DANGER: No owner check!
        authorized[user] = true;
    }
    
    /**
     * @dev HIGH VULNERABILITY: Unprotected Fund Withdrawal
     * 
     * Issue: Anyone can drain the contract!
     */
    function drainFunds(address payable recipient) public {
        // DANGER: No access control!
        recipient.call{value: address(this).balance}("");
    }
    
    /**
     * @dev HIGH VULNERABILITY: Unprotected State Modification
     */
    function setBalance(address user, uint256 amount) public {
        // DANGER: Anyone can set any balance!
        balances[user] = amount;
    }
    
    // =================================================================
    // SAFE FUNCTIONS (For comparison in demo)
    // =================================================================
    
    /**
     * @dev SAFE: Deposit function (for setting up demo)
     */
    function deposit() public payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
    
    /**
     * @dev Helper: Check contract balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
    
    /**
     * @dev Helper: Check user balance
     */
    function getMyBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
    
    // Fallback to receive ETH
    receive() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
}

/**
 * EXPECTED ML DETECTION RESULTS FOR YOUR DEMO:
 * =============================================
 * 
 * Feature Vector Profile:
 * -----------------------
 * external_call_count: 6-7        (HIGH)
 * unchecked_call_count: 5-6       (VERY HIGH - Strong indicator)
 * state_writes_after_call: 1-2    (CRITICAL - Reentrancy indicator)
 * uses_tx_origin: 1 (true)        (Medium risk indicator)
 * public_function_count: 6+       (High attack surface)
 * has_access_control_modifier: 0  (Missing protection)
 * 
 * Expected ML Predictions:
 * ------------------------
 * Vulnerability Probability: 75-95%
 * Risk Level: HIGH or CRITICAL
 * Confidence Score: 80-95%
 * 
 * Primary Vulnerabilities Detected:
 * ---------------------------------
 * 1. Reentrancy (withdrawAll)
 * 2. Unchecked Call Return Values (multiple functions)
 * 3. Access Control Issues (changeOwner, authorize)
 * 4. tx.origin Authentication (adminWithdraw)
 * 
 * DEMO TALKING POINTS:
 * ====================
 * 
 * 1. "Our ML model analyzes 16 security features extracted from the contract"
 * 2. "High external call count + unchecked returns = strong vulnerability signal"
 * 3. "State modification after external calls triggers reentrancy detection"
 * 4. "tx.origin usage is a known anti-pattern detected by the model"
 * 5. "The model learned these patterns from 600+ real vulnerable contracts"
 * 6. "Combined risk score aggregates Slither findings + ML predictions"
 * 
 * This contract is PERFECT for demonstrating your hybrid approach:
 * - Slither finds specific vulnerable lines
 * - ML model assigns overall risk score based on learned patterns
 * - Risk engine combines both for comprehensive assessment
 */
