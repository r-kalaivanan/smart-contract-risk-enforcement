pragma solidity ^0.8.0;

/**
 * @title ComplexVulnerableContract
 * @notice Deliberately vulnerable contract to test ALL 16 feature extraction capabilities
 * 
 * Feature Coverage:
 * [0] external_call_count - Multiple call(), delegatecall(), send()
 * [1] delegatecall_count - Uses delegatecall
 * [2] send_transfer_count - Uses send() and transfer()
 * [3] state_writes_before_call - State modified before external call
 * [4] state_writes_after_call - State modified AFTER external call (reentrancy!)
 * [5] public_function_count - Public functions
 * [6] external_function_count - External functions
 * [7] private_function_count - Private helper functions
 * [8] has_access_control_modifier - onlyOwner modifier
 * [9] has_reentrancy_guard - nonReentrant modifier (present but not used everywhere)
 * [10] uses_tx_origin - Uses tx.origin (phishing vulnerable)
 * [11] has_selfdestruct - Contains selfdestruct
 * [12] unchecked_call_count - Ignores return values
 * [13] max_call_depth - Internal function call chains
 * [14] has_cycle_with_external_call - Recursive pattern with external call
 * [15] external_calls_in_cycles - External calls within recursive functions
 */
contract ComplexVulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    address public delegate;
    bool private locked;
    
    // Feature [8]: Access control modifier
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // Feature [9]: Reentrancy guard
    modifier nonReentrant() {
        require(!locked, "No reentrancy");
        locked = true;
        _;
        locked = false;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    // Feature [5]: Public function with multiple features
    // Features [0,3,4]: External call with state writes before AND after
    function vulnerableWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Feature [3]: State write BEFORE external call (good pattern)
        uint256 oldBalance = balances[msg.sender];
        
        // Feature [0,12]: External call (unchecked)
        (bool success, ) = msg.sender.call{value: amount}("");
        
        // Feature [4]: State write AFTER external call (VULNERABLE!)
        if (success) {
            balances[msg.sender] -= amount;
        }
    }
    
    // Feature [6]: External function
    // Feature [13]: Calls internal helper (call depth)
    function deposit() external payable {
        _updateBalance(msg.sender, msg.value);
    }
    
    // Feature [5]: Public function with delegatecall
    // Feature [1]: delegatecall usage (dangerous!)
    function executeDelegateCall(bytes memory data) public {
        // Feature [1,0,12]: Delegatecall (unchecked)
        delegate.delegatecall(data);
    }
    
    // Feature [5,8]: Public function with access control
    // Feature [2]: Uses send (safer than call)
    function adminWithdraw(address payable recipient, uint256 amount) public onlyOwner {
        // Feature [2,0,12]: Send (unchecked)
        recipient.send(amount);
    }
    
    // Feature [6]: External function with transfer
    // Feature [2]: Uses transfer
    function safeWithdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        
        // Feature [2]: transfer (safe)
        payable(msg.sender).transfer(amount);
    }
    
    // Feature [5,10]: Public function using tx.origin (VULNERABLE!)
    function authWithTxOrigin() public {
        // Feature [10]: tx.origin authentication (phishing vulnerable!)
        require(tx.origin == owner, "Not authorized");
        // Do something privileged
    }
    
    // Feature [5,11]: Public function with selfdestruct
    function destroy() public onlyOwner {
        // Feature [11]: selfdestruct present
        selfdestruct(payable(owner));
    }
    
    // Feature [7]: Private helper function
    // Feature [13]: Creates call depth (deposit -> _updateBalance)
    function _updateBalance(address user, uint256 amount) private {
        balances[user] += amount;
        _validateBalance(user);
    }
    
    // Feature [7]: Another private helper
    // Feature [13]: Further call depth (deposit -> _updateBalance -> _validateBalance)
    function _validateBalance(address user) private view {
        require(balances[user] <= 1000 ether, "Balance too high");
    }
    
    // Feature [14,15]: Recursive function with external call (creates cycle)
    // This creates a cycle in call graph with external call present
    function recursiveWithdraw(uint256 amount, uint256 iterations) public {
        if (iterations == 0) return;
        
        // Feature [15]: External call in recursive function (cycle)
        if (balances[msg.sender] >= amount) {
            // Feature [0,12]: Unchecked call
            msg.sender.call{value: amount}("");
            
            // Feature [4]: State write after call (reentrancy!)
            balances[msg.sender] -= amount;
        }
        
        // Feature [14]: Recursive call creates cycle
        recursiveWithdraw(amount, iterations - 1);
    }
    
    // Feature [5]: Public function with multiple external calls
    // Feature [0]: Multiple external calls in one function
    function multipleExternalCalls(address payable target1, address payable target2) public {
        // Feature [0,12]: First unchecked call
        target1.call{value: 1 ether}("");
        
        // Feature [0,12]: Second unchecked call
        target2.call{value: 1 ether}("");
        
        // Feature [0,12]: Third unchecked call
        target1.call{value: 1 ether}("");
    }
    
    // Feature [6]: External function with complex call chain
    // Feature [13]: Deep call chain
    function complexOperation() external {
        _helperLevel1();
    }
    
    // Feature [7,13]: Private helper level 1
    function _helperLevel1() private {
        _helperLevel2();
    }
    
    // Feature [7,13]: Private helper level 2
    function _helperLevel2() private {
        _helperLevel3();
    }
    
    // Feature [7,13]: Private helper level 3
    function _helperLevel3() private {
        // Deep call chain: complexOperation -> _helperLevel1 -> _helperLevel2 -> _helperLevel3
        // Max depth should be 3
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
