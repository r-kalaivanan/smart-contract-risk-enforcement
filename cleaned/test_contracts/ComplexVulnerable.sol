pragma solidity ^0.8.0;

/**
 * @title ComplexVulnerableContract
 * @notice Deliberately vulnerable contract to test ALL 16 feature extraction capabilities
 */
contract ComplexVulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    address public delegate;
    bool private locked;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    modifier nonReentrant() {
        require(!locked, "No reentrancy");
        locked = true;
        _;
        locked = false;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    function vulnerableWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        uint256 oldBalance = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        if (success) {
            balances[msg.sender] -= amount;
        }
    }
    
    function deposit() external payable {
        _updateBalance(msg.sender, msg.value);
    }
    
    function executeDelegateCall(bytes memory data) public {
        delegate.delegatecall(data);
    }
    
    function adminWithdraw(address payable recipient, uint256 amount) public onlyOwner {
        recipient.send(amount);
    }
    
    function safeWithdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    function authWithTxOrigin() public {
        require(tx.origin == owner, "Not authorized");
    }
    
    function destroy() public onlyOwner {
        selfdestruct(payable(owner));
    }
    
    function _updateBalance(address user, uint256 amount) private {
        balances[user] += amount;
        _validateBalance(user);
    }
    
    function _validateBalance(address user) private view {
        require(balances[user] <= 1000 ether, "Balance too high");
    }
    
    function recursiveWithdraw(uint256 amount, uint256 iterations) public {
        if (iterations == 0) return;
        if (balances[msg.sender] >= amount) {
            msg.sender.call{value: amount}("");
            balances[msg.sender] -= amount;
        }
        recursiveWithdraw(amount, iterations - 1);
    }
    
    function multipleExternalCalls(address payable target1, address payable target2) public {
        target1.call{value: 1 ether}("");
        target2.call{value: 1 ether}("");
        target1.call{value: 1 ether}("");
    }
    
    function complexOperation() external {
        _helperLevel1();
    }
    
    function _helperLevel1() private {
        _helperLevel2();
    }
    
    function _helperLevel2() private {
        _helperLevel3();
    }
    
    function _helperLevel3() private {
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
