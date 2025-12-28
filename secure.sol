// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * SECURE CONTRACT - Best Practices
 * 
 * This contract demonstrates secure coding practices:
 * 1. ReentrancyGuard pattern
 * 2. Proper access control
 * 3. Checks-Effects-Interactions pattern
 * 4. Checked external calls
 */

contract SecureBank {
    mapping(address => uint256) public balances;
    address public owner;
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
    
    // SECURE: Follows Checks-Effects-Interactions pattern
    function withdraw(uint256 amount) public nonReentrant {
        // Checks
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Effects (state changes BEFORE external call)
        balances[msg.sender] -= amount;
        
        // Interactions
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    // SECURE: Proper access control
    function setOwner(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Invalid address");
        owner = newOwner;
    }
    
    // SECURE: Checked external call
    function transfer(address payable recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(recipient != address(0), "Invalid recipient");
        
        balances[msg.sender] -= amount;
        
        // Check return value
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }
    
    // SECURE: No timestamp dependence
    function claimReward() public {
        // Use block number instead of timestamp
        require(block.number > 0, "Invalid block");
        
        balances[msg.sender] += 100;
    }
    
    function deposit() public payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
