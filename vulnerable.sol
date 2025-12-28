// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * INTENTIONALLY VULNERABLE CONTRACT - FOR TESTING ONLY
 * DO NOT USE IN PRODUCTION
 * 
 * This contract contains multiple vulnerabilities for demonstration:
 * 1. Reentrancy vulnerability
 * 2. Missing access control
 * 3. Unchecked external call
 * 4. Timestamp dependence
 */

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABILITY 1: Reentrancy - external call before state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update happens AFTER external call - reentrancy risk!
        balances[msg.sender] -= amount;
    }
    
    // VULNERABILITY 2: Missing access control
    function setOwner(address newOwner) public {
        // VULNERABLE: No onlyOwner modifier!
        owner = newOwner;
    }
    
    // VULNERABILITY 3: Unchecked external call
    function transfer(address payable recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // VULNERABLE: Return value not checked
        recipient.call{value: amount}("");
        
        balances[msg.sender] -= amount;
    }
    
    // VULNERABILITY 4: Timestamp dependence
    function claimReward() public {
        // VULNERABLE: Uses block.timestamp for logic
        require(block.timestamp % 2 == 0, "Can only claim on even seconds");
        
        balances[msg.sender] += 100;
    }
    
    // VULNERABILITY 5: tx.origin usage
    function withdrawAll() public {
        // VULNERABLE: Using tx.origin instead of msg.sender
        require(tx.origin == owner, "Not owner");
        
        payable(owner).transfer(address(this).balance);
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
