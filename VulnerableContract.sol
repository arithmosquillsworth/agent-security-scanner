// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public criticalValue;

    constructor() {
        owner = msg.sender;
        criticalValue = 100;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable to Reentrancy
    function withdrawReentrant(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);

        (bool success, ) = msg.sender.call{value: _amount}(""); // External call before state update
        // No check on 'success' here, leading to unchecked call as well
        // if (!success) { revert("Transfer failed"); } // Missing check

        balances[msg.sender] -= _amount; // State updated after external call
    }

    // Vulnerable to Unchecked Call
    function sendEtherUnchecked(address payable _to, uint256 _amount) public {
        // Assume _amount is validated elsewhere for simplicity
        (bool success, ) = _to.call{value: _amount}("");
        // The 'success' variable is ignored here, making it an unchecked call.
        // A robust contract would check 'success' and revert if false.
    }
    
    // Vulnerable to Bad Access Control
    function setCriticalValue(uint256 _newValue) public { // Missing onlyOwner or similar
        criticalValue = _newValue; // State modification without access control
    }

    function getCriticalValue() public view returns (uint256) {
        return criticalValue;
    }

    // A safe withdrawal function for comparison, not vulnerable to reentrancy
    function withdrawSafe(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");

        balances[msg.sender] -= _amount; // State updated before external call (Checks effect-interactions pattern)

        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed"); // Check external call result
    }
}
