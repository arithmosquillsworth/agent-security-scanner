// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// WARNING: This contract contains intentional vulnerabilities for testing
contract VulnerableAgent {
    mapping(address => uint256) public balances;
    address public owner;
    string private apiKey = "sk-test-1234567890abcdef";
    
    constructor() {
        owner = msg.sender;
    }
    
    // VULNERABLE: No access control
    function withdrawAll() external {
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
    
    // VULNERABLE: Reentrancy
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }
    
    // VULNERABLE: Prompt injection risk
    function processUserInput(string memory userInput) external pure returns (string memory) {
        string memory prompt = string(abi.encodePacked(
            "Process this user request: ",
            userInput
        ));
        return prompt;
    }
    
    // VULNERABLE: Weak randomness
    function randomWinner() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
    }
    
    // VULNERABLE: Unchecked transfer
    function transferToken(address token, address to, uint256 amount) external {
        (bool success, ) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
    }
    
    // VULNERABLE: No rate limiting
    function executeTrade(uint256 amount) external {
        // Trading logic here
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
