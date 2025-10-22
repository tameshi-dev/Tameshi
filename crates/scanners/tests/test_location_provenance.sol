// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Test contract for location provenance testing
contract LocationProvenanceTest {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Function with reentrancy vulnerability at specific locations
    function vulnerableWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // External call - should be reported with location
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State modification after external call - reentrancy vulnerability
        balances[msg.sender] -= amount;
    }

    // Function with missing access control
    function dangerousSetOwner(address newOwner) public {
        owner = newOwner; // Missing onlyOwner check
    }

    // Function with unchecked return value
    function uncheckedTransfer(address token, address to, uint256 amount) public {
        // Unchecked external call
        token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
    }
}
