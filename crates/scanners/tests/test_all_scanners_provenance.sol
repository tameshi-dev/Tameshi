pragma solidity ^0.8.0;

contract ProvenanceTestContract {
    address public owner;
    mapping(address => uint256) public balances;

    // Missing access control - should be detected
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // Reentrancy vulnerability - should be detected
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] = 0;
    }

    // Unchecked return value - should be detected
    function transferTokens(address token, address to, uint256 amount) public {
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        // Not checking success
    }

    // Selfdestruct - should be detected
    function destroy() public {
        selfdestruct(payable(owner));
    }

    // tx.origin usage - should be detected
    function checkOrigin() public view returns (bool) {
        return tx.origin == owner;
    }
}
