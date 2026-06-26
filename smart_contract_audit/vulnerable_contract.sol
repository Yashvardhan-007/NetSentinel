// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Demo contract with an intentional vulnerability: tx.origin misuse for auth.
contract Test {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    // Allow sending ether to the contract for testing withdrawals.
    receive() external payable {}

    function withdraw() external {
        // VULNERABLE: tx.origin is phishable and should not be used for auth.
        require(tx.origin == owner, "not owner (tx.origin)");
        (bool ok, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }
}
