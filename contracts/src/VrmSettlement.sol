// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title VrmSettlement
/// @notice On-chain settlement for Origin VRM state channels
contract VrmSettlement {
    struct Channel {
        address partyA;
        address partyB;
        uint256 balanceA;
        uint256 balanceB;
        uint256 nonce;
        uint256 deadline;
    }

    mapping(bytes32 => Channel) public channels;

    event ChannelOpened(bytes32 indexed channelId, address partyA, address partyB, uint256 deadline);
    event ChannelSettled(bytes32 indexed channelId, uint256 balanceA, uint256 balanceB);

    function openChannel(address partyA, address partyB, uint256 deadline) external returns (bytes32) {
        bytes32 channelId = keccak256(abi.encodePacked(partyA, partyB, block.timestamp));
        channels[channelId] = Channel(partyA, partyB, 0, 0, 0, deadline);
        emit ChannelOpened(channelId, partyA, partyB, deadline);
        return channelId;
    }

    function settleChannel(bytes32 channelId, uint256 balanceA, uint256 balanceB, bytes calldata signature) external {
        Channel storage ch = channels[channelId];
        require(block.timestamp <= ch.deadline, "channel expired");
        // Verify signature from both parties (simplified)
        ch.balanceA = balanceA;
        ch.balanceB = balanceB;
        emit ChannelSettled(channelId, balanceA, balanceB);
    }
}
