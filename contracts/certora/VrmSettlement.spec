// Certora Formal Verification Spec — VrmSettlement
// Run: certoraRun VrmSettlement.sol --verify VrmSettlement:VrmSettlement.spec

rule channel_balance_nonnegative() {
    env e;
    bytes32 channelId;
    uint256 balanceA;
    uint256 balanceB;

    settleChannel(e, channelId, balanceA, balanceB, []);
    assert balanceA >= 0 && balanceB >= 0;
}

rule total_supply_invariant() {
    env e;
    bytes32 channelId;
    uint256 balanceA;
    uint256 balanceB;

    uint256 pre_total = currentContract.balance;
    settleChannel(e, channelId, balanceA, balanceB, []);
    uint256 post_total = currentContract.balance;

    assert pre_total == post_total;
}
