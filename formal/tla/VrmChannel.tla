---- MODULE VrmChannel ----
EXTENDS Naturals

CONSTANT MaxBalance

VARIABLES balanceA, balanceB, nonce

vars == <<balanceA, balanceB, nonce>>

Init ==
    /\ balanceA = 0
    /\ balanceB = 0
    /\ nonce = 0

TypeOK ==
    /\ balanceA \in 0..MaxBalance
    /\ balanceB \in 0..MaxBalance
    /\ nonce \in 0..1000000

DepositA(amount) ==
    /\ balanceA + amount <= MaxBalance
    /\ balanceA' = balanceA + amount
    /\ UNCHANGED <<balanceB, nonce>>

DepositB(amount) ==
    /\ balanceB + amount <= MaxBalance
    /\ balanceB' = balanceB + amount
    /\ UNCHANGED <<balanceA, nonce>>

Transfer(amount) ==
    /\ amount <= balanceA
    /\ balanceA' = balanceA - amount
    /\ balanceB' = balanceB + amount
    /\ nonce' = nonce + 1

Invariant ==
    balanceA + balanceB <= 2 * MaxBalance

NoOverdraft ==
    balanceA >= 0 /\ balanceB >= 0

=============================================================================
