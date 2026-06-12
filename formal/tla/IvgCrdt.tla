---- MODULE IvgCrdt ----
EXTENDS Naturals, FiniteSets

CONSTANT MaxNodes

VARIABLES entries, node

vars == <<entries, node>>

Init ==
    /\ entries = {}
    /\ node = 1

TypeOK ==
    /\ entries \subseteq [hash: 0..255, owner: 0..255, terms: 0..255]
    /\ node \in 1..MaxNodes

AddEntry(h, o, t) ==
    /\ entries' = entries \cup {[hash |-> h, owner |-> o, terms |-> t]}
    /\ UNCHANGED node

Merge(n1, n2) ==
    /\ entries' = entries \cup {e \in entries : e.owner = n1 \/ e.owner = n2}
    /\ UNCHANGED node

Invariant ==
    \A e1, e2 \in entries:
        (e1.hash = e2.hash) => (e1.owner = e2.owner)

=============================================================================
