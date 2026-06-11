# Threat Model

## Assets

| Asset | Description |
|---|---|
| Artifact integrity | The artifact bytes are exactly as the signer attested |
| Statement integrity | The fields of the statement are exactly as the signer produced them |
| Signature non-repudiation | The signer cannot deny having signed this canonical body |
| Verifier correctness | The verifier produces the correct result for any input |

## Adversary Capabilities

The adversary is assumed to be able to:

- Read any statement and any artifact
- Modify any statement and any artifact in transit
- Create arbitrary statements with unknown secret keys
- Observe the verifier's inputs and outputs
- Submit arbitrarily crafted inputs to the verifier

The adversary is NOT assumed to be able to:

- Break Ed25519 or SHA-256
- Access the signer's secret key (unless compromised)
- Execute arbitrary code on the verifier's machine (that is a separate threat)

## Attack Tree

```
┌──────────────────────────────────────────────────────────────┐
│  Forge provenance for an artifact                            │
├──────────────────────────────────────────────────────────────┤
│                                                              │
├─ 1. Forge a valid signature                                  │
│   └─ 1.1 Break Ed25519 (existential unforgeability)          │
│       └─ Computational infeasible (128-bit security)         │
│                                                              │
├─ 2. Reuse an existing signature with a different artifact    │
│   └─ 2.1 Find a SHA-256 collision                            │
│       └─ Computational infeasible (128-bit collision bound)  │
│                                                              │
├─ 3. Tamper with statement fields without invalidating sig    │
│   └─ 3.1 Modify any field (origin, hash, time, key)          │
│       └─ Detected: signature covers all 4 fields             │
│   └─ 3.2 Modify signature field only                         │
│       └─ Detected: signature verification fails              │
│                                                              │
├─ 4. Exploit parser to produce incorrect verification result   │
│   └─ 4.1 Inject control characters                           │
│       └─ Rejected: strict parser validates UTF-8, no CR, etc.│
│   └─ 4.2 Duplicate fields                                    │
│       └─ Rejected: parser forbids duplicates                 │
│   └─ 4.3 Reorder fields                                      │
│       └─ Rejected: strict ordering enforced                  │
│   └─ 4.4 Add extraneous fields                               │
│       └─ Rejected: exactly 5 lines enforced (extra →        │
│           TrailingContent error)                             │
│   └─ 4.5 Identity point key (all zeros)                     │
│       └─ Rejected: Ed25519 identity element rejected at      │
│           parse time with explicit Crypto error              │
│   └─ 4.6 Trailing content after final LF                    │
│       └─ Rejected: explicit TrailingContent error with       │
│           byte-level granularity                             │
│                                                              │
├─ 5. Replay a statement with a different timestamp            │
│   └─ Not an attack: timestamp is part of signed body.        │
│       If the adversary changes the timestamp, the signature   │
│       breaks. The original statement is immutable.            │
│                                                              │
├─ 6. Exploit side channels                                    │
│   └─ 6.1 Timing side channel in signature verification       │
│       └─ Mitigated: ed25519-dalek uses constant-time ops     │
│   └─ 6.2 Hash length extension attack                        │
│       └─ Not applicable: SHA-256 is not vulnerable (unlike   │
│           SHA-256/MAC constructions), and we do not use      │
│           secret-prefix or secret-suffix constructions       │
│                                                              │
└─ 7. Denial of service against verifier                       │
    └─ 7.1 Oversized input                                     │
        └─ Mitigated: bounded UTF-8 line length expectations   │
    └─ 7.2 Deeply nested or recursive input                    │
        └─ Not applicable: format is flat, no recursion        │
```

## TOCTOU (Time of Check, Time of Use)

When verifying a file on disk:

1. User reads artifact
2. User reads statement
3. Origin verifies the statement against the artifact bytes

An adversary who can modify the artifact file between step 2 and step 3 can bypass verification. This is a documented limitation of file-based verification. The core `verify` function operates on bytes, not paths, and is safe when the caller controls both byte buffers.

## Non-Threats

| Scenario | Why it is not a threat |
|---|---|
| Signer lies about the timestamp | Self-asserted by design. Trust model documents this. |
| Key is stolen/compromised | Out of protocol scope. Irreversible like a stolen SSH key. |
| Verifier trusts wrong public key | Key distribution is external to the protocol. |
| Two signers share the same key | A key is a cryptographic identity, not a person. |
| Statement is deleted | No durability guarantees. Backups are the user's responsibility. |
