# Trust Model

## What the Verifier Trusts

1. **Ed25519 signature scheme**. The security of the protocol rests on the existential unforgeability of Ed25519 (Edwards-curve Digital Signature Algorithm) under the RFC 8032 specification.

2. **SHA-256 hash function**. Artifact integrity rests on the collision resistance and second-preimage resistance of SHA-256.

3. **The Rust implementation of ed25519-dalek**. We rely on the `ed25519-dalek` library, which has undergone formal verification of its curve arithmetic and uses constant-time operations.

4. **The public key supplied to verification**. The verifier must obtain the trusted public key through an external channel. The protocol does not distribute, verify, or authenticate public keys.

## What the Verifier Does NOT Trust

1. **The timestamp**. Timestamps are self-asserted by the signer. The verifier only checks that the timestamp is a well-formed non-negative integer within an acceptable range. There is no mechanism to verify that the timestamp reflects "real" time.

2. **The signer's identity**. The public key identifies the signer cryptographically, but the protocol does not map keys to real-world identities. An attestation proves "key X signed this," not "person Y signed this."

3. **The artifact contents**. The protocol hashes the artifact. It does not inspect, validate, or attest to the artifact's safety, correctness, or quality.

4. **Any external infrastructure**. No network calls, certificate authorities, timestamp authorities, or key servers are consulted during verification.

5. **The statement file's path or filename**. The protocol operates on bytes, not filesystem metadata. A statement is valid regardless of its filename, directory, or storage medium.

## Trust Boundaries

```
Signer's environment
│
│   Ed25519 secret key
│   Timestamp (self-asserted)
│   Artifact bytes
│   ↓
├── Statement (signed canonical body)
│   └── Transmitted over any channel
│       ↓
Verifier's environment
│
│   Artifact bytes (may differ from signer's)
│   Trusted public key (obtained externally)
│   ↓
└── VERIFIED / FAILED
```

## Implications

- A compromised signing key cannot be revoked at the protocol level. Stop trusting statements signed after the compromise date.
- A dishonest signer can lie about timestamps. This is by design. Timestamp verification is a separate problem.
- A verifier who trusts the wrong public key will accept false statements. Key distribution is the verifier's responsibility.

> Copyright (c) 2026 Origin Protocol. MIT licensed.
