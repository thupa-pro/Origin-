# Origin Protocol — Vision

Origin is a cryptographic provenance protocol.

It lets a signer issue a statement that cryptographically binds a public key, a timestamp, and a digital artifact hash. Anyone can verify that statement independently, with zero infrastructure and zero network access.

## The Statement

A statement is a 5-line text file:

```
origin: v1
hash: sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
time: 1712345678
key: A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6AQ
sig: XyZ9A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6BQ
```

It says: "At this time, the holder of this public key acknowledges this artifact."

## Properties

- **Offline-first**: No network required to create or verify a statement.
- **Self-contained**: A statement contains everything needed for verification (except the artifact itself).
- **Deterministic**: Same inputs always produce the same statement.
- **Auditable**: The format is plain text. Read it with `cat`, verify it with `origin verify`.
- **Composable**: Statements are files. Pipe them, commit them, sign them again, attach them to releases.

## What Origin Is Not

- Not a blockchain
- Not an identity system
- Not a timestamping service
- Not a package manager
- Not a CI/CD platform

Origin is one primitive, well defined, available as a library and a CLI, usable anywhere someone needs to ask "where did this come from?"
