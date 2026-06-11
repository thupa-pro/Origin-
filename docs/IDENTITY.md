# Identity Binding — `origin id`

The `origin id` command binds a human-readable identity string (email, domain, social handle, DID) to a public key, producing a standard `.origin` statement whose hash is the SHA-256 of the identity string.

This is **not a protocol extension** — it reuses the existing v1 statement format. The identity is the *artifact*, not a field in the statement.

## Usage

```
origin id --identity "alice@example.com" --key secret.key
```

Produces `alice@example.com.origin`:

```
origin: v1
hash: sha256:ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976
time: 1712345678
key: L8fBDyO5VtoUSNZdlpn-n8lb4eCfHcV-w-1ZSpyg50k=
sig: a3HRnYLN1zrW99xEwc6lCSwKpQsEP3oYHz639FeMNYfX2-Hw1M5-PiiRKZL9E89ofsQohKsIgSo-T66t-to7Bg==
```

## How it works

1. The identity string `"alice@example.com"` is hashed with SHA-256.
2. A standard `build_statement` call produces a `.origin` file with that hash.
3. Verification is standard `origin verify` — any v1 verifier can validate it.

The identity-claim relationship is:
- `origin id` → "Key X claims identity 'alice@example.com'"
- `origin verify alice@example.com.origin` → confirms key X made that claim

## Trust model

Identity binding does not authenticate the identity. It proves that a particular key *claims* a particular identity. Trusting that claim requires an out-of-band mechanism:

- **Key distribution**: The verifier obtains the trusted public key separately
- **Identity verification**: A separate process (e.g., email challenge, DNS record) links identity to key
- **Web of trust**: Multiple identity statements from different sources can cross-validate

## Use cases

- **Creator attribution**: `origin id --identity "artist@proton.me"`
- **Package signing**: `origin id --identity "pypi:my-package@1.0.0"`
- **Org identity**: `origin id --identity "corp.example.com"`
- **DID binding**: `origin id --identity "did:web:example.com:alice"`

## Relationship to the protocol

| Property | Value |
|----------|-------|
| Protocol change? | No — reuses v1 statement format |
| New crypto? | No — standard Ed25519 signing |
| Backward compatible? | Yes — any v1 verifier validates identity statements |
| Required for verification? | No — identity is orthogonal to provenance |
