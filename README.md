[![CI](https://github.com/thupa-pro/Origin/actions/workflows/ci.yml/badge.svg)](https://github.com/thupa-pro/Origin/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Version](https://img.shields.io/github/v/tag/thupa-pro/Origin)](https://github.com/thupa-pro/Origin/tags)
[![MSRV](https://img.shields.io/badge/rust-1.85%2B-purple)](rust-toolchain.toml)

# Origin — Cryptographic Provenance for Digital Artifacts

**One file. One command. Zero infrastructure.**

Origin is the smallest possible protocol for cryptographically verifiable digital provenance. It binds an artifact hash, a public key, and a timestamp into a self-contained signed statement. Anyone can verify — offline, instantly, with no dependencies.

---

## The Problem

You download a binary, open a dataset, or pull a container image. How do you know it's really from the author? Checksums prove integrity but not origin. GPG is powerful but painful. Sigstore needs network and identity. Most people don't bother with any of it.

Origin answers one question with a single command: **"Did key X sign artifact Y?"**

---

## Quick Install

```bash
# From source (Rust 1.85+)
cargo install origin-cli

# Linux binary (x86-64)
curl -sL https://github.com/thupa-pro/Origin/releases/latest/download/origin-linux-x86_64.gz | gunzip > origin
chmod +x origin && sudo mv origin /usr/local/bin/

# GitHub Action (for your CI pipeline)
# See .github/actions/origin-verify/action.yml
```

After install, run `origin --help` to confirm. The binary is `origin`, not `origin-cli`.

---

## One Command

```bash
origin verify release.tar.gz.origin release.tar.gz
```

Returns `VERIFIED` or `FAILED`. That's it.

---

## How Trust Works

Origin separates the cryptographic verification from the trust decision:

```
1. Alice generates a key pair           →  Alice keeps the secret key
2. Alice publishes the public key        →  On her website, social media, Keybase
3. Alice signs a file with her secret key  →  Produces file.origin
4. Bob downloads the file + .origin      →  From any channel
5. Bob gets Alice's public key           →  From her website (trusted channel)
6. Bob runs: origin verify file.origin file  →  VERIFIED
```

**The verifier must obtain the trusted public key through a separate channel.** The statement contains a public key, but a forged statement would contain a forged key. The protocol proves "key X signed artifact Y" — deciding whether to trust key X is the verifier's job.

This is the same trust model as SSH and Signal. The key is the identity.

---

## GitHub Action

Verify release artifacts in your CI pipeline:

```yaml
- uses: thupa-pro/Origin/.github/actions/origin-verify@v1.1.0
  with:
    statement: release.tar.gz.origin
    artifact: release.tar.gz
```

---

## Format

A statement is a 6-line text file. Readable by humans, parseable by any language with `split(": ")`:

```
origin: v1
type: provenance
hash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
time: 1717776000
key: 71RZ3zdJoLcAjfPiis7oxnM3K6IfHpNUrf4Da493VAY=
sig: XyZ9A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0E1f2G3h4I5j6K7l8M9n0O=
```

Six fields:

| Field | Purpose |
|---|---|
| `origin` | Protocol version (always `v1`) |
| `type` | Statement type (always `provenance`) |
| `hash` | Artifact digest with algorithm prefix |
| `time` | Self-asserted UNIX timestamp (advisory — not signed) |
| `key` | Ed25519 public key (base64url, 44 chars) |
| `sig` | Ed25519 signature (base64url, 88 chars) |

An optional `parent` field enables provenance chains (7-line format).

---

## Quickstart — 2 Minutes

### Install

```bash
cargo install origin-cli
```

Or build from source:
```bash
git clone https://github.com/thupa-pro/Origin.git
cd Origin
cargo build --release
./target/release/origin --help
```

### Generate a key pair

```bash
origin keygen
```

Produces `origin-secret.key` and `origin-public.key` in the current directory.

### Sign an artifact

```bash
origin sign myfile.tar.gz --key origin-secret.key
```

Creates `myfile.tar.gz.origin` — the provenance statement.

### Verify

```bash
origin verify myfile.tar.gz.origin myfile.tar.gz
```

Prints `VERIFIED`.

### Chain to a parent (provenance chain)

```bash
origin sign v2.0.tar.gz --key origin-secret.key --parent v1.0.tar.gz.origin
```

The `parent` field links the new statement to the previous one.

### Audit

```bash
origin audit myfile.tar.gz.origin
```

Displays all fields in human-readable form.

---

## Why Origin?

### At a Glance

| Without Origin | With Origin |
|---|---|
| You have a file and the author's claim | You have a file and a provenance statement |
| No way to verify cryptographically | `origin verify file.origin file` |
| Trust the download channel | Trust only the public key (distributed separately) |

### Full Comparison

| Need | GPG | Sigstore | in-toto | **Origin** |
|---|---|---|---|---|
| Offline verification | ✅ | ❌ | ✅ | **✅** |
| Self-contained statement | ❌ (detached sig) | ❌ (3 services) | ❌ (layout) | **✅** |
| Deterministic output | ❌ (random nonces) | ❌ | ✅ | **✅** |
| Single command verify | ❌ (keyring + trust) | ❌ (cosign + rekor) | ❌ | **✅** |
| Zero infrastructure | ❌ (key server) | ❌ (Fulcio + Rekor) | ✅ | **✅** |
| Any artifact type | ✅ | ✅ | ✅ | **✅** |
| Timestamp (advisory) | ✅ | ✅ | ❌ | **✅** |

**Origin uniquely contributes:** The only system that is simultaneously offline, self-contained, artifact-agnostic, single-command verifiable, and key-infrastructure-free.

---

## Commands

| Command | Purpose |
|---|---|
| `origin hash <path>` | Print the SHA-256 hash of a file |
| `origin keygen [--output <dir>]` | Generate an Ed25519 key pair |
| `origin sign <path> --key <file>` | Sign an artifact, produce a `.origin` statement |
| `origin verify <statement> <artifact>` | Verify a statement against an artifact |
| `origin audit <statement>` | Display a human-readable audit |

Secret key sources (in priority): `$ORIGIN_KEY` env var > `--key <file>` > `--key -` (stdin).

---

## Commands in Detail

### `origin hash <path>`

```
$ origin hash myfile.tar.gz
sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

### `origin keygen [--output <dir>]`

```
$ origin keygen --output ~/.origin
Key pair generated:
  Secret: /home/user/.origin/origin-secret.key
  Public: /home/user/.origin/origin-public.key
  Public key: 71RZ3zdJoLcAjfPiis7oxnM3K6IfHpNUrf4Da493VAY=
```

Secret key file permissions: `0o600` on Unix.

### `origin sign <path> --key <file> [--time <ts>] [--parent <path>]`

```
$ origin sign release-v1.0.0.tar.gz --key origin-secret.key
Statement written to release-v1.0.0.tar.gz.origin

$ origin sign release-v2.0.0.tar.gz --key origin-secret.key --parent release-v1.0.0.tar.gz.origin
Statement written to release-v2.0.0.tar.gz.origin
```

### `origin verify <statement> <artifact>`

```
$ origin verify release-v1.0.0.tar.gz.origin release-v1.0.0.tar.gz
VERIFIED
```

Exit code 0 on success, 1 on failure.

### `origin audit <statement>`

```
$ origin audit release-v1.0.0.tar.gz.origin
Statement Audit
├─ Origin:  v1
├─ Hash:    sha256:ba7816bf... (SHA-256)
├─ Time:    2024-06-07T16:00:00Z (1717776000) — advisory
├─ Key:     71RZ3zdJoLcAjfPiis7oxnM3K6IfHpNUrf4Da493VAY=
└─ Sig:     XyZ9A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t...=
```

---

## Protocol

See [RFC-0001.md](RFC-0001.md) for the full specification.

Key design points:

- **One primitive**: A signed provenance statement (hash + pubkey + timestamp + sig)
- **No network**: Creation and verification are fully offline
- **No blockchain**: Statements are files, not transactions
- **No database**: The statement is the record
- **No identity system**: The public key is the identity
- **No metadata**: Cryptographic claims only — no notes, tags, or labels
- **No encryption**: Statements are public by design
- **Timestamps are advisory**: Self-asserted, not signed. Honest design.

---

## Features

| Feature | Status |
|---|---|
| Ed25519 signatures | ✅ |
| SHA-256 / SHA-384 / SHA-512 | ✅ |
| Deterministic output | ✅ |
| Strict parser (66 tests) | ✅ |
| Parent field (provenance chains) | ✅ |
| Self-contained statements | ✅ |
| Secret key zeroization on drop | ✅ |
| Stdin secret key (`--key -`) | ✅ |
| `$ORIGIN_KEY` env var | ✅ |

---

## Non-Goals

| Not included | Why |
|---|---|
| Blockchain / ledger | Not a consensus protocol |
| Token / cryptocurrency | Not an economic protocol |
| Identity verification | Not an identity system |
| Key distribution | Verifier supplies the key externally |
| Timestamp authority | Timestamps are self-asserted |
| Revocation | Statements are immutable by design |
| Encryption | Provenance is a public claim |
| Expiration | Trust is the verifier's decision |
| Multi-signature | Each statement has one signer |

---

## Security

- **Signatures**: Ed25519 via `ed25519-dalek` (audited, constant-time, formally verified curve ops)
- **Hashing**: SHA-2 family (FIPS 180-4 compliant)
- **Key erasure**: Secret key zeroized on drop via `zeroize` crate
- **Parser**: Strict validation — no BOM, no CR, no control chars, no null bytes, no duplicate keys, no wrong-length fields
- **Test coverage**: 66 tests (deterministic, tamper, negative, adversarial)

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) and [TRUST_MODEL.md](docs/TRUST_MODEL.md) for full security analysis.

---

## Build from Source

Requires Rust 1.85+.

```bash
git clone https://github.com/thupa-pro/Origin.git
cd Origin
cargo build --release
```

To run tests:
```bash
cargo test
```

---

## Self-Verification

Origin signs its own release artifacts. Anyone can verify:

```bash
# Download the release binary and its provenance statement
curl -sLO https://github.com/thupa-pro/Origin/releases/latest/download/origin-linux-x86_64.gz
curl -sLO https://github.com/thupa-pro/Origin/releases/latest/download/origin-linux-x86_64.origin

# Download the trusted public key
curl -sLO https://raw.githubusercontent.com/thupa-pro/Origin/main/docs/origin-public.key

# Verify
origin verify origin-linux-x86_64.origin origin-linux-x86_64.gz
```

The public key (`docs/origin-public.key`) is the trust anchor. Verify it through a separate channel (Signal, personal website, social media) before relying on it.

To run tests:
```bash
cargo test
```

---

## Documentation

| Document | Description |
|---|---|
| [RFC-0001.md](RFC-0001.md) | Full protocol specification |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Attack tree and adversary capabilities |
| [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md) | What the verifier trusts and doesn't trust |
| [docs/PROBLEM.md](docs/PROBLEM.md) | The problem Origin solves |
| [docs/NON_GOALS.md](docs/NON_GOALS.md) | Explicitly excluded features |
| [docs/PROTOCOL_VISION.md](docs/PROTOCOL_VISION.md) | Long-term protocol vision |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Planned development milestones |
| [docs/REVIEW-INDEPENDENT.md](docs/REVIEW-INDEPENDENT.md) | Independent protocol review |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | Terminology reference |

---

## Status: Beta · [![Open Issues](https://img.shields.io/github/issues/thupa-pro/Origin)](https://github.com/thupa-pro/Origin/issues) [![Good First Issues](https://img.shields.io/github/issues/thupa-pro/Origin/good%20first%20issue)](https://github.com/thupa-pro/Origin/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)

Origin v1.1.0. The protocol primitive is frozen. The API is stable. The format will not break without a major version bump.

66 tests pass. Release build compiles with zero warnings.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
