# Origin Network — Cryptographic Provenance Protocol

**Layer 1:** Proof of Origin — a 256-byte cryptographic statement that binds a
public key, a timestamp, and a digital artifact hash. Verify it with zero
infrastructure, zero network access, and zero trust.

```
origin: v1
hash: sha256:<64-hex-chars>
time: <unix-epoch-seconds>
key: <44-base64url-chars>
sig: <88-base64url-chars>
```

---

## Repository Structure

```
origin-network/
├── AGENTS.md                   # AI agent constitution (constraints for Copilot/Claude/Cursor)
├── ORIGIN_DOCTRINE.md          # Engineering manifesto & design philosophy
├── GOVERNANCE.md               # OIP process & stewardship rules
├── SECURITY.md                 # Vulnerability disclosure & bug bounty
├── flake.nix                   # Hermetic Nix dev shell (reproducible builds)
├── .pre-commit-config.yaml     # Git hooks: gitleaks, typos, fmt, lint
│
├── crates/                     # Rust workspace (the cryptographic core)
│   ├── origin-core/            # [no_std] 256-byte PoO, hashing, crypto (the narrow waist)
│   ├── origin-embed/           # [std] EXIF/ID3/PDF steganographic embedding
│   ├── origin-ivg/             # [std] Intent-Value Graph CRDT
│   ├── origin-hae/             # [std] Hybrid Attestation Engine (TEE/ZK)
│   ├── origin-vrm/             # [std] Value Routing Mesh (state channels)
│   ├── origin-ikm/             # [std] DID:origin method & reputation
│   ├── origin-zk/              # [std] Halo2 ZK circuits (PoB, Consent)
│   ├── origin-cli/             # [std] CLI binary (hash, sign, verify, audit)
│   └── fuzz/                   # Fuzzing corpora and targets (nightly)
│
├── packages/                   # Edge SDKs & frontends
│   ├── origin-sdk/             # TypeScript/WASM SDK (browser & Node)
│   └── origin-ml/              # Python SDK (coming soon)
│
├── services/                   # Network microservices (Rust/Axum)
├── contracts/                  # L2 settlement layer (Solidity/Foundry)
├── formal/                     # TLA+ models, Coq proofs, Kani harnesses
├── security/                   # Threat models, audit reports, SBOMs
├── infra/                      # Terraform, K8s, Docker, Grafana
├── docs/                       # Protocol specs, OIPs, integration guides
└── scripts/                    # Sentinel, automation, audit tooling
```

## Quick Start

```bash
cargo build -p origin-cli
cargo run -p origin-cli -- generate-key
cargo run -p origin-cli -- sign README.md --key origin-secret.key
cargo run -p origin-cli -- verify README.md --origin README.md.origin
```

## The Hourglass Architecture

The `.origin` format is the narrow waist. The core (`origin-core`) knows
nothing about networks, files, or identity. Everything above is an
application; everything below is a service.

```
           SDKs, CLI, Dashboards
                    │
                    ▼
         ┌─────────────────────┐
         │   .origin Statement │  ← 256 bytes, no_std, zero allocs
         └─────────────────────┘
                    │
                    ▼
      IVG · HAE · VRM · IKM · ZK
```

## Releases

### v1.0.0 — L1 Omega Masterpiece (2026-06-12)

**CRYPTOGRAPHICALLY SOUND ✅** — 150+ tests pass, 0 fail, clippy/fmt/deny clean.

| Domain | What's Proven |
|--------|--------------|
| **Wire Format** | 256 bytes, `#[repr(C, packed)]`, zero alloc, LE deterministic |
| **Side-Channel** | Timing t=0.424 (threshold 4.0), `ZeroizeOnDrop`, `ConstantTimeEq` |
| **Signature Hardening** | Malleability defeated, deterministic nonces, commitment binding |
| **Multi-Modal Hashing** | Fixed-point DCT pHash, ChaCha20 SimHash — cross-platform bit-identical |
| **Embedding Engine** | JPEG/PNG/MP3/PDF — binary-level splicing, zero re-encode (19 tests) |
| **CLI Streaming** | 50GB sparse file OOM-proof, SIGINT-safe atomic writes, miette diagnostics |
| **Structural Fuzzing** | 100K random PoO arrays, 10K corrupted statements, 67M fuzz iterations — 0 panics |
| **WASM/Node.js** | Full sign/verify roundtrip, C headers via cbindgen |

**2 protocol bugs fixed**, 9 crates, 4 SDK packages, 3 formal verification artifacts (TLA+/Coq/Kani).

## License

MIT — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy and
bug bounty program.
