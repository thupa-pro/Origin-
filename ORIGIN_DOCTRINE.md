# ORIGIN DOCTRINE — Engineering Manifesto

**Version:** 1.0.0  
**Status:** Ratified  

---

## 1. THE MISSION

Origin Network is civilizational infrastructure for cryptographic provenance.
We prove that a digital artifact existed at a point in time, bound to a
specific identity — with zero infrastructure, zero network access, and
zero trust required.

## 2. THE HOURGLASS ARCHITECTURE

```
         Applications (UI, SDKs, Dashboards)
                    │
                    ▼
         ┌─────────────────────┐
         │   .origin Statement │  ← The Narrow Waist
         └─────────────────────┘
                    │
                    ▼
         Services (IVG, HAE, VRM, IKM)
```

The protocol is the narrow waist. Everything above is an application.
Everything below is a service. The protocol knows nothing about either.

## 3. ENGINEERING PRINCIPLES

### 3.1 Cryptographic Minimalism
One signature scheme (Ed25519). One hash (SHA-256). One wire format
(256-byte fixed-width, `#[repr(C, packed)]`). Everything else is a service.

### 3.2 Zero-Trust by Default
No binary trusts its environment. No crate pulls in network I/O unless
explicitly required. The core cryptographic library compiles to WASM with
zero imports — it trusts nothing but the bytes it receives.

### 3.3 Deterministic Builds
Every build must be reproducible. The `flake.nix` pins every tool to an
exact content hash. CI must use the same hermetic environment as local
development.

### 3.4 Defense in Depth
- **Compile-time:** `#![deny(unsafe_code)]`, `#![deny(missing_docs)]`
- **Dependency-time:** `cargo-deny` blocks unpatched CVEs and copyleft
- **Test-time:** Unit + property + fuzz + formal verification
- **Audit-time:** SLSA Level 3 provenance + OpenSSF Scorecard

### 3.5 Streaming First
No artifact is ever fully loaded into memory for hashing. The CLI and
library always support `io::Read` / `io::Write` streaming. The protocol
is designed for terabyte-scale files.

## 4. WHAT WE DO NOT BUILD

See NON_GOALS.md (moved to docs/rfc/). Key items:
- No blockchain or tokens in Layer 1
- No identity system in Layer 1
- No network protocol in Layer 1
- No encryption (provenance is public by design)
- No revocation mechanism (provenance is immutable)

## 4.1 WHAT CANNOT BE PROVEN

The protocol proves a public key, timestamp, and artifact hash are bound.
It explicitly does **NOT** prove:

1. **Completeness of PoB declarations** — declared inputs may not be all inputs
2. **HCS accuracy** — Human Content Score is a heuristic, not a proof
3. **Semantic hash correctness** — model-dependent similarity is approximate
4. **Causal artistic derivation** — timestamps prove existence, not creation order
5. **Trust score accuracy** — trust scores are service-layer heuristics

### Temporal Priority Limitation

Timestamps are self-set. A fast attacker can sign publicly available content
before its actual creator. PoO timestamps prove existence at a point in time,
not creation priority. This is a fundamental limitation of self-attested
timestamps and cannot be mitigated at the protocol layer.

## 5. THE CONTRACT WITH AUDITORS

Every line of code in `crates/origin-core/` is auditable by a single
engineer in one sitting. The entire protocol fits in 8 source files and a
256-byte struct. Complexity is a vulnerability. Simplicity is security.

## 6. THE CRUCIBLE COMMITMENT

Before every release, the Omega Sentinel runs:
1. `cargo test` — all tests pass
2. `cargo clippy --all-targets -- -D warnings` — zero warnings
3. `cargo deny check` — no unpatched advisories
4. `cargo build --target wasm32-unknown-unknown` — WASM compiles
5. `node --test packages/origin-sdk/test.mjs` — SDK integration passes
6. `cargo +nightly fuzz run fuzz_parse -- -runs=100000` — fuzz passes
7. Formal model check (if applicable)
8. SLSA provenance attestation generated

A release that fails any of these is not a release.
