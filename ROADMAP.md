# Origin Protocol — Build Roadmap

## Phase 0: Foundation (COMPLETE)
- [x] PROBLEM.md
- [x] PROTOCOL_VISION.md
- [x] NON_GOALS.md
- [x] TRUST_MODEL.md
- [x] THREAT_MODEL.md
- [x] RFC-0001 (protocol specification)

## Phase 1: Core Library (COMPLETE)
- [x] Ed25519 signing and verification
- [x] SHA-256 artifact hashing
- [x] Strict statement parser (5 lines, no BOM/CR/control chars)
- [x] Canonical body construction
- [x] Statement encoding and decoding
- [x] Audit output formatting
- [x] Zeroizing secret key on drop

## Phase 2: CLI (COMPLETE)
- [x] `origin hash` — compute artifact hash
- [x] `origin keygen` — generate Ed25519 key pair
- [x] `origin sign` — create provenance statement
- [x] `origin verify` — verify statement against artifact
- [x] `origin audit` — display statement fields

## Phase 3: Testing (COMPLETE)
- [x] Deterministic tests (5)
- [x] Tamper tests (9)
- [x] Negative/parse tests (27)
- [x] Adversarial/attack tests (9)
- [x] Unit tests (1)

## Phase 4: Security Audit (COMPLETE)
- [x] Threat model documented
- [x] Trust model documented
- [x] Cryptographic assumptions verified (ed25519-dalek + SHA-256)
- [x] No network, database, or external state

## Future (Post-v1)
- [ ] Language bindings (C, Python, WASM)
- [ ] Statement signing workflow (multiple signers, aggregate statements)
- [ ] Timestamp authority integration (optional RFC 3161)
- [ ] Signed key delegation (key A delegates to key B)
- [ ] FIPS 140-3 validation path
- [ ] Formal verification (ProVerif, CryptoVerif)
