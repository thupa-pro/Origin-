# Changelog

## v1.1.1 — 2026-06-09

- Fuzz testing: cargo-fuzz targets for parser and verify functions
- Reproducible builds: .cargo/config.toml with remap-path-prefix, release profile with codegen-units=1, LTO=fat, strip
- Release workflow: binaries auto-signed with Origin's own key during CI
- CodeQL analysis workflow for automated security scanning
- Homebrew formula in contrib/homebrew/origin.rb
- Distroless Docker image (gcr.io/distroless/cc-debian12, USER nobody)
- Benchmarks: criterion benchmarks for parse and verify hot paths
- OpenSSF Scorecard workflow for supply-chain security assessment
- Secret scanning workflow via TruffleHog
- SBOM generation target (make sbom via cargo-cyclonedx)
- Makefile targets: fuzz, bench, sbom, tag-release, dist

## v1.1.0 — 2026-06-08

- Added `type: provenance` field for future extensibility without format breaks
- Added optional `parent:` field for provenance chaining (7-line format)
- Added hash agility: support SHA-256, SHA-384, SHA-512
- Timestamp moved OUT of canonical body — self-asserted (advisory), not signed
- CLI: `--parent` flag for `origin sign`
- Strict parser with 66 tests (deterministic, tamper, negative, adversarial)
- CI pipeline with `cargo test` and `cargo audit`
- CLI help includes usage examples for all commands
- Repository restructured with docs/, examples/, completions/
- RFC-0001.md updated to match v1.1.0 implementation

## v0.1.1-alpha — 2026-06-08

- Parent field for provenance chains
- Hash agility (sha256, sha384, sha512)
- Timestamp made advisory (format-validated, not signed)
- Independent protocol review completed (5 phases)
- 62 tests

## v0.1.0-alpha — 2026-06-07

- Initial protocol primitive
- 5-line statement format
- Ed25519 signatures via ed25519-dalek
- SHA-256 hashing
- 5 CLI commands: hash, keygen, sign, verify, audit
- 53 tests
- Spec documents: PROBLEM.md, RFC-0001.md, THREAT_MODEL.md, TRUST_MODEL.md, NON_GOALS.md
- Pushed to GitHub as alpha release
