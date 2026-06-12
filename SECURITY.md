# Security Policy — Origin Network

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x (L1 Protocol) | ✅ |
| < 1.0 | ❌ |

## Reporting a Vulnerability

**DO NOT file a public GitHub issue for security vulnerabilities.**

Instead, send an encrypted message to the Security Steward:

```
PGP Fingerprint: [TBD]
Email: security@origin.network
Signal: [TBD]
```

### What to Include
- Description of the vulnerability and impact
- Steps to reproduce (PoC preferred)
- Affected versions and components
- Suggested mitigation (if known)

### Response Timeline
| Timeframe | Action |
|-----------|--------|
| 24 hours | Acknowledgment of receipt |
| 5 days | Initial assessment & severity |
| 90 days | Patch release (critical) |
| 120 days | Patch release (high/medium) |

We follow **Coordinated Vulnerability Disclosure (CVD)**. We will work with
you to publish a fix before public disclosure.

## Bug Bounty

Coverage scope: `crates/origin-core/` cryptographic implementation.

| Severity | Reward |
|----------|--------|
| Critical | $50,000 |
| High | $10,000 |
| Medium | $2,000 |
| Low | $500 |

Out of scope:
- Theoretical attacks without working PoC
- Side-channel attacks requiring physical access
- Attacks on the CLI binary (not the library)
- Issues in third-party dependencies (report upstream)

## Security Features

- `#![deny(unsafe_code)]` in `origin-core`
- `verify_strict` for Ed25519 (rejects malleable signatures)
- `subtle::ConstantTimeEq` for all cryptographic comparisons
- `ZeroizeOnDrop` on all secret key types
- Streaming I/O prevents memory exhaustion
- `cargo-deny` blocks unpatched advisories in CI
