# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| v1.1.x | ✅ Active development |
| v0.1.x | ❌ Alpha, no longer supported |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a
[GitHub Security Advisory](https://github.com/thupa-pro/Origin-/security/advisories/new).

**Do not open a public issue for security vulnerabilities.**

You can expect:
- Acknowledgement within 48 hours
- A status update within 5 business days
- A fix timeline based on severity

## Scope

The following are in scope for security reports:
- The `origin-core` library (cryptographic verification, parsing)
- The `origin-cli` binary (key management, file handling)
- The protocol specification (format, canonical body, signing procedure)

The following are out of scope:
- Third-party dependencies (report to their maintainers)
- Operating system security (file permissions, physical access)
- Social engineering attacks
- Key distribution mechanisms (external to the protocol)

## Hallmarks of a Security Issue

- A forged statement that `origin verify` accepts as valid
- A valid statement that `origin verify` rejects as invalid
- Secret key material leaked through normal operation
- A crafted input that crashes the verifier
- A crafted input that causes incorrect parsing

## Hallmarks of a Non-Issue

- "Key X signed artifact Y" when key X is compromised — key distribution is external
- Timestamp is inaccurate — timestamps are self-asserted by design
- A statement works on one machine but not another — check byte-for-byte identity
