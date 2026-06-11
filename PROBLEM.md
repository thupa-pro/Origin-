# The Problem

Digital artifacts circulate without provenance.

A binary, a document, a container image, a release artifact — when you encounter one, you have no way to answer:

> Where did this come from?
> Who claims responsibility for it?
> Has it been tampered with since?

Existing solutions are:

- **Centralized** (GitHub releases, package registries, certificate authorities) — you must trust the operator
- **Heavyweight** (blockchain, PKI, notary services) — they require infrastructure, consensus, or ongoing operational cost
- **Incomplete** (checksums alone, GPG signing without binding to an artifact) — they prove integrity without provenance, or provenance without integrity

The gap is a protocol that binds an artifact to a claim, cryptographically, in a single self-contained statement that anyone can verify with no infrastructure and no trust beyond the public key.

No network. No database. No service. No token. No blockchain.

A file and a signature.

> Copyright (c) 2026 Origin Protocol. MIT licensed.
