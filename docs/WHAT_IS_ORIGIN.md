# Origin Protocol

## Definition

Origin is a cryptographic provenance primitive.

It creates a self-contained, verifiable statement that binds:

* an artifact hash
* a public key
* a signature

into a portable proof of authorship or responsibility.

Verification is deterministic, offline, and requires no external service.

## Protocol Guarantee

Origin answers exactly one question:

"Did the holder of this public key create or endorse this exact artifact?"

If the signature verifies, the statement is authentic.

If the artifact changes, verification fails.

## Protocol Scope

Origin provides:

* Integrity
* Authenticity
* Provenance evidence
* Offline verification
* Deterministic verification
* Auditable evidence

## Protocol Non-Goals

Origin does not provide:

* Identity
* Trust
* Reputation
* Key discovery
* Key distribution
* Revocation
* Delegation
* Authorization
* Timestamp authority
* Certificate authorities
* Blockchain consensus
* Software supply-chain policy
* Artifact storage
* Encryption
* Compression
* Networking

## Ecosystem Boundary

Origin is not a supply-chain framework.

Origin is not an identity system.

Origin is not a trust network.

Origin is not a governance layer.

Origin is the primitive upon which those systems may be built.

## Design Principle

The protocol should remain as small as possible.

Any capability that can exist outside the primitive should remain outside the primitive.

Complexity belongs in the ecosystem, not in Origin itself.
