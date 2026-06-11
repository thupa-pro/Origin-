# Non-Goals

The following are explicitly out of scope for the Origin protocol.

## Infrastructure

- **No blockchain**. No ledger, no consensus, no miners, no validators, no transactions.
- **No network protocol**. No peer-to-peer, no gossip, no RPC, no HTTP API.
- **No database**. No storage layer, no index, no query engine.
- **No cloud service**. No hosted verifier, no SaaS, no dashboard.
- **No key infrastructure**. No CA, no PKI, no certificate issuance, no Web of Trust.

## Applications

- **No identity system**. No user accounts, no profiles, no authentication.
- **No marketplace**. No buying, selling, or trading artifacts.
- **No token or cryptocurrency**. No coin, no gas, no economic incentives.
- **No DAO or governance**. No voting, no proposals, no on-chain governance.
- **No AI platform**. No model registry, no dataset provenance network.

## Features

- **No revocation mechanism**. Statements are immutable. If a key is compromised, stop trusting that key.
- **No expiration**. Statements do not expire. Trust is the verifier's decision.
- **No metadata fields**. No notes, descriptions, tags, or labels. Pure cryptographic statement.
- **No key discovery**. The protocol does not help you find public keys. You must already know the key.
- **No encryption**. Statements are public by design. No confidentiality guarantees.
- **No multi-signature**. Each statement has one signer. Multiple signers produce multiple statements.
- **No chaining semantics**. Chaining is emergent: sign a statement as an artifact.

## Policy

- **No identity verification**. The protocol does not verify that a key holder is who they claim to be.
- **No timestamp authority**. Timestamps are self-asserted. No external time source is consulted.
- **No content inspection**. The protocol hashes artifacts, it does not inspect or validate their contents.

## Why These Boundaries

Every non-goal removes complexity, attack surface, and maintenance burden. The protocol is designed to be the smallest possible cryptographic primitive that provides verifiable provenance. Everything else is layered on top by the ecosystem, not the protocol.

> Copyright (c) 2026 Origin Protocol. MIT licensed.
