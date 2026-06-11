# Architecture — 1 Protocol + N Services

Origin is designed as a minimal protocol (L1) with independent services (L2–L5) layered on top. This document describes how they compose.

## Layer 1: Proof of Origin (The Protocol)

**Repository:** `origin` (this repo)  
**Crates:** `origin-core`, `origin-cli`  
**Constraints:** No network, no tokens, no identity system.  
**Format:** The 5-line `.origin` statement (see RFC-0001.md).  
**Stability:** The protocol is frozen. Only security fixes.

Layer 1 produces and verifies `.origin` files. Every other layer reads them. No layer modifies them.

## Services (L2–L5)

Each service is a separate crate, separate binary, and has its own economics.

| Service | Responsibility | Example |
|---------|---------------|---------|
| IVG (Intent-Value Graph) | Rulebook storage and lookup | "Who owns this hash? What are the terms?" |
| HAE+ (Hybrid Attestation) | ZK compliance proofs | "Prove this AI was trained on licensed data" |
| VRM (Value Routing Mesh) | Payment settlement | "Route $0.02 from OpenAI to Alice" |
| IKM (Identity & Key Management) | Key delegation, enterprise identity | "Okta syncs keys for Reuters" |

## Interface Contracts

Services communicate with L1 only through the `.origin` statement format. There is no RPC, no shared database, no protocol-level coupling.

```
                          ┌─────────────┐
                          │   .origin   │
                          │  statement  │
                          └──────┬──────┘
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                   ▼
         ┌────────┐      ┌──────────┐       ┌──────────┐
         │  IVG   │      │   HAE+   │       │   VRM    │
         └────────┘      └──────────┘       └──────────┘
```

## Repo Strategy

This is a mono-repo with workspace members. Each service gets its own subdirectory:

```
origin/
├── origin-core/       # L1 library (published)
├── origin-cli/        # L1 CLI (published)
├── origin-ivg/        # L2 (future)
├── origin-hae/        # L3 (future)
├── origin-vrm/        # L4 (future)
├── origin-ikm/        # L5 (future)
├── docs/
├── RFC-0001.md
└── README.md
```

## Economic Model

The protocol is free. Services monetize independently:

| Layer | Free? | Revenue model |
|-------|-------|---------------|
| L1 | ✅ Always free | — |
| L2 | Free for creators | Per-lookup fees for AI labs |
| L3 | Free for basic use | Enterprise SaaS ($2k–$20k/mo) |
| L4 | Free for individuals | 0.5%–1.5% transaction fee |
| L5 | Free for individuals | Enterprise SaaS ($5k–$50k/mo) |
