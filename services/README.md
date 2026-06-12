# Origin Network Services

Each subdirectory is a standalone microservice built with Rust/Axum.

| Service | Responsibility | Status |
|---------|---------------|--------|
| `ivg-indexer/` | Consent DAG & Policy Cache | 🔜 Planned |
| `ikm-resolver/` | DID Resolver & Reputation Engine | 🔜 Planned |
| `hae-verifier/` | TEE/ZK Attestation Gateway | 🔜 Planned |
| `vrm-router/` | Micro-royalty Routing Node | 🔜 Planned |
| `compliance-api/` | EU AI Act Article 53 PDF Generator | 🔜 Planned |
| `enterprise-api/` | Metered, SLA-backed API Gateway | 🔜 Planned |

Each service is an independent binary. See `docs/specs/ARCHITECTURE.md`
for the system design.
