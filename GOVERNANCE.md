# Governance — Origin Improvement Proposals & Stewardship

## 1. THE RFC PROCESS

All protocol changes (except security fixes) must go through the OIP
(Origin Improvement Proposal) process:

1. **Pre-Draft** — Discuss in GitHub Issues
2. **Draft** — PR with `OIP-XXXX.md` added to `docs/rfc/`
3. **Review** — 14-day comment period for stewards
4. **Ratification** — 2/3 steward approval required
5. **Implementation** — PR implementing ratified OIP
6. **Activation** — Release tagged with `oip-XXXX`

### Security Fixes
Critical security patches skip steps 1-3 but must be documented in the
commit message with `Security: CVE-XXXX-XXXX` trailer and followed by
a post-mortem OIP within 30 days.

## 2. STEWARDSHIP

| Role | Responsibility |
|------|---------------|
| Protocol Steward | Approves changes to `crates/origin-core/` |
| Services Steward | Approves changes to `services/` and `crates/origin-{ivg,hae,vrm,ikm,zk}` |
| Security Steward | Approves changes to `security/` and `formal/` |
| Infrastructure Steward | Approves changes to `infra/` and `.github/` |

Stewards are listed in `STEWARDS.md` (maintained in `docs/`).

## 3. VERSIONING

Origin follows **Protocol Versioning** (not SemVer):

| Bump | Meaning |
|------|---------|
| Minor (1.x) | Backward-compatible service additions |
| Major (2.0) | Wire format or crypto algorithm change |

The protocol version (`origin: v1`) is independent of crate versions.
The crate version tracks implementation maturity, not protocol evolution.

## 4. DAO RULES (Future)

When the Origin DAO is activated:
- OIP ratification requires `ORN` token staking
- Stewards are elected quarterly
- Treasury multisig requires 3/5 signatures
- Bug bounties paid in `ORN` via Hats Finance
