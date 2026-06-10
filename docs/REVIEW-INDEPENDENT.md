# Independent Protocol Review — Origin v0.1.1-alpha

**Reviewer:** Independent Review Board  
**Date:** 2026-06-08  
**Against:** Origin v0.1.1-alpha (commit a349f7e)

---

## PHASE 1: FIELD REMOVAL ANALYSIS

### Can TIMESTAMP be removed?

| Aspect | Assessment |
|---|---|
| What breaks | Temporal ordering within a key's statements. Users who need sequence must add their own application-level timestamp. |
| What survives | Cryptographic binding of hash to key. The statement still proves "key X signed artifact hash Y at some unknown time." |
| Verdict | **Removable without breaking the core primitive.** The timestamp is the weakest field — self-asserted, unverifiable, adds no cryptographic strength. However, its removal forces every user to re-invent it, inconsistently and likely unsafely. **Keep it as advisory** (current design is correct). |

### Can PUBLIC KEY be removed?

| Aspect | Assessment |
|---|---|
| What breaks | Everything. Without a public key, verification is impossible — there is no identity to verify against. The statement becomes an anonymous claim forgeable by anyone. |
| What survives | The artifact hash. You can still prove "this hash was computed" — but you gain zero provenance value. |
| Verdict | **Not removable.** The public key is the anchor of the entire provenance claim. The protocol *is* the binding of hash to key. |

### Can ARTIFACT HASH be removed?

| Aspect | Assessment |
|---|---|
| What breaks | Everything. Without a hash, the statement is a detached signature on nothing. It proves "key X signed something." It does not bind to any specific artifact. |
| What survives | The key identity and timestamp are preserved, but they are meaningless — you cannot verify which artifact the statement refers to. |
| Verdict | **Not removable.** The hash is what binds the statement to a real-world artifact. Without it, the protocol provides zero integrity guarantees. |

### Minimal Core

Current set: `(hash, key, time, sig)`. The absolute minimum is `(hash, key, sig)` — timestamp can be advisory (which it is). **The primitive is necessary. No further field can be removed without destroying the protocol's purpose.**

---

## PHASE 2: FORGERY ANALYSIS

### Acting as malicious maintainer (has commit access)

| Attack | Feasibility | Outcome |
|---|---|---|
| Insert backdoor that accepts any signature | High — can modify `verify_statement` | **Detectable on source audit.** Rust's type system makes it hard to accidentally short-circuit crypto. A deliberate change would be caught by the 62 existing tests or by anyone re-running `cargo test`. |
| Weaken hash validation (accept md5, accept variable-length hex) | High — can modify `parse_hash_string` | **Detectable:** the parser has 33 negative tests covering hash validation. Changing the parser would break tests. |
| Exfiltrate secret keys through normal output | Medium — could log key in debug messages | **Detectable on code review.** The zeroize-on-drop pattern makes residual key exposure unlikely. |
| Change canonical body construction | High — can modify `canonical_body()` | **Critical if undetected.** Changing which fields are signed invalidates all existing signatures without breaking tests (tests use the modified code). A test checking specific canonical body format mitigates this. |

**Verdict:** A malicious maintainer can break the protocol, but cannot do so stealthily. The test suite and the simplicity of the codebase (~1000 lines total) make backdoors auditable.

### Acting as malicious contributor (can submit PRs, cannot merge)

| Attack | Feasibility | Outcome |
|---|---|---|
| Submit PR weakening crypto validation | High — but blocked by maintainer review | 62 tests + diff review makes this detectable. The protocol's simplicity (no networking, no DB, no async) limits the surface for subtle changes. |
| Add "convenience" feature that bypasses verification | Medium — e.g., add `verify_unsafe` | Blocked by maintainer review. The API surface is minimal (7 public functions) — any addition is visible. |
| Introduce dependency with known vulnerability | High — add a crate with a CVE | Blocked by `cargo audit` (not yet in CI, but recommended). `Cargo.toml` lists only 5 direct dependencies, all well-audited. |

**Verdict:** Low risk for a healthy open-source project with review. The narrow API surface and small dependency footprint are structural defenses.

### Acting as malicious distributor (controls download site, binaries, or package registry)

| Attack | Feasibility | Outcome |
|---|---|---|
| Replace `origin` binary with trojaned version | **High** — this is the classic supply-chain attack | The user would download a binary that silently accepts forged statements. Only reproducible builds or signed releases of `origin` itself can prevent this. **The protocol does not protect its own distribution.** |
| Serve modified source tarball | High — same as above | Only `git` tag verification against a known-good hash protects against this. |

**Verdict:** The protocol cannot protect itself from its own distributor. This is non-unique (every tool has this problem) but must be documented.

### Acting as repository thief (has stolen the secret key file)

| Attack | Feasibility | Outcome |
|---|---|---|
| Sign arbitrary statements as the key owner | **Complete.** The thief can create valid statements indistinguishable from the legitimate owner's. | **Irreversible.** The protocol has no revocation mechanism. This is by design (see NON_GOALS.md). Mitigation: file permissions (0o600), hardware key storage, OS-level keychain. |
| Sign statements with future/past timestamps | Trivial — timestamp is self-asserted | The thief can make stolen statements appear to come from any time. |

**Verdict:** Key compromise is total compromise. This is a property of all asymmetric signature schemes, not a protocol flaw.

### Acting as release impersonator (creates artifacts that appear to come from a trusted project)

| Attack | Feasibility | Outcome |
|---|---|---|
| Publish artifact + statement + public key that verifies | **Trivial** — generate your own key, sign your own artifact | The statement verifies correctly against the attacker's public key. The victim trusts the wrong public key. **The protocol provides zero defense against key substitution.** |
| Convince users to trust attacker's key | Social engineering, not crypto | The protocol cannot prevent this. Key distribution is out of scope. |

**Verdict:** The protocol prevents forgery of statements for a given trusted key, but does nothing to help the verifier obtain the correct trusted key. This is the fundamental limitation. Origin is honest about it.

### Summary of forgery risks

| Attack vector | Prevented by protocol? | Mitigation outside protocol |
|---|---|---|
| Signature forgery | ✅ Yes (Ed25519 EUF-CMA) | N/A |
| Hash collision | ✅ Yes (SHA-256 collision resistance) | Use SHA-256 with Ed25519's 128-bit security — hash and signature security levels are matched |
| Parser trickery | ✅ Yes (strict parser, 62 tests) | N/A |
| Key compromise | ❌ No | File permissions, HSM, OS keychain |
| Distributor trojan | ❌ No | Reproducible builds, signed binaries |
| Key substitution | ❌ No | Out-of-band key distribution |
| Timestamp lying | ❌ No (by design) | External timestamp authority |

---

## PHASE 3: COMPARISON AGAINST EXISTING SYSTEMS

### Git commit signing

| Dimension | Origin | Git commit signing |
|---|---|---|
| What it binds | Hash + key + timestamp | Commit hash + committer + tree + parent |
| Granularity | Arbitrary artifact (any file) | Git commit object only |
| Notarization | Self-contained file | Embedded in Git DAG |
| Offline | ✅ Full | ✅ Full |
| Chainability | Via parent field | Via parent commit pointers |
| Key management | Plain Ed25519 key file | GPG keyring, SSH agent |
| Complexity | 1 binary, 5 commands | GPG + git-config + keyring |

**Origin better:** Binds to *any* artifact, not just Git objects. Simpler — no GPG infrastructure, no keyring, no agent.
**Origin worse:** No integration with existing tooling (no `git log --show-signature` equivalent). No web of trust. No key discovery.
**Unique:** Offline-first provenance for non-Git artifacts (binaries, container images, datasets).

### Sigstore (cosign + Fulcio + Rekor)

| Dimension | Origin | Sigstore |
|---|---|---|
| Identity | Anonymous (just a key) | Email/OIDC identity bound to key |
| Transparency | None | Rekor transparency log (immutable, append-only) |
| Trust root | The public key you supply | Fulcio certificate chain to root CA |
| Offline | ✅ Full | ❌ Requires network for Rekor and Fulcio |
| Implementation | 1 crate, 558 lines library | Multiple services, OIDC providers, CT log |
| Cost | Zero | Free (public good), operational cost for private |

**Origin better:** Works completely offline. No dependency chain. No operational cost. Simpler threat model — you trust a specific key, not a chain of CAs and transparency logs.
**Origin worse:** No identity binding — you cannot prove "Alice signed this," only "key X signed this." No transparency — you cannot prove you *didn't* sign something. No key revocation.
**Unique:** The simplest possible provenance primitive. Can be used in air-gapped environments, embedded systems, or as a building block for higher-level protocols.

### in-toto

| Dimension | Origin | in-toto |
|---|---|---|
| Scope | Single statement | Multi-step supply chain (layout, functionaries, links) |
| Primitive | Hash + key + time | Step-by-step metadata with inspection commands |
| Verification | Verify one statement | Verify entire supply chain layout |
| Complexity | 5 commands, 1 binary | Multiple metadata types, multiple tools |

**Origin better:** Radically simpler. One statement type, one verification algorithm.
**Origin worse:** No supply chain semantics — no concept of steps, functionaries, or inspections. Cannot verify a multi-party pipeline.
**Unique:** Plug-compatible as the *signed metadata primitive* that in-toto could use for its link metadata.

### SLSA

| Dimension | Origin | SLSA |
|---|---|---|
| Level | Not applicable (no levels) | L1–L4 (provenance generation, signed, hermetic, reproducible) |
| Requirement | Any artifact | Build platform generates provenance |
| Verification | One statement per artifact | Build-to-builder chain verification |

**Origin better:** Works for *any* artifact (not just build outputs). No platform dependency.
**Origin worse:** No build platform attestation. Cannot achieve SLSA L3+ without external infrastructure.
**Unique:** Could serve as the *signed provenance format* for SLSA provenance statements in air-gapped or minimal environments.

### TUF (The Update Framework)

| Dimension | Origin | TUF |
|---|---|---|
| Purpose | Provenance | Secure update distribution |
| Trust model | Single key | Multi-key threshold signing, key rotation |
| Metadata | One statement type | Root, target, snapshot, timestamp, delegation |
| Offline | ✅ Full | ❌ Requires repository |

**Origin better:** Offline-first. No repository, no delegation, no snapshot management.
**Origin worse:** No key rotation, no delegation, no expiry, no multi-signer.
**Unique:** Could be the *leaf-level statement format* that TUF targets reference — a signed hash bound to a key.

### Signed release artifacts (GPG-signed tarballs)

| Dimension | Origin | GPG-signed releases |
|---|---|---|
| Binding | Hash + key in one file | Detached signature (`.asc` file) |
| Key format | Ed25519 (44 chars) | GPG key (long, complex) |
| Verification | One command, no keyring | Needs GPG keyring, trust setup |
| User experience | `origin verify artifact --key pubkey` | `gpg --verify artifact.asc` + key import + trust |

**Origin better:** Simpler commands. Self-contained statement (hash + key + sig in one file). No keyring setup. Deterministic output.
**Origin worse:** No ecosystem integration (no `apt-key` equivalent, no `rpm --checksig` equivalent). Unknown to existing tooling.
**Unique:** The statement IS the provenance — it's not a signature + separate hash + separate key — it's one file that says everything.

### Comparative summary

| System | Offline | Self-contained | Arbitrary artifact | Single command verify | No key infrastructure |
|---|---|---|---|---|---|
| Git signing | ✅ | ❌ (in DAG) | ❌ (Git only) | ❌ | ❌ (needs GPG) |
| Sigstore | ❌ | ❌ (needs Rekor) | ✅ | ❌ | ❌ (needs CA chain) |
| in-toto | ✅ | ❌ (needs layout) | ✅ | ❌ | ✅ |
| SLSA | ❌ | ❌ (platform dependent) | ❌ (build only) | ❌ | ❌ (needs platform) |
| TUF | ❌ | ❌ (needs repo) | ✅ | ❌ | ❌ (multi-key) |
| GPG releases | ✅ | ❌ (detached sig) | ✅ | ❌ (needs keyring) | ❌ (needs GPG) |
| **Origin** | **✅** | **✅** | **✅** | **✅** | **✅** |

**Origin uniquely contributes:** The only system that is simultaneously offline, self-contained, artifact-agnostic, single-command verifiable, and key-infrastructure-free. This is a meaningful gap in the existing landscape.

---

## PHASE 4: PROTOCOL COMPLETENESS

### Real-world use cases solved

1. **Release artifact provenance**: Project publishes `myapp-v1.0.0` + `myapp-v1.0.0.origin`. User downloads both, runs `origin verify myapp-v1.0.0 --key <trusted-key>`, gets a binary result. **Solved completely.**

2. **Container image provenance**: After `docker pull`, hash the image manifest, sign the hash. Consumer verifies image to hash to statement to key. **Solved completely.** (No Docker integration — user must compute the hash manually.)

3. **Dataset provenance**: Researcher signs the SHA-256 of a dataset. Reviewer verifies the dataset matches what was signed. **Solved completely.**

4. **Binary integrity for air-gapped systems**: USB drive with a binary and its `.origin` file. Verify on an offline machine. **Solved completely.** (Origin is uniquely suited here.)

5. **Multi-key provenance (emergent)**: Three developers sign the same artifact — three `.origin` files. Auditor verifies each against the respective trusted key. **Solved by multiplicity, not protocol feature.**

6. **Provenance chain**: Sign a statement that references a parent statement via `parent:`. Creates a DAG: root statement to intermediate to leaf. **Solved by parent field.**

### Important use cases NOT solved

1. **Key revocation**: A compromised key cannot be revoked. All statements signed by that key are forever valid (or forever suspect). **This is a real gap** — in any real deployment, keys get compromised. The protocol has no answer.

2. **Key discovery**: Given an artifact, how do you find its public key? The protocol does not help. You must know the key *before* you verify. **This is the #1 adoption blocker** — it shifts all burden to the verifier.

3. **Transparency / accountability**: No record of what anyone signed. A malicious signer can deny having signed a particular hash. No transparency log, no public audit trail, no "signed at this time" evidence. **This limits Origin to bilateral trust scenarios** (I trust a specific key I already know).

4. **Expiration**: Statements live forever. No concept of "this statement is no longer valid after date X." **Manageable but missing** — users who need expiration must add it themselves.

5. **Multi-signature / threshold**: To prove "2 of 3 maintainers approved this release," you need 3 separate `.origin` files and 3 separate verification commands. **No aggregate signature, no threshold scheme.**

6. **Statement bundle**: Signatures are one-per-file. A release with 10 artifacts produces 10 `.origin` files. **No bundle format, no manifest.**

7. **Identity binding**: The key has no name. There is no attestation that "key X corresponds to project Y version Z." Every key is a bare 44-char base64 string.

### Which missing capabilities belong IN the protocol

- **Revocation mechanism**: A way to signal "statements signed by key X after date Y are not to be trusted." Could be a separate revocation statement type signed by the same key (or a designated revocation key). Without this, a single key compromise poisons the entire protocol for that key forever.

- **Statement type tag**: A single field in the statement that distinguishes "provenance statement" from "revocation statement" from "key delegation statement." Currently, the protocol has one statement type. Future extensibility requires a discriminant.

- **Bundle / manifest format**: A way to sign multiple artifacts under one statement. A manifest could be: hash of (list of (path, hash) pairs) signed as one statement.

### Which should remain OUTSIDE the protocol forever

- **Identity layer** (name-to-key mapping): This is a user-facing application concern. Adding it to the protocol would create a dependency on naming systems, DNS, or blockchains. **Correctly excluded.**

- **Key distribution / discovery**: Any solution here becomes a centralized dependency (key server, DNS, blockchain). **Correctly excluded.**

- **Transparency log**: Would require network, consensus, and ongoing operational cost. **Correctly excluded** — but a protocol-level commitment format that transparency logs could ingest would be valuable.

- **Expiration**: A policy decision, not a cryptographic one. **Correctly excluded** — the verifier decides when to stop trusting.

- **Encryption**: Confidentiality is orthogonal to provenance. **Correctly excluded.**

---

## PHASE 5: DESIGN THE SMALLEST POSSIBLE ORIGIN v1.1

Rules: preserve simplicity, auditability, determinism. Add only features that increase protocol value by at least 10x.

### Candidate additions (ranked by value/complexity ratio)

| Feature | Value | Complexity | Ratio | Include? |
|---|---|---|---|---|
| Statement type tag (`type: provenance`, `type: revocation`, `type: delegation`) | High — enables protocol extensibility | Very low — one more field, one more parser check | **10x** | ✅ Yes |
| Revocation statement type | High — solves the key compromise problem | Low — same format, different signing semantics | **10x** | ✅ Yes |
| Manifest hash (hash-of-hashes) | Medium — bundles multiple artifacts | Low — one more variant of the hash field | ~3x | ❌ No, not 10x |
| Key fingerprint field | Medium — prevents key substitution in multi-key scenarios | Low — add `fingerprint: sha256:<b64>` line | ~2x | ❌ No |

### Proposed Origin v1.1

One new field: `type`. Three statement types.

**Format (minimal, no parent):**
```
origin: v1
type: provenance
hash: sha256:<hex>
time: <ts>
key: <b64>
sig: <b64>
```

**Format (with parent):**
```
origin: v1
type: provenance
parent: sha256:<hex>
hash: sha256:<hex>
time: <ts>
key: <b64>
sig: <b64>
```

### Statement types

- **`provenance`** — current semantics: "key X signed artifact hash Y at time Z" (canonical body: `origin` + `type` + [`parent`] + `hash` + `key`)

- **`revocation`** — "key X declares all provenance statements signed by key K after timestamp T are revoked" (canonical body: `origin` + `type` + `revoked` + `since` + `key`)

### The revocation statement (the critical 10x addition)

Same format, same verification, same key management. Signed by the key being revoked (or a designated revocation key).

**Format:**
```
origin: v1
type: revocation
revoked: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
since: 1717776000
key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
sig: <b64>
```

- **`revoked`**: base64-encoded Ed25519 public key (44 chars, same format as `key` field)
- **`since`**: UNIX timestamp — all provenance statements by the revoked key with `time >= since` should not be trusted
- **`key`**: the signer of this revocation (could be the same as `revoked` or a different recovery key)
- **Canonical body**: `origin: v1\ntype: revocation\nrevoked: <b64>\nsince: <ts>\nkey: <b64>`

**Verifier logic:**
1. Collect all revocation statements for a key
2. Find the latest `since` timestamp that is <= the provenance statement's `time`
3. If found: the provenance statement is revoked
4. If not found: the provenance statement is not revoked

**No revocation authority, no CRL, no OCSP, no network** — just a statement type that follows the same format, same verification, same key management as provenance statements. Revocations are just statements that say "stop trusting."

### Net change to v1.1

- One new field in the parser: `type`
- One new statement variant on top of the same structure
- ~50 lines of library code
- ~10 new tests
- **0 new dependencies, 0 network, 0 infrastructure**

---

## FINAL VERDICT

### Scores

| Score | Value | Rationale |
|---|---|---|
| **Minimality** | **9.5 / 10** | Every field is necessary. Parent field is a legitimate extension (not bloat). Timestamp is advisory — correct design. |
| **Security** | **8 / 10** | Crypto is sound, parser is strict, threat model is honest. Deductions: no revocation, key compromise is unrecoverable, no protection against distributor trojans. |
| **Protocol Clarity** | **9 / 10** | One primitive, one format, 5 commands, ~1000 lines of code, 62 tests. The RFC needs updating to reflect v0.1.1 changes. Syntax is self-evident. |
| **Adoption Potential** | **5 / 10** | Technically excellent but cold-start problem: no ecosystem, no key distribution, no identity binding. Users must already know the key. |
| **Infrastructure Potential** | **8 / 10** | As a *building block* for higher-level tools, Origin is ideal. Plug-compatible with SLSA, in-toto, and TUF as a leaf-level signed metadata format. |

### Final question: Is Origin's primitive strong enough to become the foundation of a larger provenance protocol?

**Yes, with one condition.**

The primitive `(hash, key, sig)` — the core binding — is correct, minimal, and cryptographically sound. It passes every test of necessity and sufficiency. You cannot remove another field without breaking the protocol's purpose.

**Why yes:**

1. **The binding is sound.** `Ed25519(canonical_body)` proves "key X claims responsibility for hash Y." This is the fundamental cryptographic unit of provenance. No existing protocol provides this binding in a simpler form.

2. **The format is universal.** Text, colon-separated, self-describing. Any tool in any language can parse it with `split(": ")` and `split("\n")`. No schema, no codec, no parser generator.

3. **The trust model is honest.** The protocol does not claim to solve identity, timestamp verification, or key distribution. This honesty is a strength — it defines clear boundaries that ecosystem tools can build on without fighting the protocol.

4. **The parent field is the right extension point.** Provenance chains, key delegation, manifest trees — all of these build on the parent field. One mechanism, infinite uses.

**The condition:**

The protocol needs **two things** before it can be called a foundation:

1. A `type` discriminant field (see Phase 5). Without it, the protocol has one statement type forever. With it, the protocol can grow revocation, delegation, manifests, and more — all within the same format, same verification algorithm, same tooling.

2. The RFC document must be updated to match the current implementation (advisory timestamp, parent field, hash agility removed — SHA-256 only). The spec and the code are out of sync — this is a documentation gap, not a protocol gap, but it undermines confidence.

### Closing assessment

Origin is not competing with Sigstore, in-toto, or SLSA. It is competing with `sha256sum` + `gpg --detach-sign`. Against that baseline, Origin wins on every axis: simplicity, determinism, offline capability, and user experience. The protocol should lean into this niche — **the simplest possible signed hash** — and let the heavyweight systems either adopt it or ignore it. Either outcome is fine for a correct primitive.
