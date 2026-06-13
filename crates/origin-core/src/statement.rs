// SPDX-License-Identifier: MIT

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use hashbrown::HashSet;

use crate::crypto;
use crate::error::{Error, Result};
use crate::hash;

/// Type alias for DID resolver function.
pub type DidResolver = dyn Fn(&str) -> Result<()>;

/// Type alias for rulebook resolver function.
pub type RulebookResolver = dyn Fn(&[u8; 32]) -> Result<()>;

const PROTOCOL_VERSION: &str = "v1";
const MAX_TIMESTAMP: u64 = 4294967295;
const KEY_B64_LEN: usize = 44;
const SIG_B64_LEN: usize = 88;
const EXPECTED_LINES: usize = 5;
const VALID_KEYS: [&str; 5] = ["origin", "hash", "time", "key", "sig"];
const HEX_CHARS: &[u8] = b"0123456789abcdef";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub origin: String,
    pub hash: String,
    pub hash_bytes: [u8; 32],
    pub time: u64,
    pub key_b64: String,
    pub key_bytes: [u8; 32],
    pub sig_b64: String,
    pub sig_bytes: [u8; 64],
    pub raw_lines: Vec<String>,
    pub semantic_hash: [u8; 32],
    pub semantic_model_ver: u8,
    pub policy_hash: [u8; 32],
    pub parent_poo_hash: [u8; 16],
}

fn validate_hex_lowercase(s: &str, expected_len: usize) -> Result<()> {
    if s.len() != expected_len {
        return Err(Error::Format(format!(
            "hex string length {} (expected {})",
            s.len(),
            expected_len
        )));
    }
    if !s.as_bytes().iter().all(|b| HEX_CHARS.contains(b)) {
        return Err(Error::Format(
            "non-hex character or uppercase in hash".into(),
        ));
    }
    Ok(())
}

fn validate_base64url(s: &str, expected_str_len: usize, expected_bytes: usize) -> Result<Vec<u8>> {
    if s.len() != expected_str_len {
        return Err(Error::Format(format!(
            "base64url length {} (expected {})",
            s.len(),
            expected_str_len
        )));
    }
    let bytes = crate::base64_decode(s)?;
    if bytes.len() != expected_bytes {
        return Err(Error::Format(format!(
            "decoded base64url length {} (expected {})",
            bytes.len(),
            expected_bytes
        )));
    }
    Ok(bytes)
}

impl Statement {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let text =
            core::str::from_utf8(data).map_err(|_| Error::Format("not valid UTF-8".into()))?;

        if data.starts_with(b"\xef\xbb\xbf") {
            return Err(Error::Format("BOM not allowed".into()));
        }
        if text.contains('\r') {
            return Err(Error::Format("CR character not allowed".into()));
        }
        if data.contains(&0x00) {
            return Err(Error::Format("null byte not allowed".into()));
        }
        if !text.ends_with('\n') {
            return Err(Error::Format("missing trailing newline".into()));
        }

        let raw = text.strip_suffix('\n').unwrap_or(text);
        let lines: Vec<&str> = raw.split('\n').collect();

        if lines.len() > EXPECTED_LINES {
            let extra = lines.len() - EXPECTED_LINES;
            return Err(Error::TrailingContent(format!(
                "expected {} lines, got {} ({} extra line{})",
                EXPECTED_LINES,
                lines.len(),
                extra,
                if extra == 1 { "" } else { "s" },
            )));
        }
        if lines.len() < EXPECTED_LINES {
            return Err(Error::Format(format!(
                "expected {} lines, got {}",
                EXPECTED_LINES,
                lines.len()
            )));
        }

        for (i, line) in lines.iter().enumerate() {
            if line.is_empty() {
                return Err(Error::Format(format!("line {} is empty", i + 1)));
            }
        }

        let mut fields: Vec<(&str, &str)> = Vec::with_capacity(EXPECTED_LINES);
        for (i, line) in lines.iter().enumerate() {
            let sep = ": ";
            let Some(pos) = line.find(sep) else {
                return Err(Error::Format(format!(
                    "line {}: missing ': ' separator",
                    i + 1
                )));
            };
            let key = &line[..pos];
            let value = &line[pos + sep.len()..];

            if key.is_empty() {
                return Err(Error::Format(format!("line {}: empty key", i + 1)));
            }
            if value.is_empty() {
                return Err(Error::Format(format!("line {}: empty value", i + 1)));
            }
            if value.starts_with(' ')
                || value.starts_with('\t')
                || value.ends_with(' ')
                || value.ends_with('\t')
            {
                return Err(Error::Format(format!(
                    "line {}: leading or trailing whitespace in value",
                    i + 1
                )));
            }
            for c in value.chars() {
                let cp = c as u32;
                if (cp < 0x20 && cp != 0x0a) || cp == 0x7f {
                    return Err(Error::Format(format!(
                        "line {}: control character U+{:04X} in value",
                        i + 1,
                        cp
                    )));
                }
            }
            fields.push((key, value));
        }

        let mut seen_keys = HashSet::new();
        for (i, (key, _)) in fields.iter().enumerate() {
            if *key != VALID_KEYS[i] {
                return Err(Error::Format(format!(
                    "line {}: expected key '{}', got '{}'",
                    i + 1,
                    VALID_KEYS[i],
                    key
                )));
            }
            if !seen_keys.insert(key) {
                return Err(Error::Format(format!("duplicate key '{}'", key)));
            }
        }

        let origin_val = fields[0].1;
        let hash_val = fields[1].1;
        let time_val = fields[2].1;
        let key_val = fields[3].1;
        let sig_val = fields[4].1;

        if origin_val != PROTOCOL_VERSION {
            return Err(Error::Format(format!(
                "origin must be '{}', got '{}'",
                PROTOCOL_VERSION, origin_val
            )));
        }

        let hash_prefix = "sha256:";
        if !hash_val.starts_with(hash_prefix) {
            return Err(Error::Format("hash must start with 'sha256:'".into()));
        }
        let hash_hex = &hash_val[hash_prefix.len()..];
        validate_hex_lowercase(hash_hex, 64)?;
        let hash_bytes = hex::decode(hash_hex)
            .map_err(|e| Error::Format(alloc::format!("invalid hex: {}", e)))?;
        let mut hb = [0u8; 32];
        hb.copy_from_slice(&hash_bytes);

        if !time_val.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Format("timestamp must be ASCII digits".into()));
        }
        if time_val.len() > 1 && time_val.starts_with('0') {
            return Err(Error::Format(
                "timestamp must not have leading zeros".into(),
            ));
        }
        let time: u64 = time_val
            .parse()
            .map_err(|_| Error::Format("timestamp overflow".into()))?;
        if time > MAX_TIMESTAMP {
            return Err(Error::Format(format!(
                "timestamp {} exceeds maximum {}",
                time, MAX_TIMESTAMP
            )));
        }

        let key_raw = validate_base64url(key_val, KEY_B64_LEN, 32)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key_raw);
        crypto::validate_public_key(&key_bytes)?;

        let sig_raw = validate_base64url(sig_val, SIG_B64_LEN, 64)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig_raw);

        let raw_lines: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();

        Ok(Statement {
            origin: origin_val.to_string(),
            hash: hash_val.to_string(),
            hash_bytes: hb,
            time,
            key_b64: key_val.to_string(),
            key_bytes,
            sig_b64: sig_val.to_string(),
            sig_bytes,
            raw_lines,
            semantic_hash: [0u8; 32],
            semantic_model_ver: 0,
            policy_hash: [0u8; 32],
            parent_poo_hash: [0u8; 16],
        })
    }

    /// Canonical body (first 4 lines, no trailing newline) for backward compat.
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut body = String::new();
        body.push_str(&self.raw_lines[0]);
        body.push('\n');
        body.push_str(&self.raw_lines[1]);
        body.push('\n');
        body.push_str(&self.raw_lines[2]);
        body.push('\n');
        body.push_str(&self.raw_lines[3]);
        body.into_bytes()
    }
}

/// Build a signed .origin statement using Ed25519ph over the binary prefix.
pub fn build_statement(
    secret: &crypto::SecretKey,
    artifact_bytes: &[u8],
    timestamp: u64,
) -> Result<Statement> {
    let hash_bytes = hash::hash_bytes(artifact_bytes);
    build_statement_from_hash(secret, &hex::encode(hash_bytes), &hash_bytes, timestamp)
}

/// Build from pre-computed hash, using Ed25519ph over the binary prefix.
pub fn build_statement_from_hash(
    secret: &crypto::SecretKey,
    hash_hex_str: &str,
    hash_bytes: &[u8; 32],
    timestamp: u64,
) -> Result<Statement> {
    let hash_str = alloc::format!("sha256:{}", hash_hex_str);

    let kp = crypto::generate_keypair_from_seed(&secret.0);
    let public = &kp.public;
    let public_b64 = crate::base64_encode(&public.0);

    let origin_line = alloc::format!("origin: {}", PROTOCOL_VERSION);
    let hash_line = alloc::format!("hash: {}", hash_str);
    let time_line = alloc::format!("time: {}", timestamp);
    let key_line = alloc::format!("key: {}", public_b64);

    // Build the statement without signature first
    let stmt_no_sig = Statement {
        origin: PROTOCOL_VERSION.to_string(),
        hash: hash_str.clone(),
        hash_bytes: *hash_bytes,
        time: timestamp,
        key_b64: public_b64.clone(),
        key_bytes: public.0,
        sig_b64: String::new(),
        sig_bytes: [0u8; 64],
        raw_lines: alloc::vec![
            origin_line.clone(),
            hash_line.clone(),
            time_line.clone(),
            key_line.clone(),
            alloc::format!("sig: {}", "placeholder"),
        ],
        semantic_hash: [0u8; 32],
        semantic_model_ver: 0,
        policy_hash: [0u8; 32],
        parent_poo_hash: [0u8; 16],
    };

    // Convert to binary ProofOfOrigin to get the signed prefix
    let mut poo = crate::binary::ProofOfOrigin::from_statement(&stmt_no_sig)?;
    poo.tool_hash = crate::binary::compute_tool_hash(DEFAULT_TOOL_STRING);
    let prefix = poo.signed_prefix();
    let sig = crypto::sign_ph(secret, &prefix);

    let sig_b64 = crate::base64_encode(&sig.0);

    let raw_lines = alloc::vec![
        origin_line,
        hash_line,
        time_line,
        key_line,
        alloc::format!("sig: {}", sig_b64),
    ];

    Ok(Statement {
        origin: PROTOCOL_VERSION.to_string(),
        hash: hash_str,
        hash_bytes: *hash_bytes,
        time: timestamp,
        key_b64: public_b64,
        key_bytes: public.0,
        sig_b64,
        sig_bytes: sig.0,
        raw_lines,
        semantic_hash: [0u8; 32],
        semantic_model_ver: 0,
        policy_hash: [0u8; 32],
        parent_poo_hash: [0u8; 16],
    })
}

const DEFAULT_TOOL_STRING: &str = "origin-cli";

/// Encode a Statement back into the .origin text format as bytes.
pub fn encode_statement(stmt: &Statement) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\n{}\n",
        stmt.raw_lines[0],
        stmt.raw_lines[1],
        stmt.raw_lines[2],
        stmt.raw_lines[3],
        stmt.raw_lines[4],
    )
    .into_bytes()
}

/// Verify a signed statement against an artifact using Ed25519ph over binary prefix.
pub fn verify_statement(stmt: &Statement, artifact_bytes: &[u8]) -> Result<()> {
    let actual_hash = hash::hash_hex(artifact_bytes);
    verify_statement_hash(stmt, &actual_hash)
}

/// Verify using pre-computed hash.
pub fn verify_statement_hash(stmt: &Statement, actual_hash_hex: &str) -> Result<()> {
    verify_statement_hash_with_time(stmt, actual_hash_hex, None, None, None)
}

/// Verify using pre-computed hash with optional clock-skew check and IKM/IVG resolution.
///
/// If `now` is provided, returns `Error::TimestampFuture` (E007) when
/// `stmt.time > now + 300` (5-minute clock-skew tolerance).
///
/// If `resolve_did` is provided, attempts DID resolution for the key.
/// Returns `Error::IkmUnreachable` (E004) if resolution fails.
///
/// If `resolve_rulebook` is provided and semantic_model_ver != 0,
/// attempts rulebook resolution. Returns `Error::IvgUnreachable` (E005) if fails.
///
/// # Temporal Priority Limitation (NP3)
///
/// **WARNING:** Timestamps are self-set. A fast attacker can sign publicly
/// available content before its actual creator. Do NOT treat timestamps as
/// proof of creation priority. Timestamps prove existence at a point in time,
/// not originality.
pub fn verify_statement_hash_with_time(
    stmt: &Statement,
    actual_hash_hex: &str,
    now: Option<u64>,
    resolve_did: Option<&DidResolver>,
    resolve_rulebook: Option<&RulebookResolver>,
) -> Result<()> {
    let expected_hash = &stmt.hash[7..];
    if actual_hash_hex != expected_hash {
        return Err(Error::ContentMismatch {
            expected: expected_hash.to_string(),
            actual: actual_hash_hex.to_string(),
        });
    }

    // E007: clock-skew tolerance — warn when timestamp > now + 300
    // Per spec: warning only, does not hard-fail
    if let Some(now) = now
        && stmt.time > now.saturating_add(300)
    {
        #[cfg(feature = "std")]
        eprintln!(
            "W003 WARNING: {}",
            Error::TimestampFuture { ts: stmt.time, now }
        );
    }

    // E004: IKM resolution check
    if let Some(resolve) = resolve_did {
        let did = format!("did:origin:{}", hex::encode(stmt.key_bytes));
        resolve(&did)?;
    }

    // E005: IVG resolution check for derivatives
    if stmt.semantic_model_ver != 0
        && let Some(resolve) = resolve_rulebook
    {
        resolve(&stmt.hash_bytes)?;
    }

    // Reconstruct binary and verify signature
    let mut poo = crate::binary::ProofOfOrigin::from_statement(stmt)?;
    poo.tool_hash = crate::binary::compute_tool_hash(DEFAULT_TOOL_STRING);
    poo.signature = stmt.sig_bytes;
    let prefix = poo.signed_prefix();

    if poo.is_multi_author() {
        // MULTI_AUTHOR: signature is BLS aggregate (48 bytes) + 16 zero bytes
        if stmt.sig_bytes[48..64].iter().any(|&b| b != 0) {
            return Err(Error::Format(
                "MULTI_AUTHOR: BLS signature bytes 48-63 must be zero".into(),
            ));
        }
        // BLS public keys must be resolved externally; use verify_bls_statement
        return Err(Error::IkmUnreachable {
            key: hex::encode(stmt.key_bytes),
        });
    }

    // Ed25519ph verification (standard single-author path)
    let public_key = crypto::PublicKey::from_bytes(&stmt.key_bytes)?;
    let sig = crypto::Signature::from_bytes(&stmt.sig_bytes)?;
    crypto::verify_ph(&public_key, &prefix, &sig)
}

/// Verify a MULTI_AUTHOR statement using explicit BLS public keys.
///
/// The PoO must have the `MULTI_AUTHOR` flag (0x0010) set.
/// `bls_public_keys` must contain all public keys that participated
/// in the aggregate signature. `bls_pops` must contain the corresponding
/// Proof-of-Possession signatures for each public key. PoPs are verified
/// BEFORE aggregation to prevent rogue-key attacks.
///
/// The aggregate signature must be a valid BLS aggregate of individual
/// signatures on the same message (PoO prefix).
pub fn verify_bls_statement(
    stmt: &Statement,
    actual_hash_hex: &str,
    bls_public_keys: &[crate::bls::BlsPublicKey],
    bls_pops: &[crate::bls::BlsSignature],
) -> Result<()> {
    let expected_hash = &stmt.hash[7..];
    if actual_hash_hex != expected_hash {
        return Err(Error::ContentMismatch {
            expected: expected_hash.to_string(),
            actual: actual_hash_hex.to_string(),
        });
    }

    let mut poo = crate::binary::ProofOfOrigin::from_statement(stmt)?;
    poo.tool_hash = crate::binary::compute_tool_hash(DEFAULT_TOOL_STRING);
    poo.signature = stmt.sig_bytes;
    let prefix = poo.signed_prefix();

    if !poo.is_multi_author() {
        return Err(Error::Format(
            "verify_bls_statement called on PoO without MULTI_AUTHOR flag".into(),
        ));
    }

    if stmt.sig_bytes[48..64].iter().any(|&b| b != 0) {
        return Err(Error::Format(
            "MULTI_AUTHOR: BLS signature bytes 48-63 must be zero".into(),
        ));
    }

    if bls_public_keys.is_empty() {
        return Err(Error::IkmUnreachable {
            key: hex::encode(stmt.key_bytes),
        });
    }

    if bls_pops.len() != bls_public_keys.len() {
        return Err(Error::Format(alloc::format!(
            "MULTI_AUTHOR: {} public keys but {} PoP signatures (must match)",
            bls_public_keys.len(),
            bls_pops.len()
        )));
    }

    // CRITICAL: Verify all PoP signatures BEFORE aggregation
    // This prevents rogue-key attacks where an adversary includes a key
    // they don't control in the aggregate.
    for (i, (pk, pop)) in bls_public_keys.iter().zip(bls_pops.iter()).enumerate() {
        if !crate::bls::bls_pop_verify(pk, pop) {
            return Err(Error::SignatureInvalid(alloc::format!(
                "MULTI_AUTHOR: PoP verification failed for key {}",
                i
            )));
        }
    }

    let bls_sig = crate::bls::BlsSignature::from_bytes(&stmt.sig_bytes[..48])?;
    let pk_refs: Vec<&crate::bls::BlsPublicKey> = bls_public_keys.iter().collect();
    if crate::bls::bls_verify_aggregate(&prefix, &bls_sig, &pk_refs) {
        Ok(())
    } else {
        Err(Error::SignatureInvalid(
            "BLS aggregate signature verification failed".into(),
        ))
    }
}

/// Result of comparing two semantic model versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelMatch {
    /// Semantic model versions are identical.
    Exact,
    /// Semantic model versions differ within same major version — derivatives permitted.
    DerivativeProbable,
    /// Semantic model versions differ across major versions — review required.
    DerivativeReview,
    /// One or both versions are zero (no semantic model).
    Uncomputable,
}

/// Compare two semantic model versions for compatibility.
///
/// - Returns `Exact` if both versions are equal and non-zero.
/// - Returns `DerivativeProbable` if major versions match but minor differs.
/// - Returns `DerivativeReview` if major versions differ.
/// - Returns `Uncomputable` if either version is 0 (no semantic model).
pub fn compare_semantic_models(ver_a: u8, ver_b: u8) -> ModelMatch {
    if ver_a == 0 || ver_b == 0 {
        return ModelMatch::Uncomputable;
    }
    if ver_a == ver_b {
        return ModelMatch::Exact;
    }
    let major_a = ver_a >> 4;
    let major_b = ver_b >> 4;
    if major_a == major_b {
        ModelMatch::DerivativeProbable
    } else {
        ModelMatch::DerivativeReview
    }
}

/// Verify a derivative PoO against its parent's semantic model version.
///
/// If both PoOs have non-zero `semantic_model_ver`, compares them.
/// Returns `Error::ModelMismatch` (E008) when versions differ.
/// Per spec: MATCH_UNCOMPUTABLE (either version is 0) is treated as DERIVATIVE_PROBABLE.
pub fn verify_model_compatibility(child_ver: u8, parent_ver: u8) -> Result<()> {
    match compare_semantic_models(child_ver, parent_ver) {
        ModelMatch::Exact => Ok(()),
        // Spec: MATCH_UNCOMPUTABLE treated as DERIVATIVE_PROBABLE → return E008
        ModelMatch::Uncomputable
        | ModelMatch::DerivativeProbable
        | ModelMatch::DerivativeReview => Err(Error::ModelMismatch {
            ver_a: child_ver,
            ver_b: parent_ver,
        }),
    }
}
