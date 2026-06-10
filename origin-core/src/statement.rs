use crate::crypto;
use crate::error::{Error, Result};
use crate::hash::{self, HashAlgorithm, ALLOWED_HASH_ALGORITHMS};

const PROTOCOL_VERSION: &str = "v1";
const STATEMENT_TYPE: &str = "provenance";
const MAX_TIMESTAMP: u64 = 253402300799;
const KEY_B64_LEN: usize = 44;
const SIG_B64_LEN: usize = 88;
const HEX_CHARS: &[u8] = b"0123456789abcdef";

/// A parsed provenance statement.
///
/// Contains all fields of a provenance statement in both encoded and decoded
/// form. Constructed by `Statement::parse()` or `build_statement()`.
///
/// The canonical body (what is signed) consists of origin, type, parent,
/// hash, and key — time and sig are excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// Protocol version (always "v1").
    pub origin: String,
    /// Optional parent statement hash (for provenance chaining).
    pub parent: Option<String>,
    /// Full hash string with algorithm prefix (e.g. `sha256:<hex>`).
    pub hash: String,
    /// Hash digest as lowercase hex (without algorithm prefix).
    pub hash_hex: String,
    /// Hash algorithm (SHA-256, SHA-384, or SHA-512).
    pub hash_alg: HashAlgorithm,
    /// Hash digest as raw bytes.
    pub hash_bytes: Vec<u8>,
    /// Self-asserted UNIX timestamp (advisory — not in canonical body).
    pub time: u64,
    /// Public key as base64url string (44 chars with padding).
    pub key_b64: String,
    /// Public key as raw 32 bytes.
    pub key_bytes: [u8; 32],
    /// Signature as base64url string (88 chars with padding).
    pub sig_b64: String,
    /// Signature as raw 64 bytes.
    pub sig_bytes: [u8; 64],
    raw_lines: Vec<String>,
    parent_present: bool,
}

fn parse_hash_string(s: &str) -> Result<(HashAlgorithm, String, Vec<u8>)> {
    let colon_pos = s.find(':').ok_or_else(|| {
        Error::Format("hash missing algorithm prefix (e.g., 'sha256:')".into())
    })?;
    let alg_str = &s[..colon_pos];
    let hex_val = &s[colon_pos + 1..];

    let alg = match alg_str {
        "sha256" => {
            let expected_hex_len = 64;
            if hex_val.len() != expected_hex_len {
                return Err(Error::Format(format!(
                    "sha256 hex length {} (expected {})",
                    hex_val.len(),
                    expected_hex_len
                )));
            }
            HashAlgorithm::Sha256
        }
        "sha384" => {
            let expected_hex_len = 96;
            if hex_val.len() != expected_hex_len {
                return Err(Error::Format(format!(
                    "sha384 hex length {} (expected {})",
                    hex_val.len(),
                    expected_hex_len
                )));
            }
            HashAlgorithm::Sha384
        }
        "sha512" => {
            let expected_hex_len = 128;
            if hex_val.len() != expected_hex_len {
                return Err(Error::Format(format!(
                    "sha512 hex length {} (expected {})",
                    hex_val.len(),
                    expected_hex_len
                )));
            }
            HashAlgorithm::Sha512
        }
        _ => {
            return Err(Error::Format(format!(
                "unknown hash algorithm '{}'. Allowed: {}",
                alg_str,
                ALLOWED_HASH_ALGORITHMS.join(", ")
            )));
        }
    };

    if !hex_val.as_bytes().iter().all(|b| HEX_CHARS.contains(b)) {
        return Err(Error::Format(
            "non-hex character or uppercase in hash".into(),
        ));
    }

    let bytes = hex::decode(hex_val)
        .map_err(|_| Error::Format("invalid hex encoding".into()))?;

    Ok((alg, hex_val.to_string(), bytes))
}

fn validate_base64url(s: &str, expected_encoded: usize, expected_bytes: usize) -> Result<Vec<u8>> {
    if s.len() != expected_encoded {
        return Err(Error::Format(format!(
            "base64url length {} (expected {})",
            s.len(),
            expected_encoded
        )));
    }
    let bytes = crate::base64url_decode(s)?;
    if bytes.len() != expected_bytes {
        return Err(Error::Format(format!(
            "decoded base64url length {} (expected {})",
            bytes.len(),
            expected_bytes
        )));
    }
    Ok(bytes)
}

fn validate_timestamp(value: &str) -> Result<u64> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Format("timestamp must be ASCII digits".into()));
    }
    if value.len() > 1 && value.starts_with('0') {
        return Err(Error::Format("timestamp must not have leading zeros".into()));
    }
    let ts: u64 = value
        .parse()
        .map_err(|_| Error::Format("timestamp overflow".into()))?;
    if ts > MAX_TIMESTAMP {
        return Err(Error::Format(format!(
            "timestamp {} exceeds maximum {}",
            ts, MAX_TIMESTAMP
        )));
    }
    Ok(ts)
}

impl Statement {
    /// Parse a statement from raw bytes (the .origin file content).
    ///
    /// Validates all structural and field constraints. Returns the parsed
    /// `Statement` or an `Error::Format` with a descriptive message.
    ///
    /// This function does NOT perform cryptographic verification.
    /// Use `verify_statement` or `verify_bytes` for that.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(data)
            .map_err(|_| Error::Format("not valid UTF-8".into()))?;

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

        if lines.len() < 6 || lines.len() > 7 {
            return Err(Error::Format(format!(
                "expected 6 or 7 lines, got {}",
                lines.len()
            )));
        }

        for (i, line) in lines.iter().enumerate() {
            if line.is_empty() {
                return Err(Error::Format(format!("line {} is empty", i + 1)));
            }
        }

        let has_parent = lines.len() == 7;
        let expected_order: Vec<&str> = if has_parent {
            vec!["origin", "type", "parent", "hash", "time", "key", "sig"]
        } else {
            vec!["origin", "type", "hash", "time", "key", "sig"]
        };

        let mut fields: Vec<(&str, &str)> = Vec::with_capacity(lines.len());
        let mut seen_keys = std::collections::HashSet::new();

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
                if cp < 0x20 || cp == 0x7f {
                    return Err(Error::Format(format!(
                        "line {}: control character U+{:04X} in value",
                        i + 1, cp
                    )));
                }
            }

            if *key != *expected_order[i] {
                return Err(Error::Format(format!(
                    "line {}: expected key '{}', got '{}'",
                    i + 1, expected_order[i], key
                )));
            }
            if !seen_keys.insert(key) {
                return Err(Error::Format(format!("duplicate key '{}'", key)));
            }

            fields.push((key, value));
        }

        let origin_val = fields[0].1;
        if origin_val != PROTOCOL_VERSION {
            return Err(Error::Format(format!(
                "origin must be '{}', got '{}'",
                PROTOCOL_VERSION, origin_val
            )));
        }

        let type_val = fields[1].1;
        if type_val != STATEMENT_TYPE {
            return Err(Error::Format(format!(
                "type must be '{}', got '{}'",
                STATEMENT_TYPE, type_val
            )));
        }

        let parent_val = if has_parent {
            let p = fields[2].1.to_string();
            parse_hash_string(&p)?;
            Some(p)
        } else {
            None
        };

        let hash_line_idx = if has_parent { 3 } else { 2 };
        let time_idx = if has_parent { 4 } else { 3 };
        let key_idx = if has_parent { 5 } else { 4 };
        let sig_idx = if has_parent { 6 } else { 5 };

        let (hash_alg, hash_hex_str, hash_bytes) = parse_hash_string(fields[hash_line_idx].1)?;
        let hash_val = fields[hash_line_idx].1.to_string();

        let time = validate_timestamp(fields[time_idx].1)?;

        let key_raw = validate_base64url(fields[key_idx].1, KEY_B64_LEN, 32)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key_raw);

        let sig_raw = validate_base64url(fields[sig_idx].1, SIG_B64_LEN, 64)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig_raw);

        let raw_lines: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();

        Ok(Statement {
            origin: origin_val.to_string(),
            parent: parent_val,
            hash: hash_val,
            hash_hex: hash_hex_str,
            hash_alg,
            hash_bytes,
            time,
            key_b64: fields[key_idx].1.to_string(),
            key_bytes,
            sig_b64: fields[sig_idx].1.to_string(),
            sig_bytes,
            raw_lines,
            parent_present: has_parent,
        })
    }

    pub fn canonical_body(&self) -> Vec<u8> {
        let origin_line = format!("origin: {}", PROTOCOL_VERSION);
        let type_line = format!("type: {}", STATEMENT_TYPE);
        if self.parent_present {
            let parent_line = format!("parent: {}", self.parent.as_deref().unwrap());
            let hash_line = format!("hash: {}", self.hash);
            let key_line = format!("key: {}", self.key_b64);
            format!("{}\n{}\n{}\n{}\n{}", origin_line, type_line, parent_line, hash_line, key_line).into_bytes()
        } else {
            let hash_line = format!("hash: {}", self.hash);
            let key_line = format!("key: {}", self.key_b64);
            format!("{}\n{}\n{}\n{}", origin_line, type_line, hash_line, key_line).into_bytes()
        }
    }

    pub fn has_parent(&self) -> bool {
        self.parent_present
    }

    pub fn parent_hash_hex(&self) -> Option<&str> {
        self.parent.as_deref()
    }
}

/// Build a signed provenance statement (defaults to SHA-256).
///
/// This is the main entry point for signing. It hashes the artifact, derives
/// the public key from the secret key, constructs the canonical body, signs
/// it, and returns a complete `Statement`.
///
/// # Arguments
///
/// * `secret` — The Ed25519 secret key (32 bytes)
/// * `artifact_bytes` — The artifact bytes to sign
/// * `timestamp` — Self-asserted UNIX timestamp (advisory, not in canonical body)
/// * `parent_hash` — Optional parent statement hash for provenance chaining
///
/// # Returns
///
/// * `Ok(Statement)` — The signed statement (use `encode_statement` to serialize)
/// * `Err(Error)` — Signing failed (cryptographic error)
///
/// # Determinism
///
/// Same inputs always produce the same output. This is guaranteed by the
/// Ed25519 signature scheme (no random nonces) and verified by tests.
pub fn build_statement(
    secret: &crypto::SecretKey,
    artifact_bytes: &[u8],
    timestamp: u64,
    parent_hash: Option<&str>,
) -> Result<Statement> {
    build_statement_with_algorithm(secret, artifact_bytes, timestamp, parent_hash, HashAlgorithm::Sha256)
}

/// Build a signed provenance statement with a specified hash algorithm.
///
/// Same as `build_statement` but allows choosing the hash algorithm.
pub fn build_statement_with_algorithm(
    secret: &crypto::SecretKey,
    artifact_bytes: &[u8],
    timestamp: u64,
    parent_hash: Option<&str>,
    algorithm: HashAlgorithm,
) -> Result<Statement> {
    if (artifact_bytes.len() as u64) > crate::MAX_ARTIFACT_SIZE {
        return Err(Error::Format(format!(
            "artifact too large ({} bytes, max {})",
            artifact_bytes.len(),
            crate::MAX_ARTIFACT_SIZE
        )));
    }
    let alg_prefix = algorithm.to_string();
    let (hash_hex_str, hash_bytes_vec) = hash::hash_data(artifact_bytes, &algorithm);
    let hash_str = format!("{}:{}", alg_prefix, hash_hex_str);

    let pair = crypto::generate_keypair_from_seed(&secret.0);
    let public_b64 = crate::base64_encode(pair.public.as_bytes());

    let origin_line = format!("origin: {}", PROTOCOL_VERSION);
    let type_line = format!("type: {}", STATEMENT_TYPE);
    let hash_line = format!("hash: {}", hash_str);
    let time_line = format!("time: {}", timestamp);
    let key_line = format!("key: {}", public_b64);

    let canonical = if let Some(p) = parent_hash {
        let parent_line = format!("parent: {}", p);
        format!(
            "{}\n{}\n{}\n{}\n{}",
            origin_line, type_line, parent_line, hash_line, key_line
        )
    } else {
        format!(
            "{}\n{}\n{}\n{}",
            origin_line, type_line, hash_line, key_line
        )
    };

    let sig = crypto::sign(secret, canonical.as_bytes());
    let sig_b64 = crate::base64_encode(&sig.0);

    let raw_lines = if let Some(p) = parent_hash {
        let parent_line = format!("parent: {}", p);
        vec![
            origin_line,
            type_line,
            parent_line,
            hash_line,
            time_line,
            key_line,
            format!("sig: {}", sig_b64),
        ]
    } else {
        vec![
            origin_line,
            type_line,
            hash_line,
            time_line,
            key_line,
            format!("sig: {}", sig_b64),
        ]
    };

    Ok(Statement {
        origin: PROTOCOL_VERSION.to_string(),
        parent: parent_hash.map(|s| s.to_string()),
        hash: hash_str,
        hash_hex: hash_hex_str,
        hash_alg: algorithm,
        hash_bytes: hash_bytes_vec,
        time: timestamp,
        key_b64: public_b64,
        key_bytes: pair.public.0,
        sig_b64,
        sig_bytes: sig.0,
        raw_lines,
        parent_present: parent_hash.is_some(),
    })
}

/// Encode a statement as a byte sequence (the .origin file content).
///
/// The output is a UTF-8 encoded text file with `\n` line endings.
pub fn encode_statement(stmt: &Statement) -> Vec<u8> {
    let mut result = String::new();
    for line in &stmt.raw_lines {
        result.push_str(line);
        result.push('\n');
    }
    result.into_bytes()
}

/// Verify a parsed statement against artifact bytes.
///
/// Checks that:
/// 1. The artifact hash matches the statement's hash field
/// 2. The Ed25519 signature is valid for the canonical body
///
/// For most users, `verify_bytes` is simpler — it handles parsing too.
pub fn verify_statement(stmt: &Statement, artifact_bytes: &[u8]) -> Result<()> {
    let (actual_hash_hex, _) = hash::hash_data(artifact_bytes, &stmt.hash_alg);
    if actual_hash_hex != stmt.hash_hex {
        return Err(Error::HashMismatch {
            expected: stmt.hash_hex.clone(),
            actual: actual_hash_hex,
        });
    }

    let public_key = crypto::PublicKey::from_bytes(&stmt.key_bytes)?;
    let canonical = stmt.canonical_body();
    let sig = crypto::Signature::from_bytes(&stmt.sig_bytes)?;
    crypto::verify(&public_key, &canonical, &sig)
}

/// Verify a statement against a trusted public key.
///
/// Like `verify_bytes`, but additionally checks that the statement's public
/// key matches the trusted key. This prevents an attacker from presenting a
/// statement signed by their own key and getting VERIFIED in return.
///
/// # Arguments
///
/// * `statement_bytes` — The complete `.origin` file content
/// * `artifact_bytes` — The artifact bytes to verify against
/// * `trusted_public_key` — The trusted public key (32 bytes)
///
/// # Returns
///
/// * `Ok(())` — The statement is valid AND signed by the trusted key
/// * `Err(Error::KeyMismatch)` — The statement's key doesn't match the trusted key
/// * `Err(Error)` — Parsing, hash, or signature verification failed
pub fn verify_against_key(
    statement_bytes: &[u8],
    artifact_bytes: &[u8],
    trusted_public_key: &[u8; 32],
) -> Result<()> {
    let stmt = Statement::parse(statement_bytes)?;
    if stmt.key_bytes != *trusted_public_key {
        return Err(Error::KeyMismatch);
    }
    verify_statement(&stmt, artifact_bytes)
}

/// Verify a statement chain where all links must use the trusted public key.
///
/// Like `verify_chain`, but additionally checks that every statement in the
/// chain (child and parent) uses the same trusted public key. This prevents
/// key substitution attacks in provenance chains.
///
/// # Arguments
///
/// * `child_bytes` — The child statement bytes
/// * `child_artifact_bytes` — The child artifact bytes
/// * `parent_bytes` — Optional parent statement bytes (required if child has parent)
/// * `parent_artifact_bytes` — Optional parent artifact bytes
/// * `trusted_public_key` — The trusted public key for ALL links in the chain
///
/// # Returns
///
/// * `Ok(())` — The chain is valid AND all links use the trusted key
/// * `Err(Error::KeyMismatch)` — Any link's key doesn't match the trusted key
/// * `Err(Error)` — Parsing, hash, signature, or parent hash mismatch
pub fn verify_chain_against_key(
    child_bytes: &[u8],
    child_artifact_bytes: &[u8],
    parent_bytes: Option<&[u8]>,
    parent_artifact_bytes: Option<&[u8]>,
    trusted_public_key: &[u8; 32],
) -> Result<()> {
    let child = Statement::parse(child_bytes)?;
    if child.key_bytes != *trusted_public_key {
        return Err(Error::KeyMismatch);
    }
    verify_statement(&child, child_artifact_bytes)?;

    if let Some(child_parent_hash) = &child.parent {
        let parent_data = parent_bytes.ok_or(Error::MissingParent)?;
        let parent_art = parent_artifact_bytes.ok_or(Error::MissingParent)?;
        let parent = Statement::parse(parent_data)?;
        if parent.key_bytes != *trusted_public_key {
            return Err(Error::KeyMismatch);
        }
        verify_statement(&parent, parent_art)?;
        if *child_parent_hash != parent.hash {
            return Err(Error::ParentMismatch {
                child_parent: child_parent_hash.clone(),
                actual_parent: parent.hash.clone(),
            });
        }
    }

    Ok(())
}

/// Verify a statement and optionally verify its parent statement.
///
/// If the child statement has a `parent` field, `parent_bytes` and
/// `parent_artifact_bytes` must be provided. The parent is verified against
/// its artifact, and the child's parent field is checked against the parent's
/// hash. If the child has no parent, the parent parameters are ignored.
///
/// NOTE: This function does NOT check the public key against a trusted key.
/// Use `verify_against_key` or `verify_chain_against_key` if you need to
/// ensure the statement was signed by a specific trusted key.
pub fn verify_chain(
    child_bytes: &[u8],
    child_artifact_bytes: &[u8],
    parent_bytes: Option<&[u8]>,
    parent_artifact_bytes: Option<&[u8]>,
) -> Result<()> {
    let child = Statement::parse(child_bytes)?;
    verify_statement(&child, child_artifact_bytes)?;

    if let Some(child_parent_hash) = &child.parent {
        let parent_data = parent_bytes.ok_or(Error::MissingParent)?;
        let parent_art = parent_artifact_bytes.ok_or(Error::MissingParent)?;
        let parent = Statement::parse(parent_data)?;
        verify_statement(&parent, parent_art)?;
        if *child_parent_hash != parent.hash {
            return Err(Error::ParentMismatch {
                child_parent: child_parent_hash.clone(),
                actual_parent: parent.hash.clone(),
            });
        }
    }

    Ok(())
}
