use crate::crypto;
use crate::error::{Error, Result};
use crate::hash::{self, HashAlgorithm, ALLOWED_HASH_ALGORITHMS};

const PROTOCOL_VERSION: &str = "v1";
const MAX_TIMESTAMP: u64 = 253402300799;
const KEY_B64_LEN: usize = 44;
const SIG_B64_LEN: usize = 88;
const HEX_CHARS: &[u8] = b"0123456789abcdef";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementType {
    Provenance,
    Revocation,
}

impl StatementType {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatementType::Provenance => "provenance",
            StatementType::Revocation => "revocation",
        }
    }

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "provenance" => Ok(StatementType::Provenance),
            "revocation" => Ok(StatementType::Revocation),
            other => Err(Error::Format(format!(
                "unknown statement type '{}'. Allowed: provenance, revocation",
                other
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementBody {
    Provenance {
        hash: String,
        hash_hex: String,
        hash_alg: HashAlgorithm,
        hash_bytes: Vec<u8>,
        time: u64,
    },
    Revocation {
        revoked_key_b64: String,
        revoked_key_bytes: [u8; 32],
        revoked_since: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub type_: StatementType,
    pub origin: String,
    pub body: StatementBody,
    pub key_b64: String,
    pub key_bytes: [u8; 32],
    pub sig_b64: String,
    pub sig_bytes: [u8; 64],
    pub parent: Option<String>,
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
                if (cp < 0x20 && cp != 0x0a) || cp == 0x7f {
                    return Err(Error::Format(format!(
                        "line {}: control character U+{:04X} in value",
                        i + 1, cp
                    )));
                }
            }

            if !seen_keys.insert(key) {
                return Err(Error::Format(format!("duplicate key '{}'", key)));
            }

            fields.push((key, value));
        }

        // Validate origin (always line 1)
        let origin_val = fields[0].1;
        if origin_val != PROTOCOL_VERSION {
            return Err(Error::Format(format!(
                "origin must be '{}', got '{}'",
                PROTOCOL_VERSION, origin_val
            )));
        }

        // Validate type (always line 2)
        if fields[1].0 != "type" {
            return Err(Error::Format(format!(
                "line 2: expected key 'type', got '{}'",
                fields[1].0
            )));
        }
        let type_val = StatementType::from_str(fields[1].1)?;

        match type_val {
            StatementType::Provenance => Self::parse_provenance(fields, lines, origin_val),
            StatementType::Revocation => Self::parse_revocation(fields, lines, origin_val),
        }
    }

    fn parse_provenance(
        fields: Vec<(&str, &str)>,
        lines: Vec<&str>,
        origin_val: &str,
    ) -> Result<Self> {
        let has_parent = fields.len() == 7;
        let expected_keys: Vec<&str> = if has_parent {
            vec!["origin", "type", "parent", "hash", "time", "key", "sig"]
        } else {
            vec!["origin", "type", "hash", "time", "key", "sig"]
        };

        for (i, (key, _)) in fields.iter().enumerate() {
            if *key != expected_keys[i] {
                return Err(Error::Format(format!(
                    "line {}: expected key '{}', got '{}'",
                    i + 1, expected_keys[i], key
                )));
            }
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
            type_: StatementType::Provenance,
            origin: origin_val.to_string(),
            body: StatementBody::Provenance {
                hash: hash_val,
                hash_hex: hash_hex_str,
                hash_alg,
                hash_bytes,
                time,
            },
            key_b64: fields[key_idx].1.to_string(),
            key_bytes,
            sig_b64: fields[sig_idx].1.to_string(),
            sig_bytes,
            parent: parent_val,
            raw_lines,
            parent_present: has_parent,
        })
    }

    fn parse_revocation(
        fields: Vec<(&str, &str)>,
        lines: Vec<&str>,
        origin_val: &str,
    ) -> Result<Self> {
        let expected_keys = vec!["origin", "type", "revoked", "since", "key", "sig"];

        if fields.len() != 6 {
            return Err(Error::Format(format!(
                "revocation statement: expected 6 lines, got {}",
                fields.len()
            )));
        }

        for (i, (key, _)) in fields.iter().enumerate() {
            if *key != expected_keys[i] {
                return Err(Error::Format(format!(
                    "line {}: expected key '{}', got '{}'",
                    i + 1, expected_keys[i], key
                )));
            }
        }

        let revoked_key_val = fields[2].1;
        let key_raw = validate_base64url(revoked_key_val, KEY_B64_LEN, 32)?;
        let mut revoked_key_bytes = [0u8; 32];
        revoked_key_bytes.copy_from_slice(&key_raw);

        let since = validate_timestamp(fields[3].1)?;

        let key_val = fields[4].1;
        let key_raw2 = validate_base64url(key_val, KEY_B64_LEN, 32)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key_raw2);

        let sig_raw = validate_base64url(fields[5].1, SIG_B64_LEN, 64)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig_raw);

        let raw_lines: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();

        Ok(Statement {
            type_: StatementType::Revocation,
            origin: origin_val.to_string(),
            body: StatementBody::Revocation {
                revoked_key_b64: revoked_key_val.to_string(),
                revoked_key_bytes,
                revoked_since: since,
            },
            key_b64: key_val.to_string(),
            key_bytes,
            sig_b64: fields[5].1.to_string(),
            sig_bytes,
            parent: None,
            raw_lines,
            parent_present: false,
        })
    }

    pub fn canonical_body(&self) -> Vec<u8> {
        match self.type_ {
            StatementType::Provenance => self.canonical_provenance(),
            StatementType::Revocation => self.canonical_revocation(),
        }
    }

    fn canonical_provenance(&self) -> Vec<u8> {
        // raw_lines: [origin, type, (parent), hash, time, key, sig]
        // Canonical: origin, type, (parent), hash, key
        if self.parent_present {
            let mut body = String::new();
            body.push_str(&self.raw_lines[0]); body.push('\n');
            body.push_str(&self.raw_lines[1]); body.push('\n');
            body.push_str(&self.raw_lines[2]); body.push('\n');
            body.push_str(&self.raw_lines[3]); body.push('\n');
            body.push_str(&self.raw_lines[5]);
            body.into_bytes()
        } else {
            let mut body = String::new();
            body.push_str(&self.raw_lines[0]); body.push('\n');
            body.push_str(&self.raw_lines[1]); body.push('\n');
            body.push_str(&self.raw_lines[2]); body.push('\n');
            body.push_str(&self.raw_lines[4]);
            body.into_bytes()
        }
    }

    fn canonical_revocation(&self) -> Vec<u8> {
        // raw_lines: [origin, type, revoked, since, key, sig]
        // Canonical: origin, type, revoked, since, key
        let mut body = String::new();
        body.push_str(&self.raw_lines[0]); body.push('\n');
        body.push_str(&self.raw_lines[1]); body.push('\n');
        body.push_str(&self.raw_lines[2]); body.push('\n');
        body.push_str(&self.raw_lines[3]); body.push('\n');
        body.push_str(&self.raw_lines[4]);
        body.into_bytes()
    }

    pub fn has_parent(&self) -> bool {
        self.parent_present
    }

    pub fn parent_hash_hex(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    // Convenience accessors for provenance body fields
    pub fn hash_str(&self) -> Option<&str> {
        match &self.body {
            StatementBody::Provenance { hash, .. } => Some(hash),
            _ => None,
        }
    }

    pub fn hash_hex(&self) -> Option<&str> {
        match &self.body {
            StatementBody::Provenance { hash_hex, .. } => Some(hash_hex),
            _ => None,
        }
    }

    pub fn hash_alg(&self) -> Option<&HashAlgorithm> {
        match &self.body {
            StatementBody::Provenance { hash_alg, .. } => Some(hash_alg),
            _ => None,
        }
    }

    pub fn time(&self) -> Option<u64> {
        match &self.body {
            StatementBody::Provenance { time, .. } => Some(*time),
            _ => None,
        }
    }

    pub fn revoked_key_b64(&self) -> Option<&str> {
        match &self.body {
            StatementBody::Revocation { revoked_key_b64, .. } => Some(revoked_key_b64),
            _ => None,
        }
    }

    pub fn revoked_since(&self) -> Option<u64> {
        match &self.body {
            StatementBody::Revocation { revoked_since, .. } => Some(*revoked_since),
            _ => None,
        }
    }
}

pub fn build_statement(
    secret: &crypto::SecretKey,
    artifact_bytes: &[u8],
    timestamp: u64,
    parent_hash: Option<&str>,
) -> Result<Statement> {
    let (hash_hex_str, hash_bytes_vec) = hash::hash_data(artifact_bytes, &HashAlgorithm::Sha256);
    let hash_str = format!("sha256:{}", hash_hex_str);

    let pair = crypto::generate_keypair_from_seed(&secret.0);
    let public_b64 = crate::base64_encode(pair.public.as_bytes());

    let origin_line = format!("origin: {}", PROTOCOL_VERSION);
    let type_line = "type: provenance".to_string();
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
        type_: StatementType::Provenance,
        origin: PROTOCOL_VERSION.to_string(),
        body: StatementBody::Provenance {
            hash: hash_str,
            hash_hex: hash_hex_str,
            hash_alg: HashAlgorithm::Sha256,
            hash_bytes: hash_bytes_vec,
            time: timestamp,
        },
        key_b64: public_b64,
        key_bytes: pair.public.0,
        sig_b64,
        sig_bytes: sig.0,
        parent: parent_hash.map(|s| s.to_string()),
        raw_lines,
        parent_present: parent_hash.is_some(),
    })
}

pub fn build_revocation_statement(
    secret: &crypto::SecretKey,
    revoked_public_key_b64: &str,
    since: u64,
    signer_public_key_b64: &str,
) -> Result<Statement> {
    // Validate inputs
    validate_base64url(revoked_public_key_b64, KEY_B64_LEN, 32)?;
    validate_base64url(signer_public_key_b64, KEY_B64_LEN, 32)?;

    let origin_line = format!("origin: {}", PROTOCOL_VERSION);
    let type_line = "type: revocation".to_string();
    let revoked_line = format!("revoked: {}", revoked_public_key_b64);
    let since_line = format!("since: {}", since);
    let key_line = format!("key: {}", signer_public_key_b64);

    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}",
        origin_line, type_line, revoked_line, since_line, key_line
    );

    let sig = crypto::sign(secret, canonical.as_bytes());
    let sig_b64 = crate::base64_encode(&sig.0);

    let revoked_key_bytes_val = {
        let raw = crate::base64_decode(revoked_public_key_b64)
            .map_err(|_| Error::Format("invalid base64 in revoked key".into()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw);
        arr
    };

    let raw_lines = vec![
        origin_line,
        type_line,
        revoked_line,
        since_line,
        key_line,
        format!("sig: {}", sig_b64),
    ];

    Ok(Statement {
        type_: StatementType::Revocation,
        origin: PROTOCOL_VERSION.to_string(),
        body: StatementBody::Revocation {
            revoked_key_b64: revoked_public_key_b64.to_string(),
            revoked_key_bytes: revoked_key_bytes_val,
            revoked_since: since,
        },
        key_b64: signer_public_key_b64.to_string(),
        key_bytes: {
            let raw = crate::base64_decode(signer_public_key_b64)
                .map_err(|_| Error::Format("invalid base64 in key".into()))?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            arr
        },
        sig_b64,
        sig_bytes: sig.0,
        parent: None,
        raw_lines,
        parent_present: false,
    })
}

pub fn encode_statement(stmt: &Statement) -> Vec<u8> {
    let mut result = String::new();
    for line in &stmt.raw_lines {
        result.push_str(line);
        result.push('\n');
    }
    result.into_bytes()
}

pub fn verify_statement(stmt: &Statement, artifact_bytes: &[u8]) -> Result<()> {
    match &stmt.body {
        StatementBody::Provenance { hash_hex, hash_alg, .. } => {
            let (actual_hash_hex, _) = hash::hash_data(artifact_bytes, hash_alg);
            if actual_hash_hex != *hash_hex {
                return Err(Error::HashMismatch {
                    expected: hash_hex.clone(),
                    actual: actual_hash_hex,
                });
            }

            let public_key = crypto::PublicKey::from_bytes(&stmt.key_bytes)?;
            let canonical = stmt.canonical_body();
            let sig = crypto::Signature::from_bytes(&stmt.sig_bytes)?;
            crypto::verify(&public_key, &canonical, &sig)
        }
        StatementBody::Revocation { .. } => {
            Err(Error::Format("cannot verify a revocation statement against an artifact".into()))
        }
    }
}

pub fn verify_revocation(stmt: &Statement) -> Result<()> {
    match &stmt.body {
        StatementBody::Revocation { .. } => {
            let public_key = crypto::PublicKey::from_bytes(&stmt.key_bytes)?;
            let canonical = stmt.canonical_body();
            let sig = crypto::Signature::from_bytes(&stmt.sig_bytes)?;
            crypto::verify(&public_key, &canonical, &sig)
        }
        StatementBody::Provenance { .. } => {
            Err(Error::Format("statement is not a revocation".into()))
        }
    }
}
