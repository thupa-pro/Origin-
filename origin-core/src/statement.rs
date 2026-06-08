use crate::crypto;
use crate::error::{Error, Result};
use crate::hash::{self, HashAlgorithm, ALLOWED_HASH_ALGORITHMS};

const PROTOCOL_VERSION: &str = "v1";
const MAX_TIMESTAMP: u64 = 253402300799;
const KEY_B64_LEN: usize = 44;
const SIG_B64_LEN: usize = 88;
const HEX_CHARS: &[u8] = b"0123456789abcdef";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub origin: String,
    pub parent: Option<String>,
    pub hash: String,
    pub hash_hex: String,
    pub hash_alg: HashAlgorithm,
    pub hash_bytes: Vec<u8>,
    pub time: u64,
    pub key_b64: String,
    pub key_bytes: [u8; 32],
    pub sig_b64: String,
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

        if lines.len() < 5 || lines.len() > 6 {
            return Err(Error::Format(format!(
                "expected 5 or 6 lines, got {}",
                lines.len()
            )));
        }

        for (i, line) in lines.iter().enumerate() {
            if line.is_empty() {
                return Err(Error::Format(format!("line {} is empty", i + 1)));
            }
        }

        // Determine expected key order
        let has_parent = lines.len() == 6;
        let expected_order: Vec<&str> = if has_parent {
            vec!["origin", "parent", "hash", "time", "key", "sig"]
        } else {
            vec!["origin", "hash", "time", "key", "sig"]
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
                if (cp < 0x20 && cp != 0x0a) || cp == 0x7f {
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

        // Extract parent if present
        let parent_val;
        let hash_val;
        let time_val;
        let key_val;
        let sig_val;

        if has_parent {
            parent_val = Some(fields[1].1.to_string());
            hash_val = fields[2].1;
            time_val = fields[3].1;
            key_val = fields[4].1;
            sig_val = fields[5].1;
        } else {
            parent_val = None;
            hash_val = fields[1].1;
            time_val = fields[2].1;
            key_val = fields[3].1;
            sig_val = fields[4].1;
        }

        // Validate parent hash if present
        if let Some(ref p) = parent_val {
            parse_hash_string(p)?;
        }

        // Validate artifact hash
        let (hash_alg, hash_hex_str, hash_bytes) = parse_hash_string(hash_val)?;

        // Validate timestamp (advisory — not in canonical body)
        if !time_val.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Format("timestamp must be ASCII digits".into()));
        }
        if time_val.len() > 1 && time_val.starts_with('0') {
            return Err(Error::Format("timestamp must not have leading zeros".into()));
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

        // Validate key
        let key_raw = validate_base64url(key_val, KEY_B64_LEN, 32)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key_raw);

        // Validate signature
        let sig_raw = validate_base64url(sig_val, SIG_B64_LEN, 64)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&sig_raw);

        let raw_lines: Vec<String> = lines.iter().map(|s| (*s).to_string()).collect();

        Ok(Statement {
            origin: origin_val.to_string(),
            parent: parent_val,
            hash: hash_val.to_string(),
            hash_hex: hash_hex_str,
            hash_alg,
            hash_bytes,
            time,
            key_b64: key_val.to_string(),
            key_bytes,
            sig_b64: sig_val.to_string(),
            sig_bytes,
            raw_lines,
            parent_present: has_parent,
        })
    }

    pub fn canonical_body(&self) -> Vec<u8> {
        let raw0 = &self.raw_lines[0];

        if self.parent_present {
            let raw1 = &self.raw_lines[1];
            let raw2 = &self.raw_lines[2];
            let key_line = &self.raw_lines[4];
            // ^ In the raw_lines array: with parent, key is at index 4; without, at index 3

            // Actually, let me be more careful. The raw_lines stores all lines as parsed.
            // For canonical body, we need:
            // origin: v1
            // parent: ... (if present)
            // hash: ...
            // key: ...
            // (no time, no sig)

            // The raw_lines content for has_parent=true:
            // [0]: origin: v1
            // [1]: parent: sha256:...
            // [2]: hash: sha256:...
            // [3]: time: ...
            // [4]: key: ...
            // [5]: sig: ...

            // Canonical body: lines 0, 1, 2, 4 (origin, parent, hash, key)
            // with \n between, no trailing \n

            let mut body = String::new();
            body.push_str(raw0); body.push('\n');
            body.push_str(raw1); body.push('\n');
            body.push_str(raw2); body.push('\n');
            body.push_str(key_line);
            body.into_bytes()
        } else {
            // Without parent:
            // [0]: origin: v1
            // [1]: hash: ...
            // [2]: time: ...
            // [3]: key: ...
            // [4]: sig: ...

            // Canonical body: lines 0, 1, 3 (origin, hash, key)
            let raw1 = &self.raw_lines[1];
            let key_line = &self.raw_lines[3];

            let mut body = String::new();
            body.push_str(raw0); body.push('\n');
            body.push_str(raw1); body.push('\n');
            body.push_str(key_line);
            body.into_bytes()
        }
    }

    pub fn has_parent(&self) -> bool {
        self.parent_present
    }

    pub fn parent_hash_hex(&self) -> Option<&str> {
        self.parent.as_deref()
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
    let hash_line = format!("hash: {}", hash_str);
    let time_line = format!("time: {}", timestamp);
    let key_line = format!("key: {}", public_b64);

    // Build canonical body (time excluded, parent included if present)
    let canonical = if let Some(p) = parent_hash {
        let parent_line = format!("parent: {}", p);
        format!(
            "{}\n{}\n{}\n{}",
            origin_line, parent_line, hash_line, key_line
        )
    } else {
        format!(
            "{}\n{}\n{}",
            origin_line, hash_line, key_line
        )
    };

    let sig = crypto::sign(secret, canonical.as_bytes());
    let sig_b64 = crate::base64_encode(&sig.0);

    let raw_lines = if let Some(p) = parent_hash {
        let parent_line = format!("parent: {}", p);
        vec![
            origin_line,
            parent_line,
            hash_line,
            time_line,
            key_line,
            format!("sig: {}", sig_b64),
        ]
    } else {
        vec![
            origin_line,
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
        hash_alg: HashAlgorithm::Sha256,
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

pub fn encode_statement(stmt: &Statement) -> Vec<u8> {
    let mut result = String::new();
    result.push_str(&stmt.raw_lines[0]); result.push('\n');
    if stmt.parent_present {
        result.push_str(&stmt.raw_lines[1]); result.push('\n');
        // raw_lines[2] is hash, [3] is time, [4] is key, [5] is sig
        result.push_str(&stmt.raw_lines[2]); result.push('\n');
        result.push_str(&stmt.raw_lines[3]); result.push('\n');
        result.push_str(&stmt.raw_lines[4]); result.push('\n');
        result.push_str(&stmt.raw_lines[5]); result.push('\n');
    } else {
        result.push_str(&stmt.raw_lines[1]); result.push('\n');
        result.push_str(&stmt.raw_lines[2]); result.push('\n');
        result.push_str(&stmt.raw_lines[3]); result.push('\n');
        result.push_str(&stmt.raw_lines[4]); result.push('\n');
    }
    result.into_bytes()
}

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
