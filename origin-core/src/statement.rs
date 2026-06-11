use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashSet;

use crate::crypto;
use crate::error::{Error, Result};
use crate::hash;

const PROTOCOL_VERSION: &str = "v1";
const MAX_TIMESTAMP: u64 = 253402300799;
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

fn validate_base64url(s: &str, expected_len: usize) -> Result<Vec<u8>> {
    if s.len() != expected_len {
        return Err(Error::Format(format!(
            "base64url length {} (expected {})",
            s.len(),
            expected_len
        )));
    }
    let bytes = crate::base64_decode(s)?;
    Ok(bytes)
}

impl Statement {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let text = core::str::from_utf8(data).map_err(|_| Error::Format("not valid UTF-8".into()))?;

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
                        i + 1, cp
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
                    i + 1, VALID_KEYS[i], key
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
        let hash_bytes =
            hex::decode(hash_hex).map_err(|_| Error::Format("invalid hex encoding".into()))?;
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

        let key_raw = validate_base64url(key_val, KEY_B64_LEN)?;
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&key_raw);
        crypto::validate_public_key(&key_bytes)?;

        let sig_raw = validate_base64url(sig_val, SIG_B64_LEN)?;
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
        })
    }

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

pub fn build_statement(
    secret: &crypto::SecretKey,
    artifact_bytes: &[u8],
    timestamp: u64,
) -> Result<Statement> {
    let hash_hex_str = hash::hash_hex(artifact_bytes);
    let hash_str = format!("sha256:{}", hash_hex_str);

    let kp = crypto::generate_keypair_from_seed(&secret.0);
    let public = &kp.public;
    let public_b64 = crate::base64_encode(&public.0);

    let origin_line = format!("origin: {}", PROTOCOL_VERSION);
    let hash_line = format!("hash: {}", hash_str);
    let time_line = format!("time: {}", timestamp);
    let key_line = format!("key: {}", public_b64);

    let canonical = format!("{}\n{}\n{}\n{}", origin_line, hash_line, time_line, key_line);

    let sig = crypto::sign(secret, canonical.as_bytes());
    let sig_b64 = crate::base64_encode(&sig.0);

    let hash_bytes = hash::hash_bytes(artifact_bytes);

    let raw_lines = vec![
        origin_line,
        hash_line,
        time_line,
        key_line,
        format!("sig: {}", sig_b64),
    ];

    Ok(Statement {
        origin: PROTOCOL_VERSION.to_string(),
        hash: hash_str,
        hash_bytes,
        time: timestamp,
        key_b64: public_b64,
        key_bytes: public.0,
        sig_b64,
        sig_bytes: sig.0,
        raw_lines,
    })
}

pub fn encode_statement(stmt: &Statement) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\nsig: {}\n",
        stmt.raw_lines[0], stmt.raw_lines[1], stmt.raw_lines[2], stmt.raw_lines[3], stmt.sig_b64,
    )
    .into_bytes()
}

pub fn verify_statement(stmt: &Statement, artifact_bytes: &[u8]) -> Result<()> {
    let actual_hash = hash::hash_hex(artifact_bytes);
    let expected_hash = &stmt.hash[7..];
    if actual_hash != expected_hash {
        return Err(Error::HashMismatch {
            expected: expected_hash.to_string(),
            actual: actual_hash,
        });
    }

    let public_key = crypto::PublicKey::from_bytes(&stmt.key_bytes)?;
    let canonical = stmt.canonical_body();
    let sig = crypto::Signature::from_bytes(&stmt.sig_bytes)?;
    crypto::verify(&public_key, &canonical, &sig)
}
