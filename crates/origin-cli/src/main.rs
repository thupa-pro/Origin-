// SPDX-License-Identifier: MIT

//! Origin CLI — cryptographic provenance for digital artifacts.
//!
//! This binary provides a command-line interface to the Origin protocol:
//! signing, verification, audit, identity binding, and key generation.
//! All I/O is streaming (no `fs::read` of artifact files); writes are atomic
//! via tempfile + rename; errors use `miette` for structured diagnostics.

#![deny(missing_docs)]

use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305,
};
use clap::{Parser, Subcommand};
use origin_core::{
    Statement, Verdict, audit, base64_encode, build_statement_from_hash, encode_statement,
    generate_keypair, hash_reader, verify_statement_hash_with_time,
};
use rpassword::prompt_password;

fn to_err(e: origin_core::Error) -> miette::Report {
    miette::miette!("{}", e)
}

/// Origin CLI entry point and subcommand dispatch.
#[derive(Parser)]
#[command(
    name = "origin",
    version,
    about = "Cryptographic provenance for digital artifacts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available subcommands for the Origin CLI.
#[derive(Subcommand)]
enum Command {
    /// Hash and sign an artifact, producing a .origin statement
    Sign {
        /// Path to the artifact file
        artifact: PathBuf,
        /// Path to the Ed25519 secret key (32 raw bytes)
        #[arg(long, short)]
        key: PathBuf,
        /// Unix timestamp (default: current time)
        #[arg(long)]
        time: Option<u64>,
        /// Output path for the .origin file (default: <artifact>.origin)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Verify an artifact against its .origin statement
    Verify {
        /// Path to the artifact file
        artifact: PathBuf,
        /// Path to the .origin statement file
        #[arg(long, short)]
        origin: PathBuf,
        /// Optional trusted public key (base64url, 44 chars)
        #[arg(long)]
        key: Option<String>,
        /// Optional current time for clock-skew check (default: system time)
        #[arg(long)]
        time: Option<u64>,
    },
    /// Display fields of a .origin statement without verifying
    Audit {
        /// Path to the .origin statement file
        origin: PathBuf,
    },
    /// Bind an identity string to a public key
    Id {
        /// Identity string (e.g. email, domain, handle)
        #[arg(long)]
        identity: String,
        /// Path to the Ed25519 secret key (32 raw bytes)
        #[arg(long, short)]
        key: PathBuf,
        /// Output path (default: <identity>.origin)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Generate a new Ed25519 key pair
    GenerateKey {
        /// Output path prefix (creates <prefix>.key and <prefix>.pub)
        #[arg(long, short, default_value = "origin-secret")]
        output: String,
    },
}

fn derive_key(passphrase: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .expect("Argon2 hashing cannot fail with valid inputs");
    key
}

fn encrypt_secret_key(secret: &[u8; 32], passphrase: &str) -> miette::Result<Vec<u8>> {
    let salt: [u8; 16] = rand::random();
    let key = derive_key(passphrase, &salt);
    let cipher = XChaCha20Poly1305::new(&key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, secret.as_ref())
        .map_err(|e| miette::miette!("encryption failed: {}", e))?;
    let mut output = Vec::with_capacity(16 + 24 + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt_secret_key(data: &[u8], passphrase: &str) -> miette::Result<[u8; 32]> {
    if data.len() < 16 + 24 {
        return Err(miette::miette!("invalid encrypted key file: too short"));
    }
    let salt: [u8; 16] = data[0..16].try_into()
        .expect("first 16 bytes are salt");
    let nonce: [u8; 24] = data[16..40].try_into()
        .expect("bytes 16-39 are nonce");
    let ciphertext = &data[40..];
    let key = derive_key(passphrase, &salt);
    let cipher = XChaCha20Poly1305::new(&key.into());
    let plaintext = cipher.decrypt((&nonce).into(), ciphertext)
        .map_err(|_| miette::miette!("decryption failed: incorrect passphrase or corrupted file"))?;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&plaintext);
    Ok(secret)
}

fn read_secret_key(path: &std::path::Path) -> miette::Result<origin_core::SecretKey> {
    let data = std::fs::read(path)
        .map_err(|e| miette::miette!("failed to read secret key '{}': {}", path.display(), e))?;
    
    // Check if file is encrypted (has salt+nonce+ciphertext structure)
    if data.len() > 40 {
        let passphrase = prompt_password("Enter passphrase for secret key: ")
            .map_err(|e| miette::miette!("failed to read passphrase: {}", e))?;
        let secret = decrypt_secret_key(&data, &passphrase)?;
        return origin_core::SecretKey::from_bytes(&secret).map_err(to_err);
    }
    
    // Check if file looks like raw 32-byte key
    if data.len() == 32 {
        eprintln!(
            "W003 WARNING: Reading raw unencrypted secret key from '{}'. \
             Secret keys should be encrypted. Use `origin generate-key` to create an encrypted key.",
            path.display()
        );
        return origin_core::SecretKey::from_bytes(&data).map_err(to_err);
    }
    
    Err(miette::miette!(
        "invalid key file '{}': unexpected length {} (expected encrypted key >40 bytes or raw 32-byte key)",
        path.display(),
        data.len()
    ))
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time is before unix epoch")
        .as_secs()
}

fn atomic_write(path: &std::path::Path, contents: &[u8]) -> miette::Result<()> {
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| miette::miette!("failed to create temp file in '{}': {}", dir.display(), e))?;
    std::io::Write::write_all(&mut tmp, contents)
        .map_err(|e| miette::miette!("failed to write temp file: {}", e))?;
    tmp.persist(path).map_err(|e| {
        miette::miette!("failed to rename temp file to '{}': {}", path.display(), e)
    })?;
    Ok(())
}

fn read_small_file(path: &std::path::Path) -> miette::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| miette::miette!("failed to read '{}': {}", path.display(), e))
}

/// Stream-hash an artifact file, returning the raw hash bytes and hex string.
fn hash_artifact(path: &std::path::Path) -> miette::Result<([u8; 32], String)> {
    let file = std::fs::File::open(path)
        .map_err(|e| miette::miette!("failed to open '{}': {}", path.display(), e))?;
    let reader = BufReader::with_capacity(65536, file);
    let hash = hash_reader(reader).map_err(to_err)?;
    let hex_str = hex::encode(hash);
    Ok((hash, hex_str))
}

fn run(cli: Cli) -> miette::Result<Verdict> {
    match cli.command {
        Command::Sign {
            artifact,
            key,
            time,
            output,
        } => {
            let secret = read_secret_key(&key)?;
            let ts = time.unwrap_or_else(timestamp_now);

            if let Some(_requested_ts) = time {
                let now = timestamp_now();
                // Reject timestamps before Origin protocol epoch (2024-01-01)
                const MIN_TS: u64 = 1_704_067_200;
                if ts < MIN_TS {
                    return Err(miette::miette!(
                        "--time {} is before the Origin protocol epoch ({}). \
                         Cannot backdate a provenance statement before the protocol existed.",
                        ts, MIN_TS
                    ));
                }
                // Warn when --time is more than 5 minutes in the future
                if ts > now.saturating_add(300) {
                    eprintln!(
                        "W002 WARNING: --time {} is {}s in the future (now={}). \
                         This may indicate clock skew.",
                        ts,
                        ts.saturating_sub(now),
                        now
                    );
                }
                // Warn when --time is more than 24 hours in the past
                if now.saturating_sub(ts) > 86_400 {
                    eprintln!(
                        "W002 WARNING: --time {} is {}s in the past (now={}). \
                         Backdating by more than 24 hours may erode trust.",
                        ts,
                        now.saturating_sub(ts),
                        now
                    );
                }
            }

            let (hash, hash_hex) = hash_artifact(&artifact)?;
            let stmt = build_statement_from_hash(&secret, &hash_hex, &hash, ts).map_err(to_err)?;

            let out_path = output.unwrap_or_else(|| {
                let mut p = artifact;
                let name = p
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                p.set_file_name(format!("{}.origin", name));
                p
            });

            let encoded = encode_statement(&stmt);
            atomic_write(&out_path, &encoded)?;
            eprintln!("Wrote {}", out_path.display());
            Ok(Ok(()))
        }

        Command::Verify {
            artifact,
            origin,
            key,
            time,
        } => {
            let statement_bytes = match read_small_file(&origin) {
                Ok(b) => b,
                Err(_) if !origin.exists() => {
                    return Err(miette::miette!(
                        "no provenance file '{}' for artifact '{}'",
                        origin.display(),
                        artifact.display()
                    ));
                }
                Err(e) => return Err(e),
            };
            let stmt = Statement::parse(&statement_bytes).map_err(to_err)?;

            if let Some(trusted_key_b64) = key {
                let trusted_bytes = origin_core::base64_decode(&trusted_key_b64)
                    .map_err(|e| miette::miette!("invalid trusted key format: {}", e))?;
                if trusted_bytes != stmt.key_bytes {
                    return Err(miette::miette!(
                        "public key mismatch: statement key does not match trusted key"
                    ));
                }
            }

            let (_hash, actual_hash_hex) = hash_artifact(&artifact)?;
            let now = time.or_else(|| Some(timestamp_now()));
            Ok(verify_statement_hash_with_time(&stmt, &actual_hash_hex, now, None, None))
        }

        Command::Audit { origin } => {
            let statement_bytes = read_small_file(&origin)?;
            let stmt = Statement::parse(&statement_bytes).map_err(to_err)?;
            println!("{}", audit::audit(&stmt));
            Ok(Ok(()))
        }

        Command::Id {
            identity,
            key,
            output,
        } => {
            let secret = read_secret_key(&key)?;
            let identity_bytes = identity.as_bytes();
            let hash = origin_core::hash::hash_bytes(identity_bytes);
            let hash_hex_str = hex::encode(hash);
            let ts = timestamp_now();

            let stmt =
                build_statement_from_hash(&secret, &hash_hex_str, &hash, ts).map_err(to_err)?;

            let out_path = output.unwrap_or_else(|| {
                let name = identity
                    .chars()
                    .map(|c| {
                        if c.is_alphanumeric() || c == '@' || c == '.' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect::<String>();
                PathBuf::from(format!("{}.origin", name))
            });
            let encoded = encode_statement(&stmt);
            atomic_write(&out_path, &encoded)?;
            eprintln!("Identity binding: key claims identity '{}'", identity);
            eprintln!("Hash: sha256:{}", hash_hex_str);
            eprintln!("Wrote {}", out_path.display());
            Ok(Ok(()))
        }

        Command::GenerateKey { output } => {
            let kp = generate_keypair();
            let secret_path = PathBuf::from(format!("{}.key", output));
            let public_path = PathBuf::from(format!("{}.pub", output));

            let passphrase = prompt_password("Enter passphrase to encrypt secret key: ")
                .map_err(|e| miette::miette!("failed to read passphrase: {}", e))?;
            let encrypted = encrypt_secret_key(&kp.secret.0, &passphrase)?;
            atomic_write(&secret_path, &encrypted)?;
            
            let pub_b64 = base64_encode(&kp.public.0);
            atomic_write(&public_path, pub_b64.as_bytes())?;

            eprintln!("W001 WARNING: Encrypted secret key written to '{}'. Do not commit or share this file.", secret_path.display());
            eprintln!("Secret key (encrypted): {}", secret_path.display());
            eprintln!("Public key: {} ({})", pub_b64, public_path.display());
            Ok(Ok(()))
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(e)) => {
            eprintln!("FAILED: {}", e);
            ExitCode::from(1)
        }
        Err(report) => {
            eprintln!("{:?}", report);
            ExitCode::from(1)
        }
    }
}
