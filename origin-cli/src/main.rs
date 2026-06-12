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

use clap::{Parser, Subcommand};
use origin_core::{
    Statement, Verdict, audit, base64_encode, build_statement_from_hash, encode_statement,
    generate_keypair, hash_reader, verify_statement_hash,
};

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

fn read_secret_key(path: &std::path::Path) -> miette::Result<origin_core::SecretKey> {
    let bytes = std::fs::read(path)
        .map_err(|e| miette::miette!("failed to read secret key '{}': {}", path.display(), e))?;
    origin_core::SecretKey::from_bytes(&bytes).map_err(to_err)
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
            Ok(verify_statement_hash(&stmt, &actual_hash_hex))
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

            atomic_write(&secret_path, &kp.secret.0)?;
            let pub_b64 = base64_encode(&kp.public.0);
            atomic_write(&public_path, pub_b64.as_bytes())?;

            eprintln!("Secret key: {}", secret_path.display());
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
