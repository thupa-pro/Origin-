use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use origin_core::{
    Statement, Verdict, audit, base64_encode, build_statement, encode_statement, generate_keypair,
    hash::hash_hex, verify_statement,
};

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

fn read_secret_key(path: &std::path::Path) -> origin_core::Result<origin_core::SecretKey> {
    let bytes = std::fs::read(path).map_err(|e| {
        origin_core::Error::Io(format!(
            "failed to read secret key '{}': {}",
            path.display(),
            e
        ))
    })?;
    origin_core::SecretKey::from_bytes(&bytes)
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time is before unix epoch")
        .as_secs()
}

fn run(cli: Cli) -> Result<Verdict, origin_core::Error> {
    match cli.command {
        Command::Sign {
            artifact,
            key,
            time,
            output,
        } => {
            let secret = read_secret_key(&key)?;
            let ts = time.unwrap_or_else(timestamp_now);
            let artifact_bytes = std::fs::read(&artifact)
                .map_err(|e| origin_core::Error::Io(format!("reading artifact: {}", e)))?;
            let stmt = build_statement(&secret, &artifact_bytes, ts)?;
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
            std::fs::write(&out_path, &encoded).map_err(|e| {
                origin_core::Error::Io(format!("writing '{}': {}", out_path.display(), e))
            })?;
            eprintln!("Wrote {}", out_path.display());
            Ok(Ok(()))
        }

        Command::Verify {
            artifact,
            origin,
            key,
        } => {
            let statement_bytes = match std::fs::read(&origin) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(origin_core::Error::Unattested(format!(
                        "no provenance file '{}' for artifact '{}'",
                        origin.display(),
                        artifact.display()
                    )));
                }
                Err(e) => {
                    return Err(origin_core::Error::Io(format!(
                        "reading '{}': {}",
                        origin.display(),
                        e
                    )));
                }
            };
            let stmt = Statement::parse(&statement_bytes)?;

            if let Some(trusted_key_b64) = key {
                let trusted_bytes = origin_core::base64_decode(&trusted_key_b64)
                    .map_err(|e| origin_core::Error::Format(e.to_string()))?;
                if trusted_bytes != stmt.key_bytes {
                    return Err(origin_core::Error::Crypto(
                        "public key mismatch: statement key does not match trusted key".into(),
                    ));
                }
            }

            let artifact_bytes = std::fs::read(&artifact).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    origin_core::Error::Unattested(format!(
                        "artifact '{}' not found",
                        artifact.display()
                    ))
                } else {
                    origin_core::Error::Io(e.to_string())
                }
            })?;
            Ok(verify_statement(&stmt, &artifact_bytes))
        }

        Command::Audit { origin } => {
            let statement_bytes = std::fs::read(&origin).map_err(|e| {
                origin_core::Error::Io(format!("reading '{}': {}", origin.display(), e))
            })?;
            let stmt = Statement::parse(&statement_bytes)?;
            println!("{}", audit::audit(&stmt));
            Ok(Ok(()))
        }

        Command::Id {
            identity,
            key,
            output,
        } => {
            let secret = read_secret_key(&key)?;
            let identity_hash = hash_hex(identity.as_bytes());
            let ts = timestamp_now();

            let stmt = build_statement(&secret, identity.as_bytes(), ts)?;

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
            std::fs::write(&out_path, &encoded).map_err(|e| {
                origin_core::Error::Io(format!("writing '{}': {}", out_path.display(), e))
            })?;
            eprintln!("Identity binding: key claims identity '{}'", identity);
            eprintln!("Hash: sha256:{}", identity_hash);
            eprintln!("Wrote {}", out_path.display());
            Ok(Ok(()))
        }

        Command::GenerateKey { output } => {
            let kp = generate_keypair();
            let secret_path = PathBuf::from(format!("{}.key", output));
            let public_path = PathBuf::from(format!("{}.pub", output));

            std::fs::write(&secret_path, &kp.secret.0).map_err(|e| {
                origin_core::Error::Io(format!("writing '{}': {}", secret_path.display(), e))
            })?;
            let pub_b64 = base64_encode(&kp.public.0);
            std::fs::write(&public_path, &pub_b64).map_err(|e| {
                origin_core::Error::Io(format!("writing '{}': {}", public_path.display(), e))
            })?;

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
        Err(origin_core::Error::Unattested(msg)) => {
            eprintln!("UNATTESTED: {}", msg);
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("ERROR: {}", e);
            ExitCode::from(1)
        }
    }
}
