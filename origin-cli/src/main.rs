use clap::{Parser, Subcommand};
use origin_core::{
    base64_encode, build_statement, encode_statement, generate_keypair, hash, verify_bytes,
    SecretKey, Statement,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "origin", version, about = "Cryptographic provenance for digital artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compute the SHA-256 hash of a file
    Hash {
        /// Path to the artifact file
        path: PathBuf,
    },
    /// Generate a new Ed25519 key pair
    Keygen {
        /// Output directory for key files (default: current directory)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Sign an artifact, producing a provenance statement
    Sign {
        /// Path to the artifact file
        path: PathBuf,
        /// Path to the secret key file (or '-' for stdin, or $ORIGIN_KEY env)
        #[arg(long, short)]
        key: Option<String>,
        /// Unix timestamp (default: current time)
        #[arg(long)]
        time: Option<u64>,
        /// Path to a parent statement to chain from
        #[arg(long)]
        parent: Option<PathBuf>,
    },
    /// Verify a provenance statement against an artifact
    Verify {
        /// Path to the statement file
        statement: PathBuf,
        /// Path to the artifact file
        artifact: PathBuf,
    },
    /// Display a human-readable audit of a statement
    Audit {
        /// Path to the statement file
        statement: PathBuf,
    },
}

fn load_secret_key(key_arg: &Option<String>) -> Result<SecretKey, String> {
    if let Ok(env_key) = std::env::var("ORIGIN_KEY") {
        let trimmed = env_key.trim().to_string();
        return decode_secret_key(&trimmed);
    }

    if let Some(key_src) = key_arg {
        if key_src == "-" {
            let mut input = String::new();
            std::io::stdin()
                .read_line(&mut input)
                .map_err(|e| format!("failed to read key from stdin: {}", e))?;
            return decode_secret_key(input.trim());
        }
        let data = std::fs::read_to_string(key_src)
            .map_err(|e| format!("failed to read key file '{}': {}", key_src, e))?;
        return decode_secret_key(data.trim());
    }

    Err("no secret key provided. Use --key <file> or set ORIGIN_KEY env var".into())
}

fn decode_secret_key(s: &str) -> Result<SecretKey, String> {
    let bytes = origin_core::base64_decode(s).map_err(|e| format!("invalid base64 key: {}", e))?;
    SecretKey::from_bytes(&bytes).map_err(|e| e.to_string())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hash { path } => {
            match hash::hash_file(&path) {
                Ok(h) => println!("sha256:{}", h),
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Keygen { output } => {
            let dir = output.unwrap_or_else(|| PathBuf::from("."));
            let pair = generate_keypair();
            let secret_b64 = base64_encode(&pair.secret.0);
            let public_b64 = base64_encode(&pair.public.0);

            std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
                eprintln!("error: cannot create output directory: {}", e);
                std::process::exit(1);
            });

            let sec_path = dir.join("origin-secret.key");
            let pub_path = dir.join("origin-public.key");

            std::fs::write(&sec_path, secret_b64.as_bytes()).unwrap_or_else(|e| {
                eprintln!("error: cannot write secret key: {}", e);
                std::process::exit(1);
            });
            std::fs::write(&pub_path, public_b64.as_bytes()).unwrap_or_else(|e| {
                eprintln!("error: cannot write public key: {}", e);
                std::process::exit(1);
            });

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&sec_path, std::fs::Permissions::from_mode(0o600))
                    .ok();
            }

            println!("Key pair generated:");
            println!("  Secret: {}", sec_path.display());
            println!("  Public: {}", pub_path.display());
            println!("  Public key: {}", public_b64);
        }
        Commands::Sign { path, key, time, parent } => {
            let secret = match load_secret_key(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            };

            let artifact_data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", path.display(), e);
                    std::process::exit(1);
                }
            };

            let parent_hash = if let Some(parent_path) = &parent {
                let parent_data = match std::fs::read(parent_path) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("error: cannot read parent '{}': {}", parent_path.display(), e);
                        std::process::exit(1);
                    }
                };
                let parent_stmt = match Statement::parse(&parent_data) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("error: invalid parent statement: {}", e);
                        std::process::exit(1);
                    }
                };
                Some(parent_stmt.hash)
            } else {
                None
            };

            let ts = time.unwrap_or_else(current_timestamp);
            let stmt = match build_statement(&secret, &artifact_data, ts, parent_hash.as_deref()) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            };

            let encoded = encode_statement(&stmt);
            let stmt_path = path.with_extension("origin");
            match std::fs::write(&stmt_path, &encoded) {
                Ok(_) => {
                    println!("Statement written to {}", stmt_path.display());
                }
                Err(e) => {
                    eprintln!("error: cannot write statement: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Verify {
            statement,
            artifact,
        } => {
            let stmt_data = match std::fs::read(&statement) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", statement.display(), e);
                    std::process::exit(1);
                }
            };
            let art_data = match std::fs::read(&artifact) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", artifact.display(), e);
                    std::process::exit(1);
                }
            };

            match verify_bytes(&stmt_data, &art_data) {
                Ok(()) => {
                    println!("VERIFIED");
                }
                Err(e) => {
                    println!("FAILED: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Audit { statement } => {
            let stmt_data = match std::fs::read(&statement) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", statement.display(), e);
                    std::process::exit(1);
                }
            };

            match Statement::parse(&stmt_data) {
                Ok(stmt) => {
                    println!("{}", origin_core::audit::audit(&stmt));
                }
                Err(e) => {
                    eprintln!("error: cannot parse statement: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
