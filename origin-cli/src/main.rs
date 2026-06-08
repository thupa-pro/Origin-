use clap::{Parser, Subcommand};
use origin_core::{
    base64_encode, build_revocation_statement, build_statement, encode_statement,
    generate_keypair, hash, verify_bytes, verify_revocation, SecretKey, Statement, StatementType,
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
    ///
    /// Examples:
    ///   origin hash myfile.bin
    ///   origin hash container.tar.gz
    Hash {
        /// Path to the artifact file
        path: PathBuf,
    },
    /// Generate a new Ed25519 key pair
    ///
    /// Produces origin-secret.key and origin-public.key in the output directory.
    /// Secret key is base64-encoded and permissions are set to 0o600 on Unix.
    /// The public key value is printed to stdout.
    ///
    /// Examples:
    ///   origin keygen
    ///   origin keygen --output ~/.origin
    Keygen {
        /// Output directory for key files (default: current directory)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Sign an artifact, producing a provenance statement
    ///
    /// Writes a .origin file next to the artifact.
    /// Secret key sources (in priority order):
    ///   1. --key <file>
    ///   2. $ORIGIN_KEY environment variable
    ///   3. --key - (read from stdin)
    ///
    /// Examples:
    ///   origin sign myapp --key origin-secret.key
    ///   origin sign myapp --key origin-secret.key --time 1717776000
    ///   origin sign myapp --key origin-secret.key --parent prev.origin
    ///   ORIGIN_KEY=$(cat origin-secret.key) origin sign myapp
    ///   cat origin-secret.key | origin sign myapp --key -
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
    ///
    /// Returns VERIFIED if the statement is cryptographically valid for the
    /// given artifact. Returns FAILED with an error message otherwise.
    ///
    /// Examples:
    ///   origin verify myapp.origin myapp
    ///   origin verify release-v1.0.0.origin release-v1.0.0.tar.gz
    Verify {
        /// Path to the statement file
        statement: PathBuf,
        /// Path to the artifact file
        artifact: PathBuf,
    },
    /// Display a human-readable audit of a statement
    ///
    /// Shows all fields in parsed form. Does NOT perform verification
    /// (use 'origin verify' for that).
    ///
    /// Examples:
    ///   origin audit myapp.origin
    ///   origin audit revocation-abc123.origin
    Audit {
        /// Path to the statement file
        statement: PathBuf,
    },
    /// Create a revocation statement for a compromised key
    ///
    /// Produces a revocation-<prefix>.origin file. The revocation is signed
    /// by the secret key provided via --key and declares that statements
    /// signed by the --revoked key with timestamp >= --since should not be
    /// trusted.
    ///
    /// Examples:
    ///   origin revoke --key origin-secret.key --revoked <base64> --since 1717776000
    ///   origin revoke --key origin-secret.key --revoked $(cat origin-public.key)
    Revoke {
        /// Path to the secret key file (or '-' for stdin, or $ORIGIN_KEY env)
        #[arg(long, short)]
        key: Option<String>,
        /// Base64-encoded Ed25519 public key being revoked
        #[arg(long)]
        revoked: String,
        /// Unix timestamp after which statements by the revoked key should not be trusted (default: now)
        #[arg(long)]
        since: Option<u64>,
    },
    /// Check revocation status of a statement
    ///
    /// Checks whether a provenance statement is revoked by a given revocation
    /// statement. Prints REVOKED if the statement's timestamp >= the revocation's
    /// 'since' field. Also verifies the revocation statement's own signature.
    ///
    /// Examples:
    ///   origin check myapp.origin --revocation revocation-abc123.origin
    Check {
        /// Path to the statement file to check
        statement: PathBuf,
        /// Path to a revocation statement file
        #[arg(long)]
        revocation: PathBuf,
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
                if parent_stmt.type_ != StatementType::Provenance {
                    eprintln!("error: parent statement must be a provenance statement, got {:?}", parent_stmt.type_);
                    std::process::exit(1);
                }
                Some(parent_stmt.hash_str().unwrap().to_string())
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
        Commands::Revoke { key, revoked, since } => {
            let secret = match load_secret_key(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            };

            // Get the public key of the signer for the revocation statement
            let pair = origin_core::generate_keypair_from_seed(&secret.0);
            let signer_pub_b64 = base64_encode(&pair.public.0);

            let ts = since.unwrap_or_else(current_timestamp);

            let stmt = match build_revocation_statement(&secret, &revoked, ts, &signer_pub_b64) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            };

            let encoded = encode_statement(&stmt);
            let out_path = format!("revocation-{}.origin", &revoked[..8]);
            match std::fs::write(&out_path, &encoded) {
                Ok(_) => {
                    println!("Revocation statement written to {}", out_path);
                }
                Err(e) => {
                    eprintln!("error: cannot write revocation: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Check { statement, revocation } => {
            let stmt_data = match std::fs::read(&statement) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", statement.display(), e);
                    std::process::exit(1);
                }
            };
            let stmt = match Statement::parse(&stmt_data) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: invalid statement: {}", e);
                    std::process::exit(1);
                }
            };

            let rev_data = match std::fs::read(&revocation) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", revocation.display(), e);
                    std::process::exit(1);
                }
            };
            let rev_stmt = match Statement::parse(&rev_data) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: invalid revocation statement: {}", e);
                    std::process::exit(1);
                }
            };

            if rev_stmt.type_ != StatementType::Revocation {
                eprintln!("error: '{}' is not a revocation statement", revocation.display());
                std::process::exit(1);
            }

            // Verify the revocation statement's own signature
            if let Err(e) = verify_revocation(&rev_stmt) {
                eprintln!("error: revocation signature is invalid: {}", e);
                std::process::exit(1);
            }

            // Check if this revocation applies to the statement's key
            let revoked_key = rev_stmt.revoked_key_b64().unwrap_or("");
            if revoked_key != stmt.key_b64 {
                println!("KEY NOT REVOKED — revocation targets a different key");
                return;
            }

            let stmt_time = stmt.time().unwrap_or(0);
            let rev_since = rev_stmt.revoked_since().unwrap_or(0);

            if stmt_time >= rev_since {
                println!("REVOKED — statement timestamp {} >= revocation since {}",
                    stmt_time, rev_since);
            } else {
                println!("NOT REVOKED — statement timestamp {} < revocation since {}",
                    stmt_time, rev_since);
            }
        }
    }
}
