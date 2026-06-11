use clap::{Parser, Subcommand};
use origin_core::{
    SecretKey, Statement, base64_encode, build_statement, encode_statement, generate_keypair, hash, verify_chain,
    verify_chain_consistency,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "origin",
    version,
    about = "Cryptographic provenance for digital artifacts"
)]
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
    ///   1. $ORIGIN_KEY environment variable
    ///   2. `--key <file>`
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
    /// By default, requires --trusted-key to pin the expected signer.
    /// Use --consistency-only to verify cryptographic integrity without
    /// key pinning (internal consistency check only).
    ///
    /// Returns VERIFIED if the statement is cryptographically valid for the
    /// given artifact. Returns FAILED with an error message otherwise.
    ///
    /// If --parent is given, also verifies the parent statement in the chain.
    ///
    /// Examples:
    ///   origin verify myapp.origin myapp --trusted-key origin-public.key
    ///   origin verify release-v1.0.0.origin release-v1.0.0.tar.gz --trusted-key release.pub
    ///   origin verify child.origin child.tar.gz --parent parent.origin parent.tar.gz --trusted-key origin-public.key
    ///   origin verify myapp.origin myapp --consistency-only
    Verify {
        /// Path to the statement file
        statement: PathBuf,
        /// Path to the artifact file
        artifact: PathBuf,
        /// Path to the parent statement and artifact (for chain verification)
        #[arg(long, num_args = 2, value_names = ["STATEMENT", "ARTIFACT"])]
        parent: Option<Vec<PathBuf>>,
        /// Path to a trusted public key file (base64url, 44 chars with padding)
        #[arg(long)]
        trusted_key: Option<PathBuf>,
        /// Skip key verification — check cryptographic integrity only
        #[arg(long)]
        consistency_only: bool,
    },
    /// Display a human-readable audit of a statement
    ///
    /// Shows all fields in parsed form. Does NOT perform verification
    /// (use 'origin verify' for that).
    ///
    /// Examples:
    ///   origin audit myapp.origin
    Audit {
        /// Path to the statement file
        statement: PathBuf,
    },
}

fn load_secret_key(key_arg: &Option<String>) -> Result<SecretKey, String> {
    if let Ok(env_key) = std::env::var("ORIGIN_KEY") {
        if key_arg.is_some() {
            eprintln!("warning: ORIGIN_KEY env var takes priority over --key flag");
        }
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
        let data =
            std::fs::read_to_string(key_src).map_err(|e| format!("failed to read key file '{}': {}", key_src, e))?;
        return decode_secret_key(data.trim());
    }

    Err("no secret key provided. Use --key <file> or set ORIGIN_KEY env var".into())
}

fn decode_secret_key(s: &str) -> Result<SecretKey, String> {
    let bytes = origin_core::base64url_decode(s).map_err(|e| format!("invalid base64 key: {}", e))?;
    SecretKey::from_bytes(&bytes).map_err(|e| e.to_string())
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX epoch")
        .as_secs()
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hash { path } => match hash::hash_file(&path) {
            Ok(h) => println!("sha256:{}", h),
            Err(e) => {
                eprintln!("error: {}", e);
                std::process::exit(1);
            },
        },
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
                std::fs::set_permissions(&sec_path, std::fs::Permissions::from_mode(0o600)).ok();
            }

            println!("Key pair generated:");
            println!("  Secret: {}", sec_path.display());
            println!("  Public: {}", pub_path.display());
            println!("  Public key: {}", public_b64);
        },
        Commands::Sign { path, key, time, parent } => {
            let secret = match load_secret_key(&key) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                },
            };

            let artifact_data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", path.display(), e);
                    std::process::exit(1);
                },
            };

            let parent_hash = if let Some(parent_path) = &parent {
                let parent_data = match std::fs::read(parent_path) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("error: cannot read parent '{}': {}", parent_path.display(), e);
                        std::process::exit(1);
                    },
                };
                let parent_stmt = match Statement::parse(&parent_data) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("error: invalid parent statement: {}", e);
                        std::process::exit(1);
                    },
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
                },
            };

            let encoded = encode_statement(&stmt);
            let stmt_path = path.with_extension("origin");
            match std::fs::write(&stmt_path, &encoded) {
                Ok(_) => {
                    println!("Statement written to {}", stmt_path.display());
                },
                Err(e) => {
                    eprintln!("error: cannot write statement: {}", e);
                    std::process::exit(1);
                },
            }
        },
        Commands::Verify { statement, artifact, parent, trusted_key, consistency_only } => {
            let stmt_data = match std::fs::read(&statement) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", statement.display(), e);
                    std::process::exit(1);
                },
            };
            let art_data = match std::fs::read(&artifact) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", artifact.display(), e);
                    std::process::exit(1);
                },
            };

            let (parent_stmt_data, parent_art_data) = if let Some(ref args) = parent {
                if args.len() != 2 {
                    eprintln!("error: --parent requires STATEMENT and ARTIFACT arguments");
                    std::process::exit(1);
                }
                let ps = match std::fs::read(&args[0]) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("error: cannot read parent '{}': {}", args[0].display(), e);
                        std::process::exit(1);
                    },
                };
                let pa = match std::fs::read(&args[1]) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("error: cannot read parent artifact '{}': {}", args[1].display(), e);
                        std::process::exit(1);
                    },
                };
                (Some(ps), Some(pa))
            } else {
                (None, None)
            };

            let result = if consistency_only {
                verify_chain_consistency(&stmt_data, &art_data, parent_stmt_data.as_deref(), parent_art_data.as_deref())
            } else if let Some(ref tk_path) = trusted_key {
                let tk_data = match std::fs::read_to_string(tk_path) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("error: cannot read trusted key '{}': {}", tk_path.display(), e);
                        std::process::exit(1);
                    },
                };
                let trimmed = tk_data.trim().to_string();
                let decoded = match origin_core::base64url_decode(&trimmed) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("error: invalid base64url in trusted key: {}", e);
                        std::process::exit(1);
                    },
                };
                if decoded.len() != 32 {
                    eprintln!("error: trusted public key must decode to 32 bytes (got {})", decoded.len());
                    std::process::exit(1);
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                verify_chain(
                    &stmt_data,
                    &art_data,
                    parent_stmt_data.as_deref(),
                    parent_art_data.as_deref(),
                    &key,
                )
            } else {
                eprintln!("error: must specify --trusted-key or --consistency-only");
                std::process::exit(1);
            };

            match result {
                Ok(()) => println!("VERIFIED"),
                Err(e) => {
                    println!("FAILED: {}", e);
                    std::process::exit(1);
                },
            }
        },
        Commands::Audit { statement } => {
            let stmt_data = match std::fs::read(&statement) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("error: cannot read '{}': {}", statement.display(), e);
                    std::process::exit(1);
                },
            };

            match Statement::parse(&stmt_data) {
                Ok(stmt) => {
                    println!("{}", origin_core::audit::audit(&stmt));
                },
                Err(e) => {
                    eprintln!("error: cannot parse statement: {}", e);
                    std::process::exit(1);
                },
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_secret_key_valid() {
        let key = decode_secret_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert_eq!(key.0, [0u8; 32]);
    }

    #[test]
    fn test_decode_secret_key_wrong_length() {
        let err = decode_secret_key("AA==").unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn test_decode_secret_key_invalid_base64() {
        let err = decode_secret_key("!!!").unwrap_err();
        assert!(err.contains("invalid base64"));
    }

    #[test]
    fn test_decode_secret_key_no_trim() {
        let key = decode_secret_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert_eq!(key.0, [0u8; 32]);
    }

    #[test]
    fn test_current_timestamp_is_reasonable() {
        let ts = current_timestamp();
        assert!(ts > 1577836800, "timestamp {} seems too low", ts);
        assert!(ts < 4102444800, "timestamp {} seems too high", ts);
    }
}
