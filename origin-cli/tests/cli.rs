use std::process::Command;

fn origin_binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_origin"))
}

#[test]
fn test_cli_version() {
    let output = origin_binary().arg("--version").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("origin"));
}

#[test]
fn test_cli_help() {
    let output = origin_binary().arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("hash"));
    assert!(stdout.contains("keygen"));
    assert!(stdout.contains("sign"));
    assert!(stdout.contains("verify"));
    assert!(stdout.contains("audit"));
}

#[test]
fn test_cli_hash_basic() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test.bin");
    std::fs::write(&file_path, b"hello world").unwrap();

    let output = origin_binary().arg("hash").arg(&file_path).output().unwrap();
    assert!(
        output.status.success(),
        "hash failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("sha256:"));
    assert_eq!(
        stdout.trim(),
        "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[test]
fn test_cli_hash_file_not_found() {
    let output = origin_binary()
        .arg("hash")
        .arg("/nonexistent/file.bin")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("error"));
}

#[test]
fn test_cli_keygen_and_sign_and_verify() {
    let dir = tempfile::tempdir().unwrap();

    // Generate key
    let output = origin_binary()
        .arg("keygen")
        .arg("--output")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "keygen failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Key pair generated"));

    let secret_key = std::fs::read_to_string(dir.path().join("origin-secret.key")).unwrap();
    let public_key = std::fs::read_to_string(dir.path().join("origin-public.key")).unwrap();
    assert!(!secret_key.trim().is_empty());
    assert!(!public_key.trim().is_empty());

    // Sign a file
    let artifact = dir.path().join("artifact.bin");
    std::fs::write(&artifact, b"sign me").unwrap();

    let output = origin_binary()
        .env("ORIGIN_KEY", secret_key.trim())
        .arg("sign")
        .arg(&artifact)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sign failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("artifact.origin").exists());

    // Verify with trusted key
    let output = origin_binary()
        .arg("verify")
        .arg(dir.path().join("artifact.origin"))
        .arg(&artifact)
        .arg("--trusted-key")
        .arg(dir.path().join("origin-public.key"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("VERIFIED"));

    // Verify with consistency-only
    let output = origin_binary()
        .arg("verify")
        .arg(dir.path().join("artifact.origin"))
        .arg(&artifact)
        .arg("--consistency-only")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "consistency verify failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("VERIFIED"));
}

#[test]
fn test_cli_sign_with_env_key() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = dir.path().join("test.bin");
    std::fs::write(&artifact, b"test data").unwrap();

    let output = origin_binary()
        .arg("keygen")
        .arg("--output")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let secret_b64 = std::fs::read_to_string(dir.path().join("origin-secret.key")).unwrap();
    let secret_trimmed = secret_b64.trim().to_string();

    let output = origin_binary()
        .env("ORIGIN_KEY", &secret_trimmed)
        .arg("sign")
        .arg(&artifact)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sign with env var failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("test.origin").exists());
}

#[test]
fn test_cli_audit() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = dir.path().join("audit.bin");
    std::fs::write(&artifact, b"audit me").unwrap();

    // Generate key and sign
    let output = origin_binary()
        .arg("keygen")
        .arg("--output")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let secret_b64 = std::fs::read_to_string(dir.path().join("origin-secret.key")).unwrap();

    let output = origin_binary()
        .env("ORIGIN_KEY", secret_b64.trim())
        .arg("sign")
        .arg(&artifact)
        .output()
        .unwrap();
    assert!(output.status.success());

    // Audit
    let output = origin_binary()
        .arg("audit")
        .arg(dir.path().join("audit.origin"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "audit failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Statement Audit"));
    assert!(stdout.contains("SHA-256"));
}

#[test]
fn test_cli_verify_missing_args() {
    let output = origin_binary().arg("verify").output().unwrap();
    assert!(!output.status.success());
}
