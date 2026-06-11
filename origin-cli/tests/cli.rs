use std::process::{Command, Stdio};

fn origin_binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_origin"))
}

fn keygen_b64_keys(dir: &tempfile::TempDir) -> (String, String) {
    let out = origin_binary()
        .arg("keygen")
        .arg("--output")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "keygen failed: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let sec = std::fs::read_to_string(dir.path().join("origin-secret.key")).unwrap();
    let pubk = std::fs::read_to_string(dir.path().join("origin-public.key")).unwrap();
    (sec.trim().to_string(), pubk.trim().to_string())
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

// ── load_secret_key: --key <file> path ──

#[test]
fn test_cli_sign_with_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _) = keygen_b64_keys(&dir);
    let sec_path = dir.path().join("my.key");
    std::fs::write(&sec_path, &sec).unwrap();

    let art = dir.path().join("file.bin");
    std::fs::write(&art, b"data").unwrap();

    let out = origin_binary()
        .arg("sign")
        .arg("--key")
        .arg(&sec_path)
        .arg(&art)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sign --key file: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join("file.origin").exists());
}

// ── load_secret_key: --key - (stdin) path ──

#[test]
fn test_cli_sign_with_key_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _) = keygen_b64_keys(&dir);
    let art = dir.path().join("data.bin");
    std::fs::write(&art, b"stdin key").unwrap();

    let mut child = origin_binary()
        .arg("sign")
        .arg("--key")
        .arg("-")
        .arg(&art)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(sec.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "sign --key -: {:?}", String::from_utf8_lossy(&out.stderr));
    assert!(dir.path().join("data.origin").exists());
}

// ── load_secret_key: no key provided ──

#[test]
fn test_cli_sign_no_key_error() {
    let dir = tempfile::tempdir().unwrap();
    let art = dir.path().join("nokey.bin");
    std::fs::write(&art, b"data").unwrap();

    let out = origin_binary().arg("sign").arg(&art).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("no secret key provided"), "stderr: {}", stderr);
}

// ── Sign with --time flag ──

#[test]
fn test_cli_sign_with_time() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _) = keygen_b64_keys(&dir);
    let art = dir.path().join("timed.bin");
    std::fs::write(&art, b"timed").unwrap();

    let out = origin_binary()
        .env("ORIGIN_KEY", &sec)
        .arg("sign")
        .arg("--time")
        .arg("1717776000")
        .arg(&art)
        .output()
        .unwrap();
    assert!(out.status.success(), "sign --time: {:?}", String::from_utf8_lossy(&out.stderr));
    assert!(dir.path().join("timed.origin").exists());
}

// ── Sign with --parent ──

#[test]
fn test_cli_sign_with_parent() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _pubk) = keygen_b64_keys(&dir);

    let parent_art = dir.path().join("parent.bin");
    std::fs::write(&parent_art, b"parent").unwrap();
    let out = origin_binary()
        .env("ORIGIN_KEY", &sec)
        .arg("sign")
        .arg(&parent_art)
        .output()
        .unwrap();
    assert!(out.status.success());

    let child_art = dir.path().join("child.bin");
    std::fs::write(&child_art, b"child").unwrap();
    let out = origin_binary()
        .env("ORIGIN_KEY", &sec)
        .arg("sign")
        .arg("--parent")
        .arg(dir.path().join("parent.origin"))
        .arg(&child_art)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sign with parent: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.path().join("child.origin").exists());

    // Verify chain
    let out = origin_binary()
        .arg("verify")
        .arg(dir.path().join("child.origin"))
        .arg(&child_art)
        .arg("--parent")
        .arg(dir.path().join("parent.origin"))
        .arg(&parent_art)
        .arg("--trusted-key")
        .arg(dir.path().join("origin-public.key"))
        .output()
        .unwrap();
    assert!(out.status.success(), "verify chain: {:?}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8(out.stdout).unwrap().contains("VERIFIED"));
}

// ── Sign with nonexistent key file ──

#[test]
fn test_cli_sign_bad_key_file() {
    let dir = tempfile::tempdir().unwrap();
    let art = dir.path().join("bad.bin");
    std::fs::write(&art, b"x").unwrap();

    let out = origin_binary()
        .arg("sign")
        .arg("--key")
        .arg("/nonexistent/key.file")
        .arg(&art)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("failed to read key file"));
}

// ── Sign with nonexistent artifact ──

#[test]
fn test_cli_sign_bad_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _) = keygen_b64_keys(&dir);

    let out = origin_binary()
        .env("ORIGIN_KEY", &sec)
        .arg("sign")
        .arg("/nonexistent/artifact.bin")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot read"));
}

// ── Sign with invalid parent file ──

#[test]
fn test_cli_sign_bad_parent_file() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _) = keygen_b64_keys(&dir);
    let art = dir.path().join("badp.bin");
    std::fs::write(&art, b"x").unwrap();

    let out = origin_binary()
        .env("ORIGIN_KEY", &sec)
        .arg("sign")
        .arg("--parent")
        .arg("/nonexistent/parent.origin")
        .arg(&art)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot read parent"));
}

// ── Sign with invalid parent content ──

#[test]
fn test_cli_sign_invalid_parent_content() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _) = keygen_b64_keys(&dir);
    let art = dir.path().join("badpc.bin");
    std::fs::write(&art, b"x").unwrap();
    let bad_parent = dir.path().join("bad_parent.origin");
    std::fs::write(&bad_parent, b"not a valid statement").unwrap();

    let out = origin_binary()
        .env("ORIGIN_KEY", &sec)
        .arg("sign")
        .arg("--parent")
        .arg(&bad_parent)
        .arg(&art)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("invalid parent statement"));
}

// ── Verify error: bad statement file ──

#[test]
fn test_cli_verify_bad_statement_file() {
    let out = origin_binary()
        .arg("verify")
        .arg("/nonexistent/stmt.origin")
        .arg("/nonexistent/art.bin")
        .arg("--consistency-only")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot read"));
}

// ── Verify error: bad artifact file ──

#[test]
fn test_cli_verify_bad_artifact_file() {
    let dir = tempfile::tempdir().unwrap();
    let stmt_path = dir.path().join("stmt.origin");
    std::fs::write(&stmt_path, b"origin: v1\ntype: provenance\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n").unwrap();

    let out = origin_binary()
        .arg("verify")
        .arg(&stmt_path)
        .arg("/nonexistent/art.bin")
        .arg("--consistency-only")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot read"));
}

// ── Verify error: bad parent files ──

#[test]
fn test_cli_verify_bad_parent() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _pubk) = keygen_b64_keys(&dir);
    let art = dir.path().join("art.bin");
    std::fs::write(&art, b"x").unwrap();

    let out = origin_binary()
        .env("ORIGIN_KEY", &sec)
        .arg("sign")
        .arg(&art)
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = origin_binary()
        .arg("verify")
        .arg(dir.path().join("art.origin"))
        .arg(&art)
        .arg("--parent")
        .arg("/nonexistent/p.origin")
        .arg("/nonexistent/p.art")
        .arg("--trusted-key")
        .arg(dir.path().join("origin-public.key"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot read parent"));
}

// ── Verify error: invalid base64 in trusted key file ──

#[test]
fn test_cli_verify_bad_trusted_key_format() {
    let dir = tempfile::tempdir().unwrap();
    let bad_key = dir.path().join("bad.key");
    std::fs::write(&bad_key, "!!!invalid-base64!!!").unwrap();
    let stmt_path = dir.path().join("s.origin");
    std::fs::write(&stmt_path, b"origin: v1\ntype: provenance\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n").unwrap();
    let art_path = dir.path().join("a.bin");
    std::fs::write(&art_path, b"").unwrap();

    let out = origin_binary()
        .arg("verify")
        .arg(&stmt_path)
        .arg(&art_path)
        .arg("--trusted-key")
        .arg(&bad_key)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("invalid base64url"));
}

// ── Verify error: trusted key decodes to wrong length ──

#[test]
fn test_cli_verify_trusted_key_wrong_length() {
    let dir = tempfile::tempdir().unwrap();
    let short_key = dir.path().join("short.key");
    // "AA==" is one byte, not 32
    std::fs::write(&short_key, "AA==").unwrap();
    let stmt_path = dir.path().join("s.origin");
    std::fs::write(&stmt_path, b"origin: v1\ntype: provenance\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n").unwrap();
    let art_path = dir.path().join("a.bin");
    std::fs::write(&art_path, b"").unwrap();

    let out = origin_binary()
        .arg("verify")
        .arg(&stmt_path)
        .arg(&art_path)
        .arg("--trusted-key")
        .arg(&short_key)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("must decode to 32 bytes"));
}

// ── Verify error: must specify --trusted-key or --consistency-only ──

#[test]
fn test_cli_verify_no_mode() {
    let dir = tempfile::tempdir().unwrap();
    let stmt_path = dir.path().join("s.origin");
    std::fs::write(&stmt_path, b"origin: v1\ntype: provenance\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n").unwrap();
    let art_path = dir.path().join("a.bin");
    std::fs::write(&art_path, b"").unwrap();

    let out = origin_binary()
        .arg("verify")
        .arg(&stmt_path)
        .arg(&art_path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("--trusted-key") || stderr.contains("--consistency-only"));
}

// ── Audit error: bad file ──

#[test]
fn test_cli_audit_bad_file() {
    let out = origin_binary()
        .arg("audit")
        .arg("/nonexistent/stmt.origin")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot read"));
}

// ── Audit error: unparsable statement ──

#[test]
fn test_cli_audit_unparsable() {
    let dir = tempfile::tempdir().unwrap();
    let stmt_path = dir.path().join("bad.origin");
    std::fs::write(&stmt_path, b"garbage\ncontent\n").unwrap();

    let out = origin_binary().arg("audit").arg(&stmt_path).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("cannot parse"));
}

// ── Verify FAILED (not error) for hash mismatch ──

#[test]
fn test_cli_verify_failed_hash() {
    let dir = tempfile::tempdir().unwrap();
    let (sec, _pubk) = keygen_b64_keys(&dir);
    let art = dir.path().join("good.bin");
    std::fs::write(&art, b"original data").unwrap();

    let out = origin_binary()
        .env("ORIGIN_KEY", &sec)
        .arg("sign")
        .arg(&art)
        .output()
        .unwrap();
    assert!(out.status.success());

    // Verify with DIFFERENT artifact - should FAIL (not error)
    let wrong_art = dir.path().join("wrong.bin");
    std::fs::write(&wrong_art, b"different data").unwrap();

    let out = origin_binary()
        .arg("verify")
        .arg(dir.path().join("good.origin"))
        .arg(&wrong_art)
        .arg("--consistency-only")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("FAILED"), "stdout: {}", stdout);
}

// ── Verify FAILED for key mismatch ──

#[test]
fn test_cli_verify_key_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let (sec1, _pubk1) = keygen_b64_keys(&dir);
    let art = dir.path().join("km.bin");
    std::fs::write(&art, b"data").unwrap();

    let out = origin_binary()
        .env("ORIGIN_KEY", &sec1)
        .arg("sign")
        .arg(&art)
        .output()
        .unwrap();
    assert!(out.status.success());

    // Generate a DIFFERENT key and use it as trusted key
    let dir2 = tempfile::tempdir().unwrap();
    let (_, _pubk2) = keygen_b64_keys(&dir2);

    let out = origin_binary()
        .arg("verify")
        .arg(dir.path().join("km.origin"))
        .arg(&art)
        .arg("--trusted-key")
        .arg(dir2.path().join("origin-public.key"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("FAILED"), "stdout: {}", stdout);
}
