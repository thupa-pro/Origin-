use origin_core::statement::Statement;

fn assert_parse_fails(data: &[u8], hint: &str) {
    let result = Statement::parse(data);
    assert!(result.is_err(), "expected parse failure: {}", hint);
}

fn assert_parse_ok(data: &[u8], hint: &str) {
    let result = Statement::parse(data);
    assert!(result.is_ok(), "expected parse success for {}: {:?}", hint, result.err());
}

fn valid_statement() -> Vec<u8> {
    b"origin: v1\ntype: provenance\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n".to_vec()
}

fn valid_with_parent() -> Vec<u8> {
    b"origin: v1\ntype: provenance\nparent: sha256:1111111111111111111111111111111111111111111111111111111111111111\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n".to_vec()
}

#[test]
fn test_parse_valid() {
    assert_parse_ok(&valid_statement(), "valid statement");
}

#[test]
fn test_parse_valid_with_parent() {
    assert_parse_ok(&valid_with_parent(), "valid statement with parent");
}

// ── Structural ──

#[test]
fn test_too_few_lines() {
    assert_parse_fails(b"origin: v1\ntype: provenance\nhash: sha256:abc\n", "too few lines");
}

#[test]
fn test_too_many_lines() {
    let mut v = valid_statement();
    v.extend_from_slice(b"extra: x\n");
    v.extend_from_slice(b"extra2: y\n");
    assert_parse_fails(&v, "too many lines");
}

#[test]
fn test_empty_line() {
    let data = b"origin: v1\ntype: provenance\n\nhash: sha256:abc\ntime: 0\nkey: xxxxx\nsig: xxxxx\n";
    assert_parse_fails(data, "empty line");
}

#[test]
fn test_missing_trailing_newline() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xxxxx\nsig: xxxxx";
    assert_parse_fails(data, "missing trailing newline");
}

// ── BOM / CR / Null ──

#[test]
fn test_bom() {
    let mut v = vec![0xef, 0xbb, 0xbf];
    v.extend_from_slice(&valid_statement());
    assert_parse_fails(&v, "BOM");
}

#[test]
fn test_cr() {
    assert_parse_fails(
        b"origin: v1\ntype: provenance\nhash: abc\ntime: 0\nkey: aaaaa\nsig: aaaaa\n",
        "CR character",
    );
}

#[test]
fn test_null_byte() {
    assert_parse_fails(
        b"origin: v1\ntype: provenance\nhash: a\ntime: 0\nkey: aaaaa\nsig: a\x00aaaa\n",
        "null byte",
    );
}

// ── Key validation ──

#[test]
fn test_wrong_key_order() {
    let data = b"origin: v1\nhash: sha256:abc\ntype: provenance\ntime: 0\nkey: xxxxx\nsig: xxxxx\n";
    assert_parse_fails(data, "wrong key order");
}

#[test]
fn test_wrong_key_order_with_parent() {
    let data = b"origin: v1\nhash: sha256:abc\ntype: provenance\nparent: x\ntime: 0\nkey: xxxxx\nsig: xxxxx\n";
    assert_parse_fails(data, "wrong key order with parent (hash before type)");
}

#[test]
fn test_unknown_key() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xxxxx\nfoo: bar\n";
    assert_parse_fails(data, "unknown key");
}

#[test]
fn test_duplicate_key() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xxxxx\norigin: v1\n";
    assert_parse_fails(data, "duplicate key");
}

#[test]
fn test_missing_separator() {
    let data = b"origin v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xxxxx\nsig: xxxxx\n";
    assert_parse_fails(data, "missing separator");
}

// ── Field validation ──

#[test]
fn test_bad_origin() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("origin: v1", "origin: v0");
    assert_parse_fails(tampered.as_bytes(), "wrong origin version");
}

#[test]
fn test_bad_type() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("type: provenance", "type: invalid");
    assert_parse_fails(tampered.as_bytes(), "invalid type");
}

#[test]
fn test_bad_hash_prefix() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("sha256:", "md5:");
    assert_parse_fails(tampered.as_bytes(), "bad hash prefix");
}

#[test]
fn test_hash_uppercase() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.to_uppercase();
    assert_parse_fails(tampered.as_bytes(), "uppercase hash");
}

#[test]
fn test_hash_too_short() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "abc");
    assert_parse_fails(tampered.as_bytes(), "hash too short");
}

#[test]
fn test_hash_alg_unknown() {
    let data =
        b"origin: v1\ntype: provenance\nhash: md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ntime: 0\nkey: xxxxx\nsig: xxxxx\n";
    assert_parse_fails(data, "unknown hash algorithm");
    let err = format!("{}", Statement::parse(data).unwrap_err());
    assert!(err.contains("sha256"), "error must mention 'sha256': {}", err);
}

#[test]
fn test_timestamp_leading_zero() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("time: 0", "time: 01");
    assert_parse_fails(tampered.as_bytes(), "leading zero in timestamp");
}

#[test]
fn test_timestamp_non_digit() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("time: 0", "time: abc");
    assert_parse_fails(tampered.as_bytes(), "non-digit timestamp");
}

#[test]
fn test_timestamp_overflow() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("time: 0", "time: 999999999999");
    assert_parse_fails(tampered.as_bytes(), "timestamp overflow");
}

#[test]
fn test_key_wrong_length() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "tooshort");
    assert_parse_fails(tampered.as_bytes(), "key too short");
}

#[test]
fn test_sig_wrong_length() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        "tooshort",
    );
    assert_parse_fails(tampered.as_bytes(), "sig too short");
}

#[test]
fn test_key_invalid_base64url() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "A+++++++++++++++++++++++++++++++++++++++++++",
    );
    assert_parse_fails(tampered.as_bytes(), "invalid base64url in key");
}

#[test]
fn test_key_decoded_length_mismatch() {
    let v = valid_statement();
    let text = String::from_utf8(v).unwrap();
    let unpadded_44 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(unpadded_44.len(), 44, "test input must be 44 chars");
    let tampered = text.replace("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", unpadded_44);
    assert_parse_fails(tampered.as_bytes(), "decoded key length mismatch");
}

#[test]
fn test_whitespace_in_value() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xxxx\nsig:  xxxx\n";
    assert_parse_fails(data, "leading whitespace in value");
}

#[test]
fn test_empty_value() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: \nsig: xxxx\n";
    assert_parse_fails(data, "empty value");
}

#[test]
fn test_control_char_in_value() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xx\x00xx\nsig: xxxx\n";
    assert_parse_fails(data, "control char in value");
}

#[test]
fn test_empty_key_name() {
    let data = b"origin: v1\ntype: provenance\n: sha256:abc\ntime: 0\nkey: xxxx\nsig: xxxx\n";
    assert_parse_fails(data, "empty key name");
}

#[test]
fn test_trailing_whitespace_in_value() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xxxx  \nsig: xxxx\n";
    assert_parse_fails(data, "trailing whitespace in value");
}

#[test]
fn test_tab_after_separator() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: \txxxx\nsig: xxxx\n";
    assert_parse_fails(data, "tab after separator in value");
}

#[test]
fn test_non_utf8() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xxxx\nsig: \xff\xff\n";
    assert_parse_fails(data, "non-UTF-8");
}

#[test]
fn test_tab_in_value() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: xx\txx\nsig: xxxx\n";
    assert_parse_fails(data, "tab in value");
}

use origin_core::SecretKey;
use origin_core::{build_statement, encode_statement, verify_chain, verify_chain_consistency, verify_consistency};

#[test]
fn test_verify_missing_parent() {
    let seed = [42u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let child_artifact = b"child with parent ref";

    let parent_hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let child = build_statement(&secret, child_artifact, 100, Some(parent_hash)).unwrap();
    let child_encoded = encode_statement(&child);

    let result = verify_chain_consistency(&child_encoded, child_artifact, None, None);
    assert!(result.is_err(), "must fail when parent is missing");
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("parent"), "error must mention parent: {}", err);
}

#[test]
fn test_verify_chain_missing_parent_with_key() {
    let seed = [42u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let tk = origin_core::generate_keypair_from_seed(&seed).public.0;
    let child_artifact = b"child with parent ref";

    let parent_hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let child = build_statement(&secret, child_artifact, 100, Some(parent_hash)).unwrap();
    let child_encoded = encode_statement(&child);

    let result = verify_chain(&child_encoded, child_artifact, None, None, &tk);
    assert!(result.is_err(), "must fail when parent is missing in verify_chain");
}

#[test]
fn test_empty_key_field() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256:abc\ntime: 0\nkey: \nsig: xxxx\n";
    assert_parse_fails(data, "empty key field");
}

#[test]
fn test_hash_no_colon() {
    let data = b"origin: v1\ntype: provenance\nhash: sha256abc\ntime: 0\nkey: xxxx\nsig: xxxx\n";
    assert_parse_fails(data, "hash no colon");
}

#[test]
fn test_artifact_too_large() {
    let data = vec![0u8; 3_000_000_000];
    let result = verify_consistency(b"origin: v1\n", &data);
    assert!(result.is_err(), "oversized artifact must fail");
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("too large"), "must mention size: {}", err);
}

#[test]
fn test_build_statement_artifact_too_large() {
    let seed = [42u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let data = vec![0u8; 3_000_000_000];
    let result = build_statement(&secret, &data, 0, None);
    assert!(result.is_err(), "oversized artifact in build must fail");
}

#[test]
fn test_verify_wrong_parent() {
    let seed = [42u8; 32];
    let secret = SecretKey::from_bytes(&seed).unwrap();
    let parent_artifact = b"parent artifact";
    let child_artifact = b"child artifact";

    let parent = build_statement(&secret, parent_artifact, 100, None).unwrap();
    let parent_encoded = encode_statement(&parent);

    // Child references a DIFFERENT hash than the actual parent
    let wrong_hash = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let child = build_statement(&secret, child_artifact, 200, Some(wrong_hash)).unwrap();
    let child_encoded = encode_statement(&child);

    let result = verify_chain_consistency(&child_encoded, child_artifact, Some(&parent_encoded), Some(parent_artifact));
    assert!(result.is_err(), "must fail when parent hash doesn't match");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("Parent hash mismatch"),
        "error must indicate hash mismatch: {}",
        err
    );
}
