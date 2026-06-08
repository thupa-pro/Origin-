use origin_core::statement::Statement;

fn assert_parse_fails(data: &[u8], hint: &str) {
    let result = Statement::parse(data);
    assert!(result.is_err(), "expected parse failure: {}", hint);
}

fn assert_parse_ok(data: &[u8], hint: &str) {
    let result = Statement::parse(data);
    assert!(result.is_ok(), "expected parse success for {}: {:?}", hint, result.err());
}

fn valid_minimal() -> Vec<u8> {
    b"origin: v1\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n".to_vec()
}

fn valid_with_parent() -> Vec<u8> {
    b"origin: v1\nparent: sha256:1111111111111111111111111111111111111111111111111111111111111111\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n".to_vec()
}

#[test]
fn test_parse_valid() {
    assert_parse_ok(&valid_minimal(), "valid minimal statement");
}

#[test]
fn test_parse_valid_with_parent() {
    assert_parse_ok(&valid_with_parent(), "valid statement with parent");
}

// ── Structural ──

#[test]
fn test_too_few_lines() {
    assert_parse_fails(b"origin: v1\nhash: sha256:abc\n", "too few lines");
}

#[test]
fn test_too_many_lines() {
    // 7 lines exceeds the max of 6
    let mut v = valid_minimal();
    v.extend_from_slice(b"extra: x\n");
    v.extend_from_slice(b"extra2: y\n");
    assert_parse_fails(&v, "too many lines");
}

#[test]
fn test_empty_line() {
    let data = b"origin: v1\n\nhash: sha256:abc\ntime: 0\nkey: xxxxx\nsig: xxxxx\n";
    assert_parse_fails(data, "empty line");
}

#[test]
fn test_missing_trailing_newline() {
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: xxxxx\nsig: xxxxx";
    assert_parse_fails(data, "missing trailing newline");
}

// ── BOM / CR / Null ──

#[test]
fn test_bom() {
    let mut v = vec![0xef, 0xbb, 0xbf];
    v.extend_from_slice(&valid_minimal());
    assert_parse_fails(&v, "BOM");
}

#[test]
fn test_cr() {
    assert_parse_fails(b"origin: v1\rhash: abc\ntime: 0\nkey: a\nsig: a\n", "CR character");
}

#[test]
fn test_null_byte() {
    assert_parse_fails(b"origin: v1\nhash: a\ntime: 0\nkey: a\nsig: a\x00\n", "null byte");
}

// ── Key validation ──

#[test]
fn test_wrong_key_order() {
    let data = b"hash: sha256:abc\norigin: v1\ntime: 0\nkey: x\nsig: x\n";
    assert_parse_fails(data, "wrong key order");
}

#[test]
fn test_wrong_key_order_with_parent() {
    // 6 lines but second key is not 'parent'
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: x\nsig: x\nextra: x\n";
    assert_parse_fails(data, "wrong key order with parent");
}

#[test]
fn test_unknown_key() {
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: x\nfoo: bar\n";
    assert_parse_fails(data, "unknown key");
}

#[test]
fn test_duplicate_key() {
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: x\norigin: v1\n";
    assert_parse_fails(data, "duplicate key");
}

#[test]
fn test_missing_separator() {
    let data = b"origin v1\nhash: sha256:abc\ntime: 0\nkey: x\nsig: x\n";
    assert_parse_fails(data, "missing separator");
}

// ── Field validation ──

#[test]
fn test_bad_origin() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("origin: v1", "origin: v0");
    assert_parse_fails(tampered.as_bytes(), "wrong origin version");
}

#[test]
fn test_bad_hash_prefix() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("sha256:", "md5:");
    assert_parse_fails(tampered.as_bytes(), "bad hash prefix");
}

#[test]
fn test_hash_uppercase() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.to_uppercase();
    assert_parse_fails(tampered.as_bytes(), "uppercase hash");
}

#[test]
fn test_hash_too_short() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "abc",
    );
    assert_parse_fails(tampered.as_bytes(), "hash too short");
}

#[test]
fn test_hash_alg_sha384() {
    // Valid sha384 hash (96 hex chars)
    let data = b"origin: v1\nhash: sha384:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n";
    assert_parse_ok(data, "sha384 hash");
}

#[test]
fn test_hash_alg_sha512() {
    // Valid sha512 hash (128 hex chars)
    let hex128 = "a".repeat(128);
    let data = format!("origin: v1\nhash: sha512:{}\ntime: 0\nkey: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nsig: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n", hex128);
    assert_parse_ok(data.as_bytes(), "sha512 hash");
}

#[test]
fn test_hash_alg_unknown() {
    let data = b"origin: v1\nhash: md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ntime: 0\nkey: xxxxx\nsig: xxxxx\n";
    assert_parse_fails(data, "unknown hash algorithm");
}

#[test]
fn test_timestamp_leading_zero() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("time: 0", "time: 01");
    assert_parse_fails(tampered.as_bytes(), "leading zero in timestamp");
}

#[test]
fn test_timestamp_non_digit() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("time: 0", "time: abc");
    assert_parse_fails(tampered.as_bytes(), "non-digit timestamp");
}

#[test]
fn test_timestamp_overflow() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace("time: 0", "time: 999999999999");
    assert_parse_fails(tampered.as_bytes(), "timestamp overflow");
}

#[test]
fn test_key_wrong_length() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "tooshort",
    );
    assert_parse_fails(tampered.as_bytes(), "key too short");
}

#[test]
fn test_sig_wrong_length() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        "tooshort",
    );
    assert_parse_fails(tampered.as_bytes(), "sig too short");
}

#[test]
fn test_key_invalid_base64url() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let tampered = text.replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "A+++++++++++++++++++++++++++++++++++++++++++",
    );
    assert_parse_fails(tampered.as_bytes(), "invalid base64url in key");
}

#[test]
fn test_key_decoded_length_mismatch() {
    let v = valid_minimal();
    let text = String::from_utf8(v).unwrap();
    let unpadded_44 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(unpadded_44.len(), 44, "test input must be 44 chars");
    let tampered = text.replace(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        unpadded_44,
    );
    assert_parse_fails(tampered.as_bytes(), "decoded key length mismatch");
}

#[test]
fn test_whitespace_in_value() {
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: xxxx\nsig:  xxxx\n";
    assert_parse_fails(data, "leading whitespace in value");
}

#[test]
fn test_empty_value() {
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: \nsig: xxxx\n";
    assert_parse_fails(data, "empty value");
}

#[test]
fn test_control_char_in_value() {
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: xx\x00xx\nsig: xxxx\n";
    assert_parse_fails(data, "control char in value");
}

#[test]
fn test_non_utf8() {
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: xxxx\nsig: \xff\xff\n";
    assert_parse_fails(data, "non-UTF-8");
}

#[test]
fn test_tab_in_value() {
    let data = b"origin: v1\nhash: sha256:abc\ntime: 0\nkey: xx\txx\nsig: xxxx\n";
    assert_parse_fails(data, "tab in value");
}
