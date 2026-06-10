use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_parse_valid(c: &mut Criterion) {
    let statement = b"origin: v1\ntype: provenance\nhash: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\ntime: 1717776000\nkey: 71RZ3zdJoLcAjfPiis7oxnM3K6IfHpNUrf4Da493VAY=\nsig: XyZ9A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0E1f2G3h4I5j6K7l8M9n0O=\n";

    c.bench_function("parse_valid", |b| {
        b.iter(|| origin_core::Statement::parse(black_box(statement)))
    });
}

fn bench_verify_valid(c: &mut Criterion) {
    // Build a real valid statement using the library
    let seed = [42u8; 32];
    let secret = origin_core::SecretKey::from_bytes(&seed).unwrap();
    let artifact = b"hello world";
    let stmt = origin_core::build_statement(&secret, artifact, 1717776000, None).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    c.bench_function("verify_valid", |b| {
        b.iter(|| {
            let _ = origin_core::verify_consistency(black_box(&encoded), black_box(artifact));
        })
    });
}

criterion_group!(benches, bench_parse_valid, bench_verify_valid);
criterion_main!(benches);
