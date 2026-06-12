use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn bench_verify(c: &mut Criterion) {
    let secret = origin_core::SecretKey::from_bytes(&[42u8; 32]).unwrap();
    let artifact = b"benchmark artifact data for performance testing";
    let stmt = origin_core::build_statement(&secret, artifact, 1_000_000).unwrap();
    let encoded = origin_core::encode_statement(&stmt);

    c.bench_function("verify_bytes", |b| {
        b.iter(|| {
            let result = origin_core::verify_bytes(black_box(&encoded), black_box(artifact));
            black_box(result)
        })
    });

    c.bench_function("build_statement", |b| {
        b.iter(|| {
            let s = origin_core::build_statement(
                black_box(&secret),
                black_box(artifact),
                black_box(1_000_001),
            );
            black_box(s)
        })
    });

    c.bench_function("encode_decode_roundtrip", |b| {
        b.iter(|| {
            let s = origin_core::build_statement(&secret, artifact, 1_000_002).unwrap();
            let enc = origin_core::encode_statement(black_box(&s));
            let parsed = origin_core::Statement::parse(black_box(&enc)).unwrap();
            black_box(parsed)
        })
    });
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
