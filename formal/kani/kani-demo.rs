// Kani Rust Verifier harness for origin-core parser
// Run: cargo kani --harness verify_parse -- -Z stderr

#[cfg(kani)]
mod verification {
    use origin_core::statement::Statement;

    #[kani::proof]
    fn verify_parse() {
        // Symbolic input: up to 256 bytes
        let input: [u8; 256] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 256);
        let _ = Statement::parse(&input[..len]);
        // Should not panic for any input
    }
}
