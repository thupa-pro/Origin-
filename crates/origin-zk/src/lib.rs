#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Zero-Knowledge (ZK) circuits for the Origin Network.
//!
//! Implements Halo2 proofs for:
//! - Proof of Binding (PoB): prove a .origin statement commits to a
//!   specific artifact without revealing the artifact
//! - Consent Proofs: prove that a signature was made with knowledge of
//!   a specific policy document

/// Generate a Proof of Binding for a .origin statement.
pub fn prove_binding(_statement: &[u8], _artifact: &[u8]) -> Vec<u8> {
    let _ = (_statement, _artifact);
    todo!("origin-zk: implement PoB circuit")
}

/// Verify a Proof of Binding.
pub fn verify_binding(_proof: &[u8], _statement: &[u8]) -> bool {
    let _ = (_proof, _statement);
    todo!("origin-zk: implement PoB verification")
}

/// Generate a Consent Proof.
pub fn prove_consent(_statement: &[u8], _policy: &[u8]) -> Vec<u8> {
    let _ = (_statement, _policy);
    todo!("origin-zk: implement Consent Proof circuit")
}

/// Verify a Consent Proof.
pub fn verify_consent(_proof: &[u8], _policy: &[u8]) -> bool {
    let _ = (_proof, _policy);
    todo!("origin-zk: implement Consent Proof verification")
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_pob_roundtrip() {
        // TODO: implement with test circuit
    }
}
