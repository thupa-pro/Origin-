use alloc::vec::Vec;
use blst::min_sig::{self as bls_impl};
use blst::BLST_ERROR;

const DST: &[u8] = b"ORIGIN_BLS_SIG_V1";

/// BLS public key: 96 bytes (G2 point, min_sig variant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsPublicKey(pub [u8; 96]);

/// BLS signature: 48 bytes (G1 point, min_sig variant).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsSignature(pub [u8; 48]);

/// BLS secret key: 32 bytes (scalar).
#[derive(Clone)]
pub struct BlsSecretKey(pub [u8; 32]);

pub fn generate_bls_keypair_from_seed(seed: &[u8; 32]) -> (BlsSecretKey, BlsPublicKey) {
    let sk = bls_impl::SecretKey::key_gen(seed, b"ORIGIN_BLS_KEY_V1")
        .expect("BLS key generation from 32-byte seed cannot fail");
    let pk = sk.sk_to_pk();
    (BlsSecretKey(sk.to_bytes()), BlsPublicKey(pk.to_bytes()))
}

pub fn bls_sign(secret: &BlsSecretKey, msg: &[u8]) -> BlsSignature {
    let sk = bls_impl::SecretKey::from_bytes(&secret.0)
        .expect("valid 32-byte BLS secret key");
    let sig = sk.sign(msg, DST, b"");
    BlsSignature(sig.to_bytes())
}

pub fn bls_verify(pk: &BlsPublicKey, msg: &[u8], sig: &BlsSignature) -> bool {
    let pk_point = match bls_impl::PublicKey::from_bytes(&pk.0) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig_point = match bls_impl::Signature::from_bytes(&sig.0) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig_point.verify(false, msg, DST, b"", &pk_point, true) == BLST_ERROR::BLST_SUCCESS
}

pub fn bls_aggregate_signatures(sigs: &[&BlsSignature]) -> Result<BlsSignature, BLST_ERROR> {
    let blst_sigs: Vec<bls_impl::Signature> = sigs
        .iter()
        .map(|s| bls_impl::Signature::from_bytes(&s.0).unwrap())
        .collect();
    let refs: Vec<&bls_impl::Signature> = blst_sigs.iter().collect();
    let agg = bls_impl::AggregateSignature::aggregate(&refs, true)?;
    Ok(BlsSignature(agg.to_signature().to_bytes()))
}

pub fn bls_aggregate_public_keys(pks: &[&BlsPublicKey]) -> Result<BlsPublicKey, BLST_ERROR> {
    let blst_pks: Vec<bls_impl::PublicKey> = pks
        .iter()
        .map(|pk| bls_impl::PublicKey::from_bytes(&pk.0).unwrap())
        .collect();
    let refs: Vec<&bls_impl::PublicKey> = blst_pks.iter().collect();
    let agg = bls_impl::AggregatePublicKey::aggregate(&refs, true)?;
    Ok(BlsPublicKey(agg.to_public_key().to_bytes()))
}

pub fn bls_verify_aggregate(
    msg: &[u8],
    sig: &BlsSignature,
    public_keys: &[&BlsPublicKey],
) -> bool {
    if public_keys.is_empty() {
        return false;
    }
    let agg_pk = match bls_aggregate_public_keys(public_keys) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    bls_verify(&agg_pk, msg, sig)
}

impl BlsPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        if bytes.len() != 96 {
            return Err(crate::error::Error::Crypto(
                alloc::format!("BLS public key must be 96 bytes, got {}", bytes.len()),
            ));
        }
        let mut key = [0u8; 96];
        key.copy_from_slice(bytes);
        if bls_impl::PublicKey::from_bytes(&key).is_err() {
            return Err(crate::error::Error::Crypto(
                "invalid BLS public key: not on curve or invalid subgroup".into(),
            ));
        }
        Ok(BlsPublicKey(key))
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        self.0
    }
}

impl BlsSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        if bytes.len() != 48 {
            return Err(crate::error::Error::Crypto(
                alloc::format!("BLS signature must be 48 bytes, got {}", bytes.len()),
            ));
        }
        let mut sig = [0u8; 48];
        sig.copy_from_slice(bytes);
        if bls_impl::Signature::from_bytes(&sig).is_err() {
            return Err(crate::error::Error::Crypto(
                "invalid BLS signature: not on curve".into(),
            ));
        }
        Ok(BlsSignature(sig))
    }

    pub fn to_bytes(&self) -> [u8; 48] {
        self.0
    }
}

impl BlsSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        if bytes.len() != 32 {
            return Err(crate::error::Error::Crypto(
                alloc::format!("BLS secret key must be 32 bytes, got {}", bytes.len()),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(BlsSecretKey(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls_keypair_deterministic() {
        let seed = [0x42u8; 32];
        let (sk1, pk1) = generate_bls_keypair_from_seed(&seed);
        let (sk2, pk2) = generate_bls_keypair_from_seed(&seed);
        assert_eq!(sk1.0, sk2.0, "BLS secret keys must be deterministic");
        assert_eq!(pk1.0, pk2.0, "BLS public keys must be deterministic");
    }

    #[test]
    fn test_bls_sign_verify_roundtrip() {
        let seed = [0x01u8; 32];
        let (sk, pk) = generate_bls_keypair_from_seed(&seed);
        let msg = b"test message for BLS signing";
        let sig = bls_sign(&sk, msg);
        assert!(bls_verify(&pk, msg, &sig), "BLS verify must succeed for valid signature");
    }

    #[test]
    fn test_bls_verify_rejects_wrong_message() {
        let seed = [0x02u8; 32];
        let (sk, pk) = generate_bls_keypair_from_seed(&seed);
        let sig = bls_sign(&sk, b"correct message");
        assert!(!bls_verify(&pk, b"wrong message", &sig), "BLS must reject wrong message");
    }

    #[test]
    fn test_bls_aggregate_sign_verify() {
        let msg = b"aggregate BLS test message";
        let seed1 = [0x11u8; 32];
        let seed2 = [0x22u8; 32];
        let (sk1, pk1) = generate_bls_keypair_from_seed(&seed1);
        let (sk2, pk2) = generate_bls_keypair_from_seed(&seed2);

        let sig1 = bls_sign(&sk1, msg);
        let sig2 = bls_sign(&sk2, msg);

        let agg_sig = bls_aggregate_signatures(&[&sig1, &sig2])
            .expect("aggregate signatures must succeed");
        let agg_verify = bls_verify_aggregate(msg, &agg_sig, &[&pk1, &pk2]);
        assert!(agg_verify, "BLS aggregate verify must succeed");
    }

    #[test]
    fn test_bls_rejects_single_signer_mismatch() {
        let seed1 = [0x33u8; 32];
        let seed2 = [0x44u8; 32];
        let (sk1, pk1) = generate_bls_keypair_from_seed(&seed1);
        let (_sk2, pk2) = generate_bls_keypair_from_seed(&seed2);

        let msg = b"aggregate mismatch test";
        let sig1 = bls_sign(&sk1, msg);
        let sig2 = bls_sign(&sk1, msg); // both from sk1

        // Aggregate two signatures from same key
        let agg_sig = bls_aggregate_signatures(&[&sig1, &sig2])
            .expect("aggregate must succeed");

        // Verify against pk1 + pk2 — should fail since pk2 didn't sign
        let result = bls_verify_aggregate(msg, &agg_sig, &[&pk1, &pk2]);
        assert!(!result, "BLS aggregate must reject when one key didn't sign");
    }

    #[test]
    fn test_bls_public_key_from_bytes() {
        let seed = [0x55u8; 32];
        let (_, pk) = generate_bls_keypair_from_seed(&seed);
        let bytes = pk.to_bytes();
        let parsed = BlsPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn test_bls_rejects_invalid_public_key() {
        let invalid = [0u8; 48];
        assert!(BlsPublicKey::from_bytes(&invalid).is_err());
    }

    #[test]
    fn test_bls_signature_serialization() {
        let seed = [0x66u8; 32];
        let (sk, _pk) = generate_bls_keypair_from_seed(&seed);
        let msg = b"serialization test";
        let sig = bls_sign(&sk, msg);
        let bytes = sig.to_bytes();
        let parsed = BlsSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn test_bls_deterministic_100_runs() {
        let seed = [0x77u8; 32];
        let (sk, _pk) = generate_bls_keypair_from_seed(&seed);
        let msg = b"deterministic BLS test";
        let first_sig = bls_sign(&sk, msg);
        for _ in 0..100 {
            let sig = bls_sign(&sk, msg);
            assert_eq!(sig.0, first_sig.0, "BLS signatures must be deterministic");
        }
    }
}
