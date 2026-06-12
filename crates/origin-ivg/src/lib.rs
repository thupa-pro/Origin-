#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Intent-Value Graph (IVG): a conflict-free replicated data type (CRDT)
//! for storing and resolving policy rulebooks bound to .origin statements.
//!
//! The IVG maps (hash, public_key) → rulebook entries, enabling queries like
//! "Who owns this hash?" and "What are the terms of use?"

/// A collection of rulebook entries forming a policy set.
pub struct Rulebook {
    /// The entries in this rulebook.
    pub entries: Vec<RuleEntry>,
}

/// A single rulebook entry binding an artifact hash to an owner with terms.
pub struct RuleEntry {
    /// SHA-256 hash of the artifact.
    pub hash: [u8; 32],
    /// Ed25519 public key of the owner.
    pub owner: [u8; 32],
    /// Serialized terms of use (format TBD).
    pub terms: Vec<u8>,
}

/// Resolve a rulebook entry for a given artifact hash.
pub fn resolve(_hash: &[u8; 32]) -> Option<RuleEntry> {
    let _ = _hash;
    todo!("origin-ivg: implement CRDT-based resolution")
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ivg_crdt_merge() {
        // TODO: implement CRDT merge test
    }
}
