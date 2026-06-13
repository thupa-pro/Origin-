#![deny(missing_docs)]
#![deny(unsafe_code)]

//! Intent-Value Graph (IVG): a conflict-free replicated data type (CRDT)
//! for storing and resolving policy rulebooks bound to .origin statements.
//!
//! The IVG maps (hash, public_key) → rulebook entries, enabling queries like
//! "Who owns this hash?" and "What are the terms of use?"

use origin_core::Error;

extern crate alloc;

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
    // E005 IVG_UNREACHABLE: CRDT-based resolution not yet implemented.
    // Returns None to signal unreachability, allowing callers to fall back
    // to research_only mode per spec section 5.1.
    None
}

/// Resolve a rulebook entry with error construction.
///
/// Attempts CRDT resolution. If unreachable, returns `Error::IvgUnreachable` (E005).
pub fn resolve_or_err(hash: &[u8; 32]) -> origin_core::Result<RuleEntry> {
    let _ = hash;
    resolve(hash).ok_or_else(|| Error::IvgUnreachable(
        "rulebook entry not resolvable (IVG CRDT offline)".into()
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ivg_crdt_merge() {
        // TODO: implement CRDT merge test
    }
}
