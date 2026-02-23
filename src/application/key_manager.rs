//! Key Management utilities
//!
//! Provides high-level functions for deriving and managing cryptographic keys
//! in the Orbinum wallet.

use orbinum_encrypted_memo::{
    derive_eddsa_key_from_spending as derive_eddsa_key,
    derive_nullifier_key_from_spending as derive_nullifier_key,
    derive_viewing_key_from_spending as derive_viewing_key, KeySet,
};

/// Derives viewing key from spending key.
///
/// The viewing key allows reading all transactions but cannot spend funds.
/// Safe to share with auditors for compliance purposes.
pub fn derive_viewing_key_from_spending(spending_key: &[u8; 32]) -> [u8; 32] {
    *derive_viewing_key(spending_key).as_bytes()
}

/// Derives nullifier key from spending key.
///
/// Used to compute nullifiers for spending notes. Must be kept secret.
pub fn derive_nullifier_key_from_spending(spending_key: &[u8; 32]) -> [u8; 32] {
    *derive_nullifier_key(spending_key).as_bytes()
}

/// Derives EdDSA signing key from spending key.
///
/// Used for circuit signatures in ZK proofs. Must be kept secret.
pub fn derive_eddsa_key_from_spending(spending_key: &[u8; 32]) -> [u8; 32] {
    *derive_eddsa_key(spending_key).as_bytes()
}

/// Derives complete keyset from spending key.
///
/// Generates all derived keys at once: viewing, nullifier, and EdDSA.
pub fn derive_keyset_from_spending(spending_key: &[u8; 32]) -> KeySet {
    KeySet::from_spending_key(*spending_key)
}

/// Validates spending key format (32 bytes, non-zero).
pub fn validate_spending_key(key: &[u8]) -> bool {
    if key.len() != 32 {
        return false;
    }

    // Check it's not all zeros
    key.iter().any(|&b| b != 0)
}

/// Validates viewing key format (32 bytes).
pub fn validate_viewing_key(key: &[u8]) -> bool {
    key.len() == 32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_viewing_key() {
        let spending_key = [1u8; 32];
        let viewing_key = derive_viewing_key_from_spending(&spending_key);

        assert_eq!(viewing_key.len(), 32);
        assert_ne!(viewing_key, spending_key); // Should be different
    }

    #[test]
    fn test_derive_nullifier_key() {
        let spending_key = [2u8; 32];
        let nullifier_key = derive_nullifier_key_from_spending(&spending_key);

        assert_eq!(nullifier_key.len(), 32);
        assert_ne!(nullifier_key, spending_key);
    }

    #[test]
    fn test_derive_keyset() {
        let spending_key = [3u8; 32];
        let keyset = derive_keyset_from_spending(&spending_key);

        // All keys should be different
        assert_ne!(keyset.viewing_key.as_bytes(), spending_key.as_slice());
        assert_ne!(keyset.nullifier_key.as_bytes(), spending_key.as_slice());
        assert_ne!(keyset.eddsa_key.as_bytes(), spending_key.as_slice());

        // Keys should be different from each other
        assert_ne!(
            keyset.viewing_key.as_bytes(),
            keyset.nullifier_key.as_bytes()
        );
        assert_ne!(keyset.viewing_key.as_bytes(), keyset.eddsa_key.as_bytes());
    }

    #[test]
    fn test_deterministic_derivation() {
        let spending_key = [4u8; 32];

        // Multiple calls should produce same results
        let vk1 = derive_viewing_key_from_spending(&spending_key);
        let vk2 = derive_viewing_key_from_spending(&spending_key);

        assert_eq!(vk1, vk2);
    }

    #[test]
    fn test_validate_spending_key() {
        assert!(validate_spending_key(&[1u8; 32]));
        assert!(!validate_spending_key(&[0u8; 32])); // All zeros invalid
        assert!(!validate_spending_key(&[1u8; 31])); // Wrong length
        assert!(!validate_spending_key(&[1u8; 33])); // Wrong length
    }

    #[test]
    fn test_validate_viewing_key() {
        assert!(validate_viewing_key(&[0u8; 32]));
        assert!(!validate_viewing_key(&[0u8; 31]));
        assert!(!validate_viewing_key(&[0u8; 33]));
    }
}
