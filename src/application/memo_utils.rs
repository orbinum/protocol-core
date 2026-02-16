//! Application layer utilities for encrypted memos
//!
//! Provides high-level functions to work with Orbinum encrypted memos using
//! the `orbinum-encrypted-memo` primitive from Orbinum Node.

extern crate alloc;
use alloc::vec::Vec;

use orbinum_encrypted_memo::{
    decrypt_memo, encrypt_memo_random, is_valid_encrypted_memo, MemoData,
};

/// Encrypts memo data for a recipient with automatic random nonce generation.
///
/// The primitive generates cryptographically secure nonces automatically using
/// the system's CSPRNG, eliminating the need for manual nonce management.
///
/// # Arguments
/// * `value` - Amount in the note
/// * `owner_pk` - Owner's public key (32 bytes)
/// * `blinding` - Blinding factor (32 bytes)
/// * `asset_id` - Asset identifier
/// * `commitment` - Note commitment (32 bytes)
/// * `recipient_viewing_key` - Recipient's viewing key (32 bytes)
///
/// # Returns
/// Encrypted memo bytes (104 bytes: 12-byte nonce + 92-byte ciphertext)
pub fn create_encrypted_memo(
    value: u64,
    owner_pk: [u8; 32],
    blinding: [u8; 32],
    asset_id: u32,
    commitment: &[u8; 32],
    recipient_viewing_key: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    let memo = MemoData::new(value, owner_pk, blinding, asset_id);

    encrypt_memo_random(&memo, commitment, recipient_viewing_key)
        .map_err(|_| "Failed to encrypt memo")
}

/// Decrypts an encrypted memo using the viewing key.
///
/// # Arguments
/// * `encrypted` - Encrypted memo bytes (104 bytes)
/// * `commitment` - Note commitment (32 bytes)
/// * `viewing_key` - Viewing key (32 bytes)
///
/// # Returns
/// Decrypted `MemoData` containing value, owner_pk, blinding, and asset_id
pub fn decrypt_encrypted_memo(
    encrypted: &[u8],
    commitment: &[u8; 32],
    viewing_key: &[u8; 32],
) -> Result<MemoData, &'static str> {
    decrypt_memo(encrypted, commitment, viewing_key).map_err(|_| "Failed to decrypt memo")
}

/// Validates encrypted memo format.
///
/// Checks length bounds: minimum 28 bytes, maximum 104 bytes.
pub fn validate_encrypted_memo(encrypted: &[u8]) -> bool {
    is_valid_encrypted_memo(encrypted)
}

/// Creates a dummy encrypted memo for testing.
///
/// Returns a valid 104-byte encrypted memo with zero values.
pub fn create_dummy_encrypted_memo() -> Vec<u8> {
    let memo = MemoData::new(0, [0u8; 32], [0u8; 32], 0);
    let commitment = [0u8; 32];
    let viewing_key = [0u8; 32];

    encrypt_memo_random(&memo, &commitment, &viewing_key)
        .expect("Dummy memo encryption should never fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let value = 1000u64;
        let owner_pk = [1u8; 32];
        let blinding = [2u8; 32];
        let asset_id = 0u32;
        let commitment = [3u8; 32];
        let viewing_key = [4u8; 32];

        let encrypted = create_encrypted_memo(
            value,
            owner_pk,
            blinding,
            asset_id,
            &commitment,
            &viewing_key,
        )
        .expect("Encryption should succeed");

        assert_eq!(encrypted.len(), 104); // 12 + 76 + 16

        let decrypted = decrypt_encrypted_memo(&encrypted, &commitment, &viewing_key)
            .expect("Decryption should succeed");

        assert_eq!(decrypted.value, value);
        assert_eq!(decrypted.owner_pk, owner_pk);
        assert_eq!(decrypted.blinding, blinding);
        assert_eq!(decrypted.asset_id, asset_id);
    }

    #[test]
    fn test_validate_encrypted_memo() {
        let dummy = create_dummy_encrypted_memo();
        assert!(validate_encrypted_memo(&dummy));

        // Too short (less than 28 bytes)
        assert!(!validate_encrypted_memo(&[0u8; 27]));

        // Too long (more than 104 bytes)
        assert!(!validate_encrypted_memo(&[0u8; 105]));

        // Minimum valid size (28 bytes)
        assert!(validate_encrypted_memo(&[0u8; 28]));

        // Maximum valid size (104 bytes)
        assert!(validate_encrypted_memo(&[0u8; 104]));
    }

    #[test]
    fn test_dummy_encrypted_memo() {
        let dummy = create_dummy_encrypted_memo();
        assert_eq!(dummy.len(), 104);
        assert!(validate_encrypted_memo(&dummy));
    }
}
