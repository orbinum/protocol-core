//! Domain Types Module
//!
//! Core domain types organized by category:
//! - **primitives**: Basic blockchain types (Address, Hash)
//! - **crypto**: Cryptographic types (Commitment, Nullifier, Keys, Signatures)
//! - **identifiers**: Type-safe identifier wrappers (AssetId)

pub mod crypto;
pub mod identifiers;
pub mod primitives;

// Re-export all types for convenient access
pub use crypto::{Commitment, Nullifier, PublicKey, SecretKey, Signature};
pub use identifiers::AssetId;
pub use primitives::{Address, Hash};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_types_reexports_basic_usage() {
        let address = Address::from_slice_unchecked(&[1u8; 20]);
        let hash = Hash::from_slice(&[2u8; 32]);
        let commitment = Commitment::from_bytes_unchecked([3u8; 32]);
        let nullifier = Nullifier::from_bytes_unchecked([4u8; 32]);
        let signature = Signature::new([5u8; 32], [6u8; 32], 27);
        let secret = SecretKey::from_bytes([7u8; 32]);
        let public = PublicKey::from_bytes([8u8; 64]);
        let asset = AssetId::new(9);

        assert_eq!(address.as_bytes(), &[1u8; 20]);
        assert_eq!(hash.as_bytes(), &[2u8; 32]);
        assert_eq!(commitment.as_bytes(), &[3u8; 32]);
        assert_eq!(nullifier.as_bytes(), &[4u8; 32]);
        assert_eq!(signature.to_bytes().len(), 65);
        assert_eq!(secret.as_bytes(), &[7u8; 32]);
        assert_eq!(public.as_bytes(), &[8u8; 64]);
        assert_eq!(asset.as_u32(), 9);
    }
}
