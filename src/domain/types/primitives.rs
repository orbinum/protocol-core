//! Primitive domain types
//!
//! Basic types representing addresses, hashes and other fundamental blockchain primitives.

extern crate alloc;
use crate::domain::ports::Serializable;
use alloc::vec::Vec;

/// Substrate AccountId32 address (32 bytes)
///
/// Supports both Sr25519 accounts (public key = AccountId32 directly) and
/// ECDSA accounts (blake2_256(compressed_pubkey_33_bytes) = AccountId32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address(pub [u8; 32]);

impl Address {
    /// Creates an Address from a slice with validation
    ///
    /// # Errors
    /// Returns error if slice is not exactly 32 bytes
    pub fn from_slice(slice: &[u8]) -> Result<Self, &'static str> {
        if slice.len() != 32 {
            return Err("Address must be exactly 32 bytes");
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Address(bytes))
    }

    /// Creates an Address without validation
    ///
    /// # Safety
    /// Panics if slice has less than 32 bytes. Use only with trusted input.
    pub fn from_slice_unchecked(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&slice[..32]);
        Address(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serializable for Address {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        Self::from_slice(bytes)
    }
}

impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Address(bytes)
    }
}

/// Hash (H256)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&slice[..32]);
        Hash(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serializable for Hash {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 32 {
            return Err("Hash requires 32 bytes");
        }
        Ok(Self::from_slice(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_serializable() {
        let original = Address::from_slice_unchecked(&[1u8; 32]);
        let bytes = original.to_bytes();

        assert_eq!(bytes.len(), 32);

        let deserialized = Address::from_bytes(&bytes).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_address_from_bytes_error() {
        let short_bytes = vec![1u8; 10];
        let result = Address::from_bytes(&short_bytes);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Address must be exactly 32 bytes");
    }

    #[test]
    fn test_address_from_slice_validation() {
        let valid = Address::from_slice(&[42u8; 32]);
        assert!(valid.is_ok());

        let invalid = Address::from_slice(&[1u8; 15]);
        assert!(invalid.is_err());
        assert_eq!(invalid.unwrap_err(), "Address must be exactly 32 bytes");
    }

    #[test]
    fn test_hash_serializable() {
        let original = Hash::from_slice(&[2u8; 32]);
        let bytes = original.to_bytes();

        assert_eq!(bytes.len(), 32);

        let deserialized = Hash::from_bytes(&bytes).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_hash_from_bytes_error() {
        let short_bytes = vec![1u8; 16];
        let result = Hash::from_bytes(&short_bytes);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Hash requires 32 bytes");
    }

    #[test]
    fn test_serializable_roundtrip_primitives() {
        // Test that primitive types can be serialized and deserialized correctly
        let address = Address::from_slice_unchecked(&[5u8; 32]);
        assert_eq!(
            address,
            <Address as Serializable>::from_bytes(&address.to_bytes()).unwrap()
        );

        let hash = Hash::from_slice(&[6u8; 32]);
        assert_eq!(
            hash,
            <Hash as Serializable>::from_bytes(&hash.to_bytes()).unwrap()
        );
    }
}
