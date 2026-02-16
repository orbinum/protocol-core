//! Cryptographic domain types
//!
//! Types representing cryptographic primitives used in zero-knowledge proofs,
//! signatures, and key management.

extern crate alloc;
use crate::domain::ports::Serializable;
use alloc::vec::Vec;

/// Commitment for notes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(pub [u8; 32]);

impl Commitment {
    /// Creates a Commitment from bytes with validation
    ///
    /// # Errors
    /// Returns error if commitment is all zeros (invalid in ZK systems)
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, &'static str> {
        if bytes == [0u8; 32] {
            return Err("Commitment cannot be all zeros");
        }
        Ok(Commitment(bytes))
    }

    /// Creates a Commitment without validation
    ///
    /// # Safety
    /// Use only when you trust the source (e.g., from blockchain, tests)
    pub fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Commitment(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serializable for Commitment {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 32 {
            return Err("Commitment requires 32 bytes");
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[..32]);
        Self::from_bytes(array)
    }
}

/// Nullifier to prevent double-spending
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    /// Creates a Nullifier from bytes with validation
    ///
    /// # Errors
    /// Returns error if nullifier is all zeros (invalid)
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, &'static str> {
        if bytes == [0u8; 32] {
            return Err("Nullifier cannot be all zeros");
        }
        Ok(Nullifier(bytes))
    }

    /// Creates a Nullifier without validation
    ///
    /// # Safety
    /// Use only when you trust the source (e.g., from blockchain, tests)
    pub fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Nullifier(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serializable for Nullifier {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 32 {
            return Err("Nullifier requires 32 bytes");
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[..32]);
        Self::from_bytes(array)
    }
}

/// ECDSA signature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl Signature {
    pub fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Signature { r, s, v }
    }

    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.v;
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 65]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..64]);
        let v = bytes[64];
        Signature { r, s, v }
    }
}

/// Private key (opaque for security)
#[derive(Clone)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// Implementation of Zeroize for security (when memory is released)
impl Drop for SecretKey {
    fn drop(&mut self) {
        // Overwrite memory with zeros
        self.0.iter_mut().for_each(|byte| *byte = 0);
    }
}

/// Public key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 64]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        PublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_serializable() {
        let original = Commitment::from_bytes_unchecked([3u8; 32]);
        let bytes = original.to_bytes();

        assert_eq!(bytes.len(), 32);

        let deserialized = <Commitment as Serializable>::from_bytes(&bytes).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_commitment_from_bytes_error() {
        let short_bytes = vec![1u8; 20];
        let result = <Commitment as Serializable>::from_bytes(&short_bytes);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Commitment requires 32 bytes");
    }

    #[test]
    fn test_commitment_validation_all_zeros() {
        let result = Commitment::from_bytes([0u8; 32]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Commitment cannot be all zeros");

        // Unchecked should work
        let commitment = Commitment::from_bytes_unchecked([0u8; 32]);
        assert_eq!(commitment.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_nullifier_serializable() {
        let original = Nullifier::from_bytes_unchecked([4u8; 32]);
        let bytes = original.to_bytes();

        assert_eq!(bytes.len(), 32);

        let deserialized = <Nullifier as Serializable>::from_bytes(&bytes).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_nullifier_from_bytes_error() {
        let short_bytes = vec![1u8; 8];
        let result = <Nullifier as Serializable>::from_bytes(&short_bytes);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Nullifier requires 32 bytes");
    }

    #[test]
    fn test_nullifier_validation_all_zeros() {
        let result = Nullifier::from_bytes([0u8; 32]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Nullifier cannot be all zeros");

        // Unchecked should work
        let nullifier = Nullifier::from_bytes_unchecked([0u8; 32]);
        assert_eq!(nullifier.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_serializable_roundtrip_crypto() {
        // Test that crypto types can be serialized and deserialized correctly
        let commitment = Commitment::from_bytes_unchecked([7u8; 32]);
        assert_eq!(
            commitment,
            <Commitment as Serializable>::from_bytes(&commitment.to_bytes()).unwrap()
        );

        let nullifier = Nullifier::from_bytes_unchecked([8u8; 32]);
        assert_eq!(
            nullifier,
            <Nullifier as Serializable>::from_bytes(&nullifier.to_bytes()).unwrap()
        );
    }

    #[test]
    fn test_signature_roundtrip() {
        let r = [1u8; 32];
        let s = [2u8; 32];
        let v = 27u8;

        let sig = Signature::new(r, s, v);
        let bytes = sig.to_bytes();

        assert_eq!(bytes.len(), 65);

        let recovered = Signature::from_bytes(&bytes);
        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_secret_key_zeroize() {
        let key_bytes = [42u8; 32];
        {
            let _key = SecretKey::from_bytes(key_bytes);
            // Key will be zeroized when dropped
        }
        // Unfortunately we can't test that memory was zeroized without unsafe code
    }

    #[test]
    fn test_public_key_roundtrip() {
        let bytes = [3u8; 64];
        let pubkey = PublicKey::from_bytes(bytes);
        assert_eq!(pubkey.as_bytes(), &bytes);
    }
}
