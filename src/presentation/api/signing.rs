//! Signing API
//!
//! Build and sign transactions with integrated ECDSA (requires "crypto" feature).

#[cfg(feature = "crypto")]
use crate::application::builders::*;
#[cfg(feature = "crypto")]
use crate::application::errors::SignerError;
#[cfg(feature = "crypto")]
use crate::application::params::*;
#[cfg(feature = "crypto")]
use crate::domain::ports::SignerPort;
#[cfg(feature = "crypto")]
use crate::domain::types::*;
#[cfg(feature = "crypto")]
use crate::infrastructure::crypto::EcdsaSigner;
#[cfg(feature = "crypto")]
use crate::infrastructure::serializers::SubstrateTransactionEncoder;

#[cfg(feature = "crypto")]
extern crate alloc;
#[cfg(feature = "crypto")]
use alloc::vec::Vec;

/// API for signing and building complete transactions.
#[cfg(feature = "crypto")]
pub struct SigningApi;

#[cfg(feature = "crypto")]
impl SigningApi {
    /// Creates a signer from hex private key.
    pub fn create_signer(private_key_hex: &str) -> Result<EcdsaSigner, SignerError> {
        EcdsaSigner::from_hex(private_key_hex).map_err(|e| e.into())
    }

    /// Signs and builds complete Shield transaction.
    pub fn sign_and_build_shield(
        amount: u128,
        asset_id: u32,
        commitment: [u8; 32],
        encrypted_memo: Vec<u8>,
        nonce: u32,
        private_key_hex: &str,
    ) -> Result<Vec<u8>, SignerError> {
        let signer = Self::create_signer(private_key_hex)?;

        let params = ShieldParams {
            amount,
            asset_id: AssetId::new(asset_id),
            commitment: Commitment::from_bytes(commitment)
                .map_err(|e| SignerError::Other(format!("Invalid commitment: {}", e)))?,
        };

        let encoder = SubstrateTransactionEncoder::new();
        ShieldBuilder::build_signed(&encoder, params, encrypted_memo, nonce, &signer)
    }

    /// Signs and builds complete Unshield transaction.
    pub fn sign_and_build_unshield(
        nullifier: [u8; 32],
        amount: u128,
        asset_id: u32,
        recipient: [u8; 32],
        root: [u8; 32],
        proof: Vec<u8>,
        nonce: u32,
        private_key_hex: &str,
    ) -> Result<Vec<u8>, SignerError> {
        let signer = Self::create_signer(private_key_hex)?;

        let params = UnshieldParams {
            nullifier: Nullifier::from_bytes(nullifier)
                .map_err(|e| SignerError::Other(format!("Invalid nullifier: {}", e)))?,
            amount,
            recipient: Address::from_slice(&recipient)
                .map_err(|e| SignerError::Other(format!("Invalid recipient: {}", e)))?,
            root: Hash::from_slice(&root),
            proof,
        };

        let encoder = SubstrateTransactionEncoder::new();
        UnshieldBuilder::build_signed(&encoder, params, AssetId::new(asset_id), nonce, &signer)
    }

    /// Signs and builds complete private Transfer transaction.
    pub fn sign_and_build_transfer(
        input_nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        root: [u8; 32],
        proof: Vec<u8>,
        encrypted_memos: [Vec<u8>; 2],
        nonce: u32,
        private_key_hex: &str,
    ) -> Result<Vec<u8>, SignerError> {
        let signer = Self::create_signer(private_key_hex)?;

        let params = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes(input_nullifiers[0])
                    .map_err(|e| SignerError::Other(format!("Invalid nullifier 0: {}", e)))?,
                Nullifier::from_bytes(input_nullifiers[1])
                    .map_err(|e| SignerError::Other(format!("Invalid nullifier 1: {}", e)))?,
            ],
            output_commitments: [
                Commitment::from_bytes(output_commitments[0])
                    .map_err(|e| SignerError::Other(format!("Invalid commitment 0: {}", e)))?,
                Commitment::from_bytes(output_commitments[1])
                    .map_err(|e| SignerError::Other(format!("Invalid commitment 1: {}", e)))?,
            ],
            root: Hash::from_slice(&root),
            proof,
            encrypted_memos: encrypted_memos.clone(),
        };

        let encoder = SubstrateTransactionEncoder::new();
        TransferBuilder::build_signed(&encoder, params, nonce, &signer)
    }

    /// Gets Substrate AccountId32 from ECDSA private key.
    ///
    /// # Returns
    /// AccountId32 (32 bytes) = blake2_256(compressed_secp256k1_pubkey)
    pub fn get_address(private_key_hex: &str) -> Result<[u8; 32], SignerError> {
        let signer = Self::create_signer(private_key_hex)?;
        Ok(*signer.address().as_bytes())
    }
}

#[cfg(test)]
#[cfg(feature = "crypto")]
mod tests {
    use super::*;

    fn valid_key() -> &'static str {
        "0101010101010101010101010101010101010101010101010101010101010101"
    }

    #[test]
    fn test_create_signer_and_get_address() {
        let signer = SigningApi::create_signer(valid_key());
        assert!(signer.is_ok());

        let address = SigningApi::get_address(valid_key());
        assert!(address.is_ok());
        assert_eq!(address.unwrap().len(), 32);
    }

    #[test]
    fn test_sign_and_build_shield() {
        let out =
            SigningApi::sign_and_build_shield(100, 1, [2u8; 32], vec![3u8; 16], 0, valid_key());

        assert!(out.is_ok());
        let bytes = out.unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_sign_and_build_unshield() {
        let out = SigningApi::sign_and_build_unshield(
            [4u8; 32],
            50,
            1,
            [5u8; 32],
            [6u8; 32],
            vec![7u8; 64],
            1,
            valid_key(),
        );

        assert!(out.is_ok());
        assert!(!out.unwrap().is_empty());
    }

    #[test]
    fn test_sign_and_build_transfer() {
        let out = SigningApi::sign_and_build_transfer(
            [[8u8; 32], [9u8; 32]],
            [[10u8; 32], [11u8; 32]],
            [12u8; 32],
            vec![13u8; 64],
            [vec![14u8; 8], vec![15u8; 8]],
            2,
            valid_key(),
        );

        assert!(out.is_ok());
        assert!(!out.unwrap().is_empty());
    }

    #[test]
    fn test_sign_and_build_shield_invalid_commitment() {
        let out =
            SigningApi::sign_and_build_shield(100, 1, [0u8; 32], vec![1u8; 8], 0, valid_key());

        assert!(out.is_err());
    }

    #[test]
    fn test_sign_and_build_with_invalid_private_key() {
        let out = SigningApi::sign_and_build_shield(100, 1, [16u8; 32], vec![17u8; 8], 0, "abcd");
        assert!(out.is_err());
    }
}
