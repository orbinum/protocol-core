//! Core Transaction API
//!
//! Build unsigned transactions for Shield, Unshield, and Transfer operations.

use crate::application::builders::*;
use crate::application::params::*;
use crate::domain::types::*;
use crate::infrastructure::serializers::SubstrateTransactionEncoder;

extern crate alloc;
use alloc::vec::Vec;

/// API for building core transactions without signatures.
pub struct TransactionApi;

impl TransactionApi {
    /// Builds unsigned Shield transaction.
    pub fn build_shield_unsigned(
        amount: u128,
        asset_id: u32,
        commitment: [u8; 32],
        encrypted_memo: Vec<u8>,
        nonce: u32,
    ) -> Vec<u8> {
        let params = ShieldParams {
            amount,
            asset_id: AssetId::new(asset_id),
            commitment: Commitment::from_bytes(commitment)
                .expect("Invalid commitment: cannot be all zeros"),
        };
        let encoder = SubstrateTransactionEncoder::new();
        let tx = ShieldBuilder::build_unsigned(&encoder, params, encrypted_memo, nonce);
        tx.call_data().to_vec()
    }

    /// Builds unsigned Unshield transaction.
    pub fn build_unshield_unsigned(
        nullifier: [u8; 32],
        amount: u128,
        asset_id: u32,
        recipient: [u8; 20],
        root: [u8; 32],
        proof: Vec<u8>,
        nonce: u32,
    ) -> Vec<u8> {
        let params = UnshieldParams {
            nullifier: Nullifier::from_bytes(nullifier)
                .expect("Invalid nullifier: cannot be all zeros"),
            amount,
            recipient: Address::from_slice(&recipient)
                .expect("Invalid recipient address: must be 20 bytes"),
            root: Hash::from_slice(&root),
            proof,
        };

        let encoder = SubstrateTransactionEncoder::new();
        let tx = UnshieldBuilder::build_unsigned(&encoder, params, AssetId::new(asset_id), nonce);
        tx.call_data().to_vec()
    }

    /// Builds unsigned private transfer transaction.
    pub fn build_transfer_unsigned(
        input_nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        root: [u8; 32],
        proof: Vec<u8>,
        encrypted_memos: [Vec<u8>; 2],
        nonce: u32,
    ) -> Vec<u8> {
        let params = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes(input_nullifiers[0])
                    .expect("Invalid nullifier[0]: cannot be all zeros"),
                Nullifier::from_bytes(input_nullifiers[1])
                    .expect("Invalid nullifier[1]: cannot be all zeros"),
            ],
            output_commitments: [
                Commitment::from_bytes(output_commitments[0])
                    .expect("Invalid commitment[0]: cannot be all zeros"),
                Commitment::from_bytes(output_commitments[1])
                    .expect("Invalid commitment[1]: cannot be all zeros"),
            ],
            root: Hash::from_slice(&root),
            proof,
            encrypted_memos: encrypted_memos.clone(),
        };

        let encoder = SubstrateTransactionEncoder::new();
        let tx = TransferBuilder::build_unsigned(&encoder, params, nonce);
        tx.call_data().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presentation::config::{shield_calls, PALLET_INDEX};

    #[test]
    fn test_build_shield_unsigned() {
        let call_data = TransactionApi::build_shield_unsigned(100, 1, [1u8; 32], vec![2u8; 16], 0);

        assert_eq!(call_data[0], PALLET_INDEX);
        assert_eq!(call_data[1], shield_calls::SHIELD);
    }

    #[test]
    fn test_build_unshield_unsigned() {
        let call_data = TransactionApi::build_unshield_unsigned(
            [3u8; 32],
            50,
            1,
            [4u8; 20],
            [5u8; 32],
            vec![6u8; 64],
            1,
        );

        assert_eq!(call_data[0], PALLET_INDEX);
        assert_eq!(call_data[1], shield_calls::UNSHIELD);
    }

    #[test]
    fn test_build_transfer_unsigned() {
        let call_data = TransactionApi::build_transfer_unsigned(
            [[7u8; 32], [8u8; 32]],
            [[9u8; 32], [10u8; 32]],
            [11u8; 32],
            vec![12u8; 64],
            [vec![13u8; 8], vec![14u8; 8]],
            2,
        );

        assert_eq!(call_data[0], PALLET_INDEX);
        assert_eq!(call_data[1], shield_calls::TRANSFER);
    }

    #[test]
    #[should_panic(expected = "Invalid commitment")]
    fn test_build_shield_unsigned_panics_with_zero_commitment() {
        let _ = TransactionApi::build_shield_unsigned(100, 1, [0u8; 32], vec![1u8; 8], 0);
    }
}
