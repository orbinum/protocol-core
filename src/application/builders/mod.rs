//! Transaction Builders
//!
//! Modular transaction builders organized by category:
//! - Core: shield, unshield, transfer
//! - Batch: shield_batch
//! - Compliance: audit policies and disclosures

// Core transaction builders
pub mod core;
pub use core::{ShieldBuilder, TransferBuilder, UnshieldBuilder};

// Batch operation builders
pub mod batch;
pub use batch::ShieldBatchBuilder;

// Compliance and disclosure builders
pub mod compliance;
pub use compliance::{
    ApproveDisclosureBuilder, BatchSubmitDisclosureBuilder, RejectDisclosureBuilder,
    RequestDisclosureBuilder, SetAuditPolicyBuilder, SubmitDisclosureBuilder,
};

// Extrinsic builder
pub mod extrinsic;
pub use extrinsic::ExtrinsicBuilder;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::application::params::*;
    use crate::domain::types::*;
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    // Integration tests
    #[test]
    fn test_full_shield_workflow() {
        let encoder = SubstrateTransactionEncoder::new();
        // Create unsigned transaction
        let params = ShieldParams {
            amount: 1000u128,
            asset_id: AssetId::new(1),
            commitment: Commitment::from_bytes_unchecked([1u8; 32]),
        };
        let unsigned_tx =
            ShieldBuilder::build_unsigned(&encoder, params, vec![0u8; 32], 5).with_tip(100);

        // Sign it
        let signature = vec![12u8; 65];
        let address = Address::from_slice_unchecked(&[13u8; 20]);
        let signed_tx = ExtrinsicBuilder::build_signed(unsigned_tx, &signature, address);

        // Serialize it
        let serialized = ExtrinsicBuilder::serialize(&signed_tx);

        assert!(!serialized.is_empty());
        assert_eq!(signed_tx.nonce(), 5);
    }

    #[test]
    fn test_full_unshield_workflow() {
        // Create unsigned transaction
        let params = UnshieldParams {
            nullifier: Nullifier::from_bytes_unchecked([2u8; 32]),
            amount: 500u128,
            recipient: Address::from_slice_unchecked(&[3u8; 20]),
            root: Hash::from_slice(&[4u8; 32]),
            proof: vec![5u8; 128],
        };
        let encoder = SubstrateTransactionEncoder::new();
        let unsigned_tx =
            UnshieldBuilder::build_unsigned(&encoder, params, AssetId::new(1), 10).with_tip(200);

        // Sign it
        let signature = vec![14u8; 65];
        let address = Address::from_slice_unchecked(&[15u8; 20]);
        let signed_tx = ExtrinsicBuilder::build_signed(unsigned_tx, &signature, address);

        // Serialize it
        let serialized = ExtrinsicBuilder::serialize(&signed_tx);

        assert!(!serialized.is_empty());
        assert_eq!(signed_tx.nonce(), 10);
    }

    #[test]
    fn test_full_transfer_workflow() {
        // Create unsigned transaction
        let params = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([6u8; 32]),
                Nullifier::from_bytes_unchecked([7u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([8u8; 32]),
                Commitment::from_bytes_unchecked([9u8; 32]),
            ],
            root: Hash::from_slice(&[10u8; 32]),
            proof: vec![11u8; 128],
            encrypted_memos: [vec![0u8; 32], vec![0u8; 32]],
        };
        let encoder = SubstrateTransactionEncoder::new();
        let unsigned_tx = TransferBuilder::build_unsigned(&encoder, params, 15).with_tip(300);

        // Sign it
        let signature = vec![16u8; 65];
        let address = Address::from_slice_unchecked(&[17u8; 20]);
        let signed_tx = ExtrinsicBuilder::build_signed(unsigned_tx, &signature, address);

        // Serialize it
        let serialized = ExtrinsicBuilder::serialize(&signed_tx);

        assert!(!serialized.is_empty());
        assert_eq!(signed_tx.nonce(), 15);
    }

    #[test]
    fn test_extrinsic_build_signed_with_different_addresses() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = ShieldParams {
            amount: 1000u128,
            asset_id: AssetId::new(1),
            commitment: Commitment::from_bytes_unchecked([1u8; 32]),
        };
        let unsigned_tx = ShieldBuilder::build_unsigned(&encoder, params, vec![0u8; 32], 0);
        let signature = vec![12u8; 65];

        let address1 = Address::from_slice_unchecked(&[1u8; 20]);
        let address2 = Address::from_slice_unchecked(&[2u8; 20]);

        let signed_tx1 = ExtrinsicBuilder::build_signed(unsigned_tx.clone(), &signature, address1);
        let signed_tx2 = ExtrinsicBuilder::build_signed(unsigned_tx, &signature, address2);

        assert_eq!(signed_tx1.address(), &address1);
        assert_eq!(signed_tx2.address(), &address2);
        assert_ne!(signed_tx1.address(), signed_tx2.address());
    }

    #[test]
    fn test_extrinsic_serialize_consistency() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = ShieldParams {
            amount: 1000u128,
            asset_id: AssetId::new(1),
            commitment: Commitment::from_bytes_unchecked([1u8; 32]),
        };
        let unsigned_tx = ShieldBuilder::build_unsigned(&encoder, params, vec![0u8; 32], 0);
        let signature = vec![12u8; 65];
        let address = Address::from_slice_unchecked(&[13u8; 20]);

        let signed_tx = ExtrinsicBuilder::build_signed(unsigned_tx, &signature, address);

        // Serialize multiple times should produce same result
        let serialized1 = ExtrinsicBuilder::serialize(&signed_tx);
        let serialized2 = ExtrinsicBuilder::serialize(&signed_tx);

        assert_eq!(serialized1, serialized2);
    }
}
