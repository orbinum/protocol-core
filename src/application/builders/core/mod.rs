// Core builders module
//! Core wallet operation builders (shield, unshield, transfer)

pub mod shield;
pub mod transfer;
pub mod unshield;

pub use shield::ShieldBuilder;
pub use transfer::TransferBuilder;
pub use unshield::UnshieldBuilder;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::params::{ShieldParams, TransferParams, UnshieldParams};
    use crate::domain::types::{Address, AssetId, Commitment, Hash, Nullifier};
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_core_reexports_builders_end_to_end() {
        let encoder = SubstrateTransactionEncoder::new();

        let shield = ShieldBuilder::build_unsigned(
            &encoder,
            ShieldParams {
                asset_id: AssetId::ORB,
                amount: 100,
                commitment: Commitment::from_bytes_unchecked([1u8; 32]),
            },
            vec![2u8; 8],
            1,
        );

        let transfer = TransferBuilder::build_unsigned(
            &encoder,
            TransferParams {
                input_nullifiers: [
                    Nullifier::from_bytes_unchecked([3u8; 32]),
                    Nullifier::from_bytes_unchecked([4u8; 32]),
                ],
                output_commitments: [
                    Commitment::from_bytes_unchecked([5u8; 32]),
                    Commitment::from_bytes_unchecked([6u8; 32]),
                ],
                root: Hash::from_slice(&[7u8; 32]),
                proof: vec![8u8; 64],
                encrypted_memos: [vec![9u8; 8], vec![10u8; 8]],
            },
            2,
        );

        let unshield = UnshieldBuilder::build_unsigned(
            &encoder,
            UnshieldParams {
                nullifier: Nullifier::from_bytes_unchecked([11u8; 32]),
                amount: 50,
                recipient: Address::from_slice_unchecked(&[12u8; 20]),
                root: Hash::from_slice(&[13u8; 32]),
                proof: vec![14u8; 64],
            },
            AssetId::ORB,
            3,
        );

        assert_eq!(shield.call_data()[1], 0);
        assert_eq!(transfer.call_data()[1], 1);
        assert_eq!(unshield.call_data()[1], 2);
    }
}
