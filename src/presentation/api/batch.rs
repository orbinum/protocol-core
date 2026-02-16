//! Batch Transaction API
//!
//! Build unsigned batch transactions.

use crate::application::builders::*;
use crate::application::params::*;
use crate::infrastructure::serializers::SubstrateTransactionEncoder;
use crate::presentation::api::core::TransactionApi;

extern crate alloc;
use alloc::vec::Vec;

impl TransactionApi {
    /// Builds unsigned Shield Batch transaction.
    pub fn build_shield_batch_unsigned(operations: Vec<ShieldOperation>, nonce: u32) -> Vec<u8> {
        let params = ShieldBatchParams { operations };
        let encoder = SubstrateTransactionEncoder::new();
        let tx = ShieldBatchBuilder::build_unsigned(&encoder, params, nonce);
        tx.call_data().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{AssetId, Commitment};
    use crate::presentation::config::{shield_calls, PALLET_INDEX};

    #[test]
    fn test_build_shield_batch_unsigned() {
        let operations = vec![
            ShieldOperation {
                asset_id: AssetId::new(1),
                amount: 10,
                commitment: Commitment::from_bytes_unchecked([1u8; 32]),
                encrypted_memo: vec![2u8; 8],
            },
            ShieldOperation {
                asset_id: AssetId::new(2),
                amount: 20,
                commitment: Commitment::from_bytes_unchecked([3u8; 32]),
                encrypted_memo: vec![4u8; 8],
            },
        ];

        let call_data = TransactionApi::build_shield_batch_unsigned(operations, 0);
        assert_eq!(call_data[0], PALLET_INDEX);
        assert_eq!(call_data[1], shield_calls::SHIELD_BATCH);
    }
}
