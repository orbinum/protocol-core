//! Approve disclosure transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;

/// Builder for Approve Disclosure transactions
pub struct ApproveDisclosureBuilder;

impl ApproveDisclosureBuilder {
    /// Builds an unsigned approve disclosure transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: ApproveDisclosureParams,
        nonce: u32,
    ) -> UnsignedTransaction {
        let call_data = encoder.encode_approve_disclosure_call_data(&params);

        UnsignedTransaction::new(call_data, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{Address, Commitment};
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_approve_disclosure_build_unsigned() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = ApproveDisclosureParams {
            auditor: Address::from_slice_unchecked(&[1u8; 20]),
            commitment: Commitment::from_bytes_unchecked([2u8; 32]),
            zk_proof: vec![10u8; 128],
            disclosed_data: vec![20u8; 16],
        };

        let tx = ApproveDisclosureBuilder::build_unsigned(&encoder, params, 11);

        assert_eq!(tx.nonce(), 11);
        assert_eq!(tx.call_data()[0], 50);
        assert_eq!(tx.call_data()[1], 6);
        assert!(tx.call_data().len() > 2);
    }

    #[test]
    fn test_approve_disclosure_payload_changes_encoding() {
        let encoder = SubstrateTransactionEncoder::new();
        let base_commitment = Commitment::from_bytes_unchecked([3u8; 32]);

        let tx_a = ApproveDisclosureBuilder::build_unsigned(
            &encoder,
            ApproveDisclosureParams {
                auditor: Address::from_slice_unchecked(&[4u8; 20]),
                commitment: base_commitment,
                zk_proof: vec![1u8; 64],
                disclosed_data: vec![2u8; 8],
            },
            0,
        );

        let tx_b = ApproveDisclosureBuilder::build_unsigned(
            &encoder,
            ApproveDisclosureParams {
                auditor: Address::from_slice_unchecked(&[4u8; 20]),
                commitment: base_commitment,
                zk_proof: vec![9u8; 64],
                disclosed_data: vec![8u8; 8],
            },
            0,
        );

        assert_ne!(tx_a.call_data(), tx_b.call_data());
    }
}
