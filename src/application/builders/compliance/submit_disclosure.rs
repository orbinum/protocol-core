//! Submit disclosure transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;

/// Builder for Submit Disclosure transactions
pub struct SubmitDisclosureBuilder;

impl SubmitDisclosureBuilder {
    /// Builds an unsigned submit disclosure transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: SubmitDisclosureParams,
        nonce: u32,
    ) -> UnsignedTransaction {
        let call_data = encoder.encode_submit_disclosure_call_data(&params);

        UnsignedTransaction::new(call_data, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{Address, Commitment};
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_submit_disclosure_build_unsigned() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = SubmitDisclosureParams {
            commitment: Commitment::from_bytes_unchecked([23u8; 32]),
            proof_bytes: vec![1u8; 96],
            public_signals: vec![2u8; 48],
            partial_data: vec![3u8; 24],
            auditor: Some(Address::from_slice_unchecked(&[24u8; 32])),
        };

        let tx = SubmitDisclosureBuilder::build_unsigned(&encoder, params, 61);

        assert_eq!(tx.nonce(), 61);
        assert_eq!(tx.call_data()[0], 50);
        assert_eq!(tx.call_data()[1], 8);
        assert!(tx.call_data().len() > 2);
    }

    #[test]
    fn test_submit_disclosure_auditor_option_changes_encoding() {
        let encoder = SubstrateTransactionEncoder::new();
        let commitment = Commitment::from_bytes_unchecked([25u8; 32]);

        let with_auditor = SubmitDisclosureBuilder::build_unsigned(
            &encoder,
            SubmitDisclosureParams {
                commitment,
                proof_bytes: vec![4u8; 64],
                public_signals: vec![5u8; 32],
                partial_data: vec![6u8; 16],
                auditor: Some(Address::from_slice_unchecked(&[26u8; 32])),
            },
            0,
        );

        let without_auditor = SubmitDisclosureBuilder::build_unsigned(
            &encoder,
            SubmitDisclosureParams {
                commitment,
                proof_bytes: vec![4u8; 64],
                public_signals: vec![5u8; 32],
                partial_data: vec![6u8; 16],
                auditor: None,
            },
            0,
        );

        assert_ne!(with_auditor.call_data(), without_auditor.call_data());
    }
}
