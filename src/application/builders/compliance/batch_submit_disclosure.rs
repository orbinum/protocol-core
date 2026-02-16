//! Batch submit disclosure transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;

/// Builder for Batch Submit Disclosure Proofs transactions
pub struct BatchSubmitDisclosureBuilder;

impl BatchSubmitDisclosureBuilder {
    /// Builds an unsigned batch submit disclosure transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: BatchSubmitDisclosureParams,
        nonce: u32,
    ) -> UnsignedTransaction {
        let call_data = encoder.encode_batch_submit_disclosure_call_data(&params);

        UnsignedTransaction::new(call_data, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Commitment;
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_batch_submit_disclosure_build_unsigned() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = BatchSubmitDisclosureParams {
            submissions: vec![
                DisclosureSubmission {
                    commitment: Commitment::from_bytes_unchecked([11u8; 32]),
                    proof: vec![1u8; 64],
                    public_signals: vec![2u8; 32],
                    disclosed_data: vec![3u8; 16],
                },
                DisclosureSubmission {
                    commitment: Commitment::from_bytes_unchecked([12u8; 32]),
                    proof: vec![4u8; 64],
                    public_signals: vec![5u8; 32],
                    disclosed_data: vec![6u8; 16],
                },
            ],
        };

        let tx = BatchSubmitDisclosureBuilder::build_unsigned(&encoder, params, 31);

        assert_eq!(tx.nonce(), 31);
        assert_eq!(tx.call_data()[0], 50);
        assert_eq!(tx.call_data()[1], 13);
        assert!(tx.call_data().len() > 2);
    }

    #[test]
    fn test_batch_submit_disclosure_count_changes_encoding() {
        let encoder = SubstrateTransactionEncoder::new();

        let single = BatchSubmitDisclosureBuilder::build_unsigned(
            &encoder,
            BatchSubmitDisclosureParams {
                submissions: vec![DisclosureSubmission {
                    commitment: Commitment::from_bytes_unchecked([13u8; 32]),
                    proof: vec![7u8; 64],
                    public_signals: vec![8u8; 32],
                    disclosed_data: vec![9u8; 16],
                }],
            },
            0,
        );

        let multiple = BatchSubmitDisclosureBuilder::build_unsigned(
            &encoder,
            BatchSubmitDisclosureParams {
                submissions: vec![
                    DisclosureSubmission {
                        commitment: Commitment::from_bytes_unchecked([13u8; 32]),
                        proof: vec![7u8; 64],
                        public_signals: vec![8u8; 32],
                        disclosed_data: vec![9u8; 16],
                    },
                    DisclosureSubmission {
                        commitment: Commitment::from_bytes_unchecked([14u8; 32]),
                        proof: vec![10u8; 64],
                        public_signals: vec![11u8; 32],
                        disclosed_data: vec![12u8; 16],
                    },
                ],
            },
            0,
        );

        assert_ne!(single.call_data(), multiple.call_data());
    }
}
