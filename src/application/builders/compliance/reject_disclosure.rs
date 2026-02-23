//! Reject disclosure transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;

/// Builder for Reject Disclosure transactions
pub struct RejectDisclosureBuilder;

impl RejectDisclosureBuilder {
    /// Builds an unsigned reject disclosure transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: RejectDisclosureParams,
        nonce: u32,
    ) -> UnsignedTransaction {
        let call_data = encoder.encode_reject_disclosure_call_data(&params);

        UnsignedTransaction::new(call_data, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Address;
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_reject_disclosure_build_unsigned() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = RejectDisclosureParams {
            auditor: Address::from_slice_unchecked(&[21u8; 32]),
            reason: b"Insufficient evidence".to_vec(),
        };

        let tx = RejectDisclosureBuilder::build_unsigned(&encoder, params, 51);

        assert_eq!(tx.nonce(), 51);
        assert_eq!(tx.call_data()[0], 50);
        assert_eq!(tx.call_data()[1], 7);
        assert!(tx.call_data().len() > 2);
    }

    #[test]
    fn test_reject_disclosure_reason_changes_encoding() {
        let encoder = SubstrateTransactionEncoder::new();
        let auditor = Address::from_slice_unchecked(&[22u8; 32]);

        let tx_a = RejectDisclosureBuilder::build_unsigned(
            &encoder,
            RejectDisclosureParams {
                auditor,
                reason: b"reason-a".to_vec(),
            },
            0,
        );

        let tx_b = RejectDisclosureBuilder::build_unsigned(
            &encoder,
            RejectDisclosureParams {
                auditor,
                reason: b"reason-b".to_vec(),
            },
            0,
        );

        assert_ne!(tx_a.call_data(), tx_b.call_data());
    }
}
