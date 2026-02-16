//! Request disclosure transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;

/// Builder for Request Disclosure transactions
pub struct RequestDisclosureBuilder;

impl RequestDisclosureBuilder {
    /// Builds an unsigned request disclosure transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: RequestDisclosureParams,
        nonce: u32,
    ) -> UnsignedTransaction {
        let call_data = encoder.encode_request_disclosure_call_data(&params);

        UnsignedTransaction::new(call_data, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Address;
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_request_disclosure_build_unsigned() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = RequestDisclosureParams {
            target: Address::from_slice_unchecked(&[15u8; 20]),
            reason: b"Suspicious pattern".to_vec(),
            evidence: Some(vec![42u8; 12]),
        };

        let tx = RequestDisclosureBuilder::build_unsigned(&encoder, params, 41);

        assert_eq!(tx.nonce(), 41);
        assert_eq!(tx.call_data()[0], 50);
        assert_eq!(tx.call_data()[1], 5);
        assert!(tx.call_data().len() > 2);
    }

    #[test]
    fn test_request_disclosure_evidence_option_changes_encoding() {
        let encoder = SubstrateTransactionEncoder::new();
        let target = Address::from_slice_unchecked(&[16u8; 20]);
        let reason = b"Regulatory request".to_vec();

        let with_evidence = RequestDisclosureBuilder::build_unsigned(
            &encoder,
            RequestDisclosureParams {
                target,
                reason: reason.clone(),
                evidence: Some(vec![1u8; 8]),
            },
            0,
        );

        let without_evidence = RequestDisclosureBuilder::build_unsigned(
            &encoder,
            RequestDisclosureParams {
                target,
                reason,
                evidence: None,
            },
            0,
        );

        assert_ne!(with_evidence.call_data(), without_evidence.call_data());
    }
}
