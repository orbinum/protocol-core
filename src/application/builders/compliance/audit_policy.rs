//! Audit policy transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;

/// Builder for Set Audit Policy transactions
pub struct SetAuditPolicyBuilder;

impl SetAuditPolicyBuilder {
    /// Builds an unsigned set audit policy transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: SetAuditPolicyParams,
        nonce: u32,
    ) -> UnsignedTransaction {
        let call_data = encoder.encode_set_audit_policy_call_data(&params);

        UnsignedTransaction::new(call_data, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Address;
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_set_audit_policy_build_unsigned() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = SetAuditPolicyParams {
            auditors: vec![AuditorInfo {
                account: Address::from_slice_unchecked(&[5u8; 32]),
                public_key: Some([6u8; 32]),
                authorized_from: 100,
            }],
            conditions: vec![
                DisclosureConditionType::AmountAbove(1_000),
                DisclosureConditionType::ManualApproval,
            ],
            max_frequency: Some(24),
        };

        let tx = SetAuditPolicyBuilder::build_unsigned(&encoder, params, 21);

        assert_eq!(tx.nonce(), 21);
        assert_eq!(tx.call_data()[0], 50);
        assert_eq!(tx.call_data()[1], 4);
        assert!(tx.call_data().len() > 2);
    }

    #[test]
    fn test_set_audit_policy_option_encoding_changes() {
        let encoder = SubstrateTransactionEncoder::new();
        let auditors = vec![AuditorInfo {
            account: Address::from_slice_unchecked(&[7u8; 32]),
            public_key: None,
            authorized_from: 0,
        }];
        let conditions = vec![DisclosureConditionType::TimeElapsed(3600)];

        let tx_some = SetAuditPolicyBuilder::build_unsigned(
            &encoder,
            SetAuditPolicyParams {
                auditors: auditors.clone(),
                conditions: conditions.clone(),
                max_frequency: Some(1),
            },
            0,
        );

        let tx_none = SetAuditPolicyBuilder::build_unsigned(
            &encoder,
            SetAuditPolicyParams {
                auditors,
                conditions,
                max_frequency: None,
            },
            0,
        );

        assert_ne!(tx_some.call_data(), tx_none.call_data());
    }
}
