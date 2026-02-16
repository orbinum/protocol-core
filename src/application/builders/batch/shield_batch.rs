//! Shield batch transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;

/// Builder for Shield Batch transactions
pub struct ShieldBatchBuilder;

impl ShieldBatchBuilder {
    /// Builds an unsigned shield batch transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: ShieldBatchParams,
        nonce: u32,
    ) -> UnsignedTransaction {
        let call_data = encoder.encode_shield_batch_call_data(&params);

        UnsignedTransaction::new(call_data, nonce)
    }
}

// Tests would need updates to mock encoder or use default setup.
// Skipping tests update in this file for now to focus on compilation boundaries,
// but assuming existing tests might fail if they call build_unsigned directly.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::*;

    // We need a mock encoder for testing, or we skip test compilation if we don't mock.
    // Ideally we should update the test.
    // But for this step focusing on compilation of `lib`.
    // Cargo check includes tests by default. So I must fix tests too.

    struct MockEncoder;
    impl TransactionEncoderPort for MockEncoder {
        fn encode_shield_call_data(&self, _: &ShieldParams, _: &[u8]) -> Vec<u8> {
            vec![]
        }
        fn encode_shield_batch_call_data(&self, _: &ShieldBatchParams) -> Vec<u8> {
            // Return dummy valid call data: [pallet, call]
            vec![50, 12]
        }
        fn encode_unshield_call_data(&self, _: &UnshieldParams, _: AssetId) -> Vec<u8> {
            vec![]
        }
        fn encode_transfer_call_data(&self, _: &TransferParams) -> Vec<u8> {
            vec![]
        }
        fn encode_set_audit_policy_call_data(&self, _: &SetAuditPolicyParams) -> Vec<u8> {
            vec![]
        }
        fn encode_request_disclosure_call_data(&self, _: &RequestDisclosureParams) -> Vec<u8> {
            vec![]
        }
        fn encode_approve_disclosure_call_data(&self, _: &ApproveDisclosureParams) -> Vec<u8> {
            vec![]
        }
        fn encode_reject_disclosure_call_data(&self, _: &RejectDisclosureParams) -> Vec<u8> {
            vec![]
        }
        fn encode_submit_disclosure_call_data(&self, _: &SubmitDisclosureParams) -> Vec<u8> {
            vec![]
        }
        fn encode_batch_submit_disclosure_call_data(
            &self,
            _: &BatchSubmitDisclosureParams,
        ) -> Vec<u8> {
            vec![]
        }
    }

    #[test]
    fn test_shield_batch_build() {
        let operations = vec![ShieldOperation {
            asset_id: AssetId::new(1),
            amount: 1000,
            commitment: Commitment::from_bytes_unchecked([1u8; 32]),
            encrypted_memo: vec![0u8; 104],
        }];
        let params = ShieldBatchParams { operations };
        let encoder = MockEncoder;
        let tx = ShieldBatchBuilder::build_unsigned(&encoder, params, 0);

        assert_eq!(tx.call_data()[0], 50);
        assert_eq!(tx.call_data()[1], 12);
    }
}
