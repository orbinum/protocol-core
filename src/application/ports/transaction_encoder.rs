//! Transaction Encoder Port
//!
//! High-level port for encoding transactions. Abstracts call data encoding
//! details from builders, maintaining Clean Architecture boundaries.

use crate::application::params::*;
use crate::domain::types::AssetId;
extern crate alloc;
use alloc::vec::Vec;

/// High-level transaction encoder for application layer.
///
/// Builders depend on this port; infrastructure provides the implementation.
pub trait TransactionEncoderPort {
    /// Encode Shield call data
    fn encode_shield_call_data(&self, params: &ShieldParams, encrypted_memo: &[u8]) -> Vec<u8>;

    /// Encode Shield Batch call data
    fn encode_shield_batch_call_data(&self, params: &ShieldBatchParams) -> Vec<u8>;

    /// Encode Unshield call data
    fn encode_unshield_call_data(&self, params: &UnshieldParams, asset_id: AssetId) -> Vec<u8>;

    /// Encode Private Transfer call data
    fn encode_transfer_call_data(&self, params: &TransferParams) -> Vec<u8>;

    // Compliance & Disclosure

    /// Encode Set Audit Policy call data
    fn encode_set_audit_policy_call_data(&self, params: &SetAuditPolicyParams) -> Vec<u8>;

    /// Encode Request Disclosure call data
    fn encode_request_disclosure_call_data(&self, params: &RequestDisclosureParams) -> Vec<u8>;

    /// Encode Approve Disclosure call data
    fn encode_approve_disclosure_call_data(&self, params: &ApproveDisclosureParams) -> Vec<u8>;

    /// Encode Reject Disclosure call data
    fn encode_reject_disclosure_call_data(&self, params: &RejectDisclosureParams) -> Vec<u8>;

    /// Encode Submit Disclosure call data
    fn encode_submit_disclosure_call_data(&self, params: &SubmitDisclosureParams) -> Vec<u8>;

    /// Encode Batch Submit Disclosure call data
    fn encode_batch_submit_disclosure_call_data(
        &self,
        params: &BatchSubmitDisclosureParams,
    ) -> Vec<u8>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::params::{
        ApproveDisclosureParams, AuditorInfo, BatchSubmitDisclosureParams, DisclosureConditionType,
        DisclosureSubmission, RejectDisclosureParams, RequestDisclosureParams,
        SetAuditPolicyParams, ShieldBatchParams, ShieldOperation, ShieldParams,
        SubmitDisclosureParams, TransferParams, UnshieldParams,
    };
    use crate::domain::types::{Address, AssetId, Commitment, Hash, Nullifier};

    struct MockEncoder;

    impl TransactionEncoderPort for MockEncoder {
        fn encode_shield_call_data(
            &self,
            _params: &ShieldParams,
            _encrypted_memo: &[u8],
        ) -> Vec<u8> {
            vec![1]
        }

        fn encode_shield_batch_call_data(&self, _params: &ShieldBatchParams) -> Vec<u8> {
            vec![2]
        }

        fn encode_unshield_call_data(
            &self,
            _params: &UnshieldParams,
            _asset_id: AssetId,
        ) -> Vec<u8> {
            vec![3]
        }

        fn encode_transfer_call_data(&self, _params: &TransferParams) -> Vec<u8> {
            vec![4]
        }

        fn encode_set_audit_policy_call_data(&self, _params: &SetAuditPolicyParams) -> Vec<u8> {
            vec![5]
        }

        fn encode_request_disclosure_call_data(
            &self,
            _params: &RequestDisclosureParams,
        ) -> Vec<u8> {
            vec![6]
        }

        fn encode_approve_disclosure_call_data(
            &self,
            _params: &ApproveDisclosureParams,
        ) -> Vec<u8> {
            vec![7]
        }

        fn encode_reject_disclosure_call_data(&self, _params: &RejectDisclosureParams) -> Vec<u8> {
            vec![8]
        }

        fn encode_submit_disclosure_call_data(&self, _params: &SubmitDisclosureParams) -> Vec<u8> {
            vec![9]
        }

        fn encode_batch_submit_disclosure_call_data(
            &self,
            _params: &BatchSubmitDisclosureParams,
        ) -> Vec<u8> {
            vec![10]
        }
    }

    #[test]
    fn test_transaction_encoder_port_contract_all_methods() {
        let encoder = MockEncoder;

        let shield = ShieldParams {
            amount: 100,
            asset_id: AssetId::ORB,
            commitment: Commitment::from_bytes_unchecked([1u8; 32]),
        };
        assert_eq!(encoder.encode_shield_call_data(&shield, &[0u8; 4]), vec![1]);

        let shield_batch = ShieldBatchParams {
            operations: vec![ShieldOperation {
                asset_id: AssetId::new(1),
                amount: 50,
                commitment: Commitment::from_bytes_unchecked([2u8; 32]),
                encrypted_memo: vec![3u8; 8],
            }],
        };
        assert_eq!(
            encoder.encode_shield_batch_call_data(&shield_batch),
            vec![2]
        );

        let unshield = UnshieldParams {
            nullifier: Nullifier::from_bytes_unchecked([4u8; 32]),
            amount: 20,
            recipient: Address::from_slice_unchecked(&[5u8; 20]),
            root: Hash::from_slice(&[6u8; 32]),
            proof: vec![7u8; 16],
        };
        assert_eq!(
            encoder.encode_unshield_call_data(&unshield, AssetId::new(2)),
            vec![3]
        );

        let transfer = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([8u8; 32]),
                Nullifier::from_bytes_unchecked([9u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([10u8; 32]),
                Commitment::from_bytes_unchecked([11u8; 32]),
            ],
            root: Hash::from_slice(&[12u8; 32]),
            proof: vec![13u8; 64],
            encrypted_memos: [vec![14u8; 8], vec![15u8; 8]],
        };
        assert_eq!(encoder.encode_transfer_call_data(&transfer), vec![4]);

        let set_audit_policy = SetAuditPolicyParams {
            auditors: vec![AuditorInfo {
                account: Address::from_slice_unchecked(&[16u8; 20]),
                public_key: Some([17u8; 32]),
                authorized_from: 1,
            }],
            conditions: vec![DisclosureConditionType::ManualApproval],
            max_frequency: Some(10),
        };
        assert_eq!(
            encoder.encode_set_audit_policy_call_data(&set_audit_policy),
            vec![5]
        );

        let request_disclosure = RequestDisclosureParams {
            target: Address::from_slice_unchecked(&[18u8; 20]),
            reason: b"reason".to_vec(),
            evidence: Some(vec![19u8; 4]),
        };
        assert_eq!(
            encoder.encode_request_disclosure_call_data(&request_disclosure),
            vec![6]
        );

        let approve_disclosure = ApproveDisclosureParams {
            auditor: Address::from_slice_unchecked(&[20u8; 20]),
            commitment: Commitment::from_bytes_unchecked([21u8; 32]),
            zk_proof: vec![22u8; 32],
            disclosed_data: vec![23u8; 8],
        };
        assert_eq!(
            encoder.encode_approve_disclosure_call_data(&approve_disclosure),
            vec![7]
        );

        let reject_disclosure = RejectDisclosureParams {
            auditor: Address::from_slice_unchecked(&[24u8; 20]),
            reason: b"reject".to_vec(),
        };
        assert_eq!(
            encoder.encode_reject_disclosure_call_data(&reject_disclosure),
            vec![8]
        );

        let submit_disclosure = SubmitDisclosureParams {
            commitment: Commitment::from_bytes_unchecked([25u8; 32]),
            proof_bytes: vec![26u8; 32],
            public_signals: vec![27u8; 32],
            partial_data: vec![28u8; 8],
            auditor: None,
        };
        assert_eq!(
            encoder.encode_submit_disclosure_call_data(&submit_disclosure),
            vec![9]
        );

        let batch_submit_disclosure = BatchSubmitDisclosureParams {
            submissions: vec![DisclosureSubmission {
                commitment: Commitment::from_bytes_unchecked([29u8; 32]),
                proof: vec![30u8; 32],
                public_signals: vec![31u8; 16],
                disclosed_data: vec![32u8; 8],
            }],
        };
        assert_eq!(
            encoder.encode_batch_submit_disclosure_call_data(&batch_submit_disclosure),
            vec![10]
        );
    }
}
