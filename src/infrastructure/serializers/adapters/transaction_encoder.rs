//! TransactionEncoderPort adapter for Substrate
use crate::application::params::{
    ApproveDisclosureParams, BatchSubmitDisclosureParams, RejectDisclosureParams,
    RequestDisclosureParams, SetAuditPolicyParams, ShieldBatchParams, ShieldParams,
    SubmitDisclosureParams, TransferParams, UnshieldParams,
};
use crate::application::ports::TransactionEncoderPort;
use crate::domain::types::AssetId;
use crate::infrastructure::codec::encoder::ScaleEncoder;
use crate::infrastructure::serializers::core::call_data_builder::CallDataBuilder;
use alloc::vec::Vec;

/// Substrate transaction encoder using SCALE encoding.
pub struct SubstrateTransactionEncoder {
    builder: CallDataBuilder<ScaleEncoder>,
}

impl SubstrateTransactionEncoder {
    pub fn new() -> Self {
        Self {
            builder: CallDataBuilder::new(ScaleEncoder::new()),
        }
    }
}

impl Default for SubstrateTransactionEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionEncoderPort for SubstrateTransactionEncoder {
    fn encode_shield_call_data(&self, params: &ShieldParams, encrypted_memo: &[u8]) -> Vec<u8> {
        self.builder.build_shield_call_data(
            params.asset_id.as_u32(),
            params.amount,
            &params.commitment,
            encrypted_memo,
        )
    }

    fn encode_shield_batch_call_data(&self, params: &ShieldBatchParams) -> Vec<u8> {
        self.builder
            .build_shield_batch_call_data(&params.operations)
    }

    fn encode_unshield_call_data(&self, params: &UnshieldParams, asset_id: AssetId) -> Vec<u8> {
        self.builder.build_unshield_call_data(
            &params.nullifier,
            params.amount,
            &params.recipient,
            &params.root,
            &params.proof,
            asset_id.as_u32(),
        )
    }

    fn encode_transfer_call_data(&self, params: &TransferParams) -> Vec<u8> {
        self.builder.build_transfer_call_data(
            &params.input_nullifiers,
            &params.output_commitments,
            &params.root,
            &params.proof,
            &params.encrypted_memos,
        )
    }

    fn encode_set_audit_policy_call_data(&self, params: &SetAuditPolicyParams) -> Vec<u8> {
        self.builder.build_set_audit_policy_call_data(
            &params.auditors,
            &params.conditions,
            params.max_frequency,
        )
    }

    fn encode_request_disclosure_call_data(&self, params: &RequestDisclosureParams) -> Vec<u8> {
        self.builder.build_request_disclosure_call_data(
            &params.target,
            &params.reason,
            params.evidence.as_ref(),
        )
    }

    fn encode_approve_disclosure_call_data(&self, params: &ApproveDisclosureParams) -> Vec<u8> {
        self.builder.build_approve_disclosure_call_data(
            &params.auditor,
            &params.commitment,
            &params.zk_proof,
            &params.disclosed_data,
        )
    }

    fn encode_reject_disclosure_call_data(&self, params: &RejectDisclosureParams) -> Vec<u8> {
        self.builder
            .build_reject_disclosure_call_data(&params.auditor, &params.reason)
    }

    fn encode_submit_disclosure_call_data(&self, params: &SubmitDisclosureParams) -> Vec<u8> {
        self.builder.build_submit_disclosure_call_data(
            &params.commitment,
            &params.proof_bytes,
            &params.public_signals,
            &params.partial_data,
            params.auditor.as_ref(),
        )
    }

    fn encode_batch_submit_disclosure_call_data(
        &self,
        params: &BatchSubmitDisclosureParams,
    ) -> Vec<u8> {
        self.builder
            .build_batch_submit_disclosure_call_data(&params.submissions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::params::{
        AuditorInfo, DisclosureConditionType, DisclosureSubmission, ShieldOperation,
    };
    use crate::presentation::config::{compliance_calls, shield_calls, PALLET_INDEX};

    #[test]
    fn test_substrate_encoder_all_calls_have_expected_indices() {
        let encoder = SubstrateTransactionEncoder::new();

        let shield = ShieldParams {
            amount: 100,
            asset_id: AssetId::ORB,
            commitment: crate::domain::types::Commitment::from_bytes_unchecked([1u8; 32]),
        };
        let shield_data = encoder.encode_shield_call_data(&shield, &[0u8; 8]);
        assert_eq!(shield_data[0], PALLET_INDEX);
        assert_eq!(shield_data[1], shield_calls::SHIELD);

        let shield_batch = ShieldBatchParams {
            operations: vec![ShieldOperation {
                asset_id: AssetId::new(1),
                amount: 1,
                commitment: crate::domain::types::Commitment::from_bytes_unchecked([2u8; 32]),
                encrypted_memo: vec![1u8; 4],
            }],
        };
        let shield_batch_data = encoder.encode_shield_batch_call_data(&shield_batch);
        assert_eq!(shield_batch_data[0], PALLET_INDEX);
        assert_eq!(shield_batch_data[1], shield_calls::SHIELD_BATCH);

        let unshield = UnshieldParams {
            nullifier: crate::domain::types::Nullifier::from_bytes_unchecked([3u8; 32]),
            amount: 10,
            recipient: crate::domain::types::Address::from_slice_unchecked(&[4u8; 20]),
            root: crate::domain::types::Hash::from_slice(&[5u8; 32]),
            proof: vec![6u8; 64],
        };
        let unshield_data = encoder.encode_unshield_call_data(&unshield, AssetId::new(2));
        assert_eq!(unshield_data[0], PALLET_INDEX);
        assert_eq!(unshield_data[1], shield_calls::UNSHIELD);

        let transfer = TransferParams {
            input_nullifiers: [
                crate::domain::types::Nullifier::from_bytes_unchecked([7u8; 32]),
                crate::domain::types::Nullifier::from_bytes_unchecked([8u8; 32]),
            ],
            output_commitments: [
                crate::domain::types::Commitment::from_bytes_unchecked([9u8; 32]),
                crate::domain::types::Commitment::from_bytes_unchecked([10u8; 32]),
            ],
            root: crate::domain::types::Hash::from_slice(&[11u8; 32]),
            proof: vec![12u8; 64],
            encrypted_memos: [vec![13u8; 4], vec![14u8; 4]],
        };
        let transfer_data = encoder.encode_transfer_call_data(&transfer);
        assert_eq!(transfer_data[0], PALLET_INDEX);
        assert_eq!(transfer_data[1], shield_calls::TRANSFER);

        let set_policy = SetAuditPolicyParams {
            auditors: vec![AuditorInfo {
                account: crate::domain::types::Address::from_slice_unchecked(&[15u8; 20]),
                public_key: None,
                authorized_from: 1,
            }],
            conditions: vec![DisclosureConditionType::ManualApproval],
            max_frequency: Some(1),
        };
        let set_policy_data = encoder.encode_set_audit_policy_call_data(&set_policy);
        assert_eq!(set_policy_data[0], PALLET_INDEX);
        assert_eq!(set_policy_data[1], compliance_calls::SET_AUDIT_POLICY);

        let request = RequestDisclosureParams {
            target: crate::domain::types::Address::from_slice_unchecked(&[16u8; 20]),
            reason: b"request reason".to_vec(),
            evidence: Some(vec![17u8; 4]),
        };
        let request_data = encoder.encode_request_disclosure_call_data(&request);
        assert_eq!(request_data[0], PALLET_INDEX);
        assert_eq!(request_data[1], compliance_calls::REQUEST_DISCLOSURE);

        let approve = ApproveDisclosureParams {
            auditor: crate::domain::types::Address::from_slice_unchecked(&[18u8; 20]),
            commitment: crate::domain::types::Commitment::from_bytes_unchecked([19u8; 32]),
            zk_proof: vec![20u8; 8],
            disclosed_data: vec![21u8; 8],
        };
        let approve_data = encoder.encode_approve_disclosure_call_data(&approve);
        assert_eq!(approve_data[0], PALLET_INDEX);
        assert_eq!(approve_data[1], compliance_calls::APPROVE_DISCLOSURE);

        let reject = RejectDisclosureParams {
            auditor: crate::domain::types::Address::from_slice_unchecked(&[22u8; 20]),
            reason: b"reject reason".to_vec(),
        };
        let reject_data = encoder.encode_reject_disclosure_call_data(&reject);
        assert_eq!(reject_data[0], PALLET_INDEX);
        assert_eq!(reject_data[1], compliance_calls::REJECT_DISCLOSURE);

        let submit = SubmitDisclosureParams {
            commitment: crate::domain::types::Commitment::from_bytes_unchecked([23u8; 32]),
            proof_bytes: vec![24u8; 8],
            public_signals: vec![25u8; 8],
            partial_data: vec![26u8; 8],
            auditor: None,
        };
        let submit_data = encoder.encode_submit_disclosure_call_data(&submit);
        assert_eq!(submit_data[0], PALLET_INDEX);
        assert_eq!(submit_data[1], compliance_calls::SUBMIT_DISCLOSURE);

        let batch_submit = BatchSubmitDisclosureParams {
            submissions: vec![DisclosureSubmission {
                commitment: crate::domain::types::Commitment::from_bytes_unchecked([27u8; 32]),
                proof: vec![28u8; 8],
                public_signals: vec![29u8; 8],
                disclosed_data: vec![30u8; 8],
            }],
        };
        let batch_submit_data = encoder.encode_batch_submit_disclosure_call_data(&batch_submit);
        assert_eq!(batch_submit_data[0], PALLET_INDEX);
        assert_eq!(
            batch_submit_data[1],
            compliance_calls::BATCH_SUBMIT_DISCLOSURE
        );
    }
}
