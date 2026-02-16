//! Call data builder for Substrate extrinsics
use crate::application::params::{
    AuditorInfo, DisclosureConditionType, DisclosureSubmission, ShieldOperation,
};
use crate::domain::ports::EncoderPort;
use crate::domain::types::{Address, Commitment, Hash, Nullifier};
use crate::infrastructure::codec::types::{
    AuditorInfoCodec, DisclosureConditionTypeCodec, DisclosureSubmissionCodec, ShieldOperationCodec,
};
use crate::presentation::config::{compliance_calls, shield_calls, PALLET_INDEX};
use alloc::vec::Vec;
use codec::Encode;

/// Builds raw call data bytes using an injected encoder port.
pub struct CallDataBuilder<E: EncoderPort> {
    encoder: E,
}

impl<E: EncoderPort> CallDataBuilder<E> {
    pub fn new(encoder: E) -> Self {
        Self { encoder }
    }

    /// Builds Shield call data (pallet: 50, call: 0).
    pub fn build_shield_call_data(
        &self,
        asset_id: u32,
        amount: u128,
        commitment: &Commitment,
        memo: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(shield_calls::SHIELD));
        data.extend_from_slice(&self.encoder.encode_u32(asset_id));
        data.extend_from_slice(&self.encoder.encode_u128(amount));
        data.extend_from_slice(&self.encoder.encode_commitment(commitment));
        data.extend_from_slice(&self.encoder.encode_bytes(memo));
        data
    }

    /// Builds Shield Batch call data (pallet: 50, call: 12).
    pub fn build_shield_batch_call_data(&self, operations: &[ShieldOperation]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(shield_calls::SHIELD_BATCH));

        let operations_codec: Vec<ShieldOperationCodec> = operations
            .iter()
            .map(|op| ShieldOperationCodec::from(op.clone()))
            .collect();
        data.extend_from_slice(&operations_codec.encode());
        data
    }

    /// Builds Private Transfer call data (pallet: 50, call: 1).
    pub fn build_transfer_call_data(
        &self,
        input_nullifiers: &[Nullifier; 2],
        output_commitments: &[Commitment; 2],
        root: &Hash,
        proof: &[u8],
        encrypted_memos: &[Vec<u8>; 2],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(shield_calls::TRANSFER));

        // Node order: proof, merkle_root, nullifiers, commitments, encrypted_memos
        data.extend_from_slice(&self.encoder.encode_bytes(proof));
        data.extend_from_slice(&self.encoder.encode_hash(root));
        data.extend_from_slice(&self.encoder.encode_nullifier_pair(input_nullifiers));
        data.extend_from_slice(&self.encoder.encode_commitment_pair(output_commitments));

        // Single argument in pallet: BoundedVec<FrameEncryptedMemo, ConstU32<2>>
        data.extend_from_slice(&encrypted_memos.to_vec().encode());
        data
    }

    /// Builds Unshield call data (pallet: 50, call: 2).
    pub fn build_unshield_call_data(
        &self,
        nullifier: &Nullifier,
        amount: u128,
        recipient: &Address,
        root: &Hash,
        proof: &[u8],
        asset_id: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(shield_calls::UNSHIELD));

        // Node order: proof, merkle_root, nullifier, asset_id, amount, recipient
        data.extend_from_slice(&self.encoder.encode_bytes(proof));
        data.extend_from_slice(&self.encoder.encode_hash(root));
        data.extend_from_slice(&self.encoder.encode_nullifier(nullifier));
        data.extend_from_slice(&self.encoder.encode_u32(asset_id));
        data.extend_from_slice(&self.encoder.encode_u128(amount));
        data.extend_from_slice(&self.encoder.encode_address(recipient));
        data
    }

    /// Builds Set Audit Policy call data (pallet: 50, call: 4).
    pub fn build_set_audit_policy_call_data(
        &self,
        auditors: &[AuditorInfo],
        conditions: &[DisclosureConditionType],
        max_frequency: Option<u32>,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(compliance_calls::SET_AUDIT_POLICY));

        // Encode Vec<AuditorInfo>
        let auditors_codec: Vec<AuditorInfoCodec> = auditors
            .iter()
            .map(|a| AuditorInfoCodec::from(a.clone()))
            .collect();
        data.extend_from_slice(&auditors_codec.encode());

        // Encode Vec<DisclosureConditionType>
        let conditions_codec: Vec<DisclosureConditionTypeCodec> = conditions
            .iter()
            .map(|c| DisclosureConditionTypeCodec::from(c.clone()))
            .collect();
        data.extend_from_slice(&conditions_codec.encode());

        // Encode Option<u32>
        data.extend_from_slice(&max_frequency.encode());

        data
    }

    /// Builds Request Disclosure call data (pallet: 50, call: 5).
    pub fn build_request_disclosure_call_data(
        &self,
        target: &Address,
        reason: &[u8],
        evidence: Option<&Vec<u8>>,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(compliance_calls::REQUEST_DISCLOSURE));

        data.extend_from_slice(&self.encoder.encode_address(target));
        data.extend_from_slice(&self.encoder.encode_bytes(reason));

        match evidence {
            Some(e) => {
                data.push(1); // Some
                data.extend_from_slice(&self.encoder.encode_bytes(e));
            }
            None => data.push(0), // None
        }

        data
    }

    /// Build Approve Disclosure call data
    /// Pallet Index: 50, Call Index: 6
    pub fn build_approve_disclosure_call_data(
        &self,
        auditor: &Address,
        commitment: &Commitment,
        zk_proof: &[u8],
        disclosed_data: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(compliance_calls::APPROVE_DISCLOSURE));

        data.extend_from_slice(&self.encoder.encode_address(auditor));
        data.extend_from_slice(&self.encoder.encode_commitment(commitment));
        data.extend_from_slice(&self.encoder.encode_bytes(zk_proof));
        data.extend_from_slice(&self.encoder.encode_bytes(disclosed_data));

        data
    }

    /// Build Reject Disclosure call data
    /// Pallet Index: 50, Call Index: 7
    pub fn build_reject_disclosure_call_data(&self, auditor: &Address, reason: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(compliance_calls::REJECT_DISCLOSURE));

        data.extend_from_slice(&self.encoder.encode_address(auditor));
        data.extend_from_slice(&self.encoder.encode_bytes(reason));

        data
    }

    /// Build Submit Disclosure call data
    /// Pallet Index: 50, Call Index: 8
    pub fn build_submit_disclosure_call_data(
        &self,
        commitment: &Commitment,
        proof_bytes: &[u8],
        public_signals: &[u8],
        partial_data: &[u8],
        auditor: Option<&Address>,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(&self.encoder.encode_u8(compliance_calls::SUBMIT_DISCLOSURE));

        data.extend_from_slice(&self.encoder.encode_commitment(commitment));
        data.extend_from_slice(&self.encoder.encode_bytes(proof_bytes));
        data.extend_from_slice(&self.encoder.encode_bytes(public_signals));
        data.extend_from_slice(&self.encoder.encode_bytes(partial_data));

        match auditor {
            Some(a) => {
                data.push(1);
                data.extend_from_slice(&self.encoder.encode_address(a));
            }
            None => data.push(0),
        }

        data
    }

    /// Build Batch Submit Disclosure call data
    /// Pallet Index: 50, Call Index: 13
    pub fn build_batch_submit_disclosure_call_data(
        &self,
        submissions: &[DisclosureSubmission],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.encoder.encode_u8(PALLET_INDEX));
        data.extend_from_slice(
            &self
                .encoder
                .encode_u8(compliance_calls::BATCH_SUBMIT_DISCLOSURE),
        );

        let submissions_codec: Vec<DisclosureSubmissionCodec> = submissions
            .iter()
            .map(|s| DisclosureSubmissionCodec::from(s.clone()))
            .collect();
        data.extend_from_slice(&submissions_codec.encode());

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{Address, AssetId, Commitment, Hash, Nullifier};
    use crate::infrastructure::codec::encoder::ScaleEncoder;
    use crate::presentation::config::{compliance_calls, shield_calls, PALLET_INDEX};

    fn builder() -> CallDataBuilder<ScaleEncoder> {
        CallDataBuilder::new(ScaleEncoder::new())
    }

    #[test]
    fn test_build_shield_and_unshield_indices() {
        let b = builder();

        let shield = b.build_shield_call_data(
            AssetId::ORB.as_u32(),
            10,
            &Commitment::from_bytes_unchecked([1u8; 32]),
            &[2u8; 8],
        );
        assert_eq!(shield[0], PALLET_INDEX);
        assert_eq!(shield[1], shield_calls::SHIELD);

        let unshield = b.build_unshield_call_data(
            &Nullifier::from_bytes_unchecked([3u8; 32]),
            20,
            &Address::from_slice_unchecked(&[4u8; 20]),
            &Hash::from_slice(&[5u8; 32]),
            &[6u8; 64],
            1,
        );
        assert_eq!(unshield[0], PALLET_INDEX);
        assert_eq!(unshield[1], shield_calls::UNSHIELD);
    }

    #[test]
    fn test_build_transfer_changes_with_proof() {
        let b = builder();
        let input_nullifiers = [
            Nullifier::from_bytes_unchecked([7u8; 32]),
            Nullifier::from_bytes_unchecked([8u8; 32]),
        ];
        let output_commitments = [
            Commitment::from_bytes_unchecked([9u8; 32]),
            Commitment::from_bytes_unchecked([10u8; 32]),
        ];
        let root = Hash::from_slice(&[11u8; 32]);
        let memos = [vec![12u8; 4], vec![13u8; 4]];

        let t1 = b.build_transfer_call_data(
            &input_nullifiers,
            &output_commitments,
            &root,
            &[14u8; 64],
            &memos,
        );
        let t2 = b.build_transfer_call_data(
            &input_nullifiers,
            &output_commitments,
            &root,
            &[15u8; 64],
            &memos,
        );

        assert_eq!(t1[0], PALLET_INDEX);
        assert_eq!(t1[1], shield_calls::TRANSFER);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_build_compliance_call_indices() {
        let b = builder();

        let auditors = vec![AuditorInfo {
            account: Address::from_slice_unchecked(&[16u8; 20]),
            public_key: None,
            authorized_from: 1,
        }];
        let conditions = vec![DisclosureConditionType::ManualApproval];

        let set_policy = b.build_set_audit_policy_call_data(&auditors, &conditions, Some(1));
        assert_eq!(set_policy[0], PALLET_INDEX);
        assert_eq!(set_policy[1], compliance_calls::SET_AUDIT_POLICY);

        let request = b.build_request_disclosure_call_data(
            &Address::from_slice_unchecked(&[17u8; 20]),
            b"reason-test",
            Some(&vec![18u8; 4]),
        );
        assert_eq!(request[0], PALLET_INDEX);
        assert_eq!(request[1], compliance_calls::REQUEST_DISCLOSURE);

        let approve = b.build_approve_disclosure_call_data(
            &Address::from_slice_unchecked(&[19u8; 20]),
            &Commitment::from_bytes_unchecked([20u8; 32]),
            &[21u8; 8],
            &[22u8; 8],
        );
        assert_eq!(approve[0], PALLET_INDEX);
        assert_eq!(approve[1], compliance_calls::APPROVE_DISCLOSURE);

        let reject = b.build_reject_disclosure_call_data(
            &Address::from_slice_unchecked(&[23u8; 20]),
            b"reject reason",
        );
        assert_eq!(reject[0], PALLET_INDEX);
        assert_eq!(reject[1], compliance_calls::REJECT_DISCLOSURE);

        let submit = b.build_submit_disclosure_call_data(
            &Commitment::from_bytes_unchecked([24u8; 32]),
            &[25u8; 8],
            &[26u8; 8],
            &[27u8; 8],
            None,
        );
        assert_eq!(submit[0], PALLET_INDEX);
        assert_eq!(submit[1], compliance_calls::SUBMIT_DISCLOSURE);

        let batch = b.build_batch_submit_disclosure_call_data(&[DisclosureSubmission {
            commitment: Commitment::from_bytes_unchecked([28u8; 32]),
            proof: vec![29u8; 8],
            public_signals: vec![30u8; 8],
            disclosed_data: vec![31u8; 8],
        }]);
        assert_eq!(batch[0], PALLET_INDEX);
        assert_eq!(batch[1], compliance_calls::BATCH_SUBMIT_DISCLOSURE);
    }
}
