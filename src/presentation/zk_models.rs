//! ZK Models
//!
//! Zero-knowledge cryptographic data structures for notes, nullifiers, and proofs.

use crate::domain::types::{AssetId, Commitment, Nullifier};
use serde::{Deserialize, Serialize};

/// Note data for external use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteData {
    pub value: u128,
    pub asset_id: AssetId,
    pub owner_pubkey: [u8; 32],
    pub blinding: [u8; 32],
    pub commitment: [u8; 32],
}

impl NoteData {
    pub fn new(
        value: u128,
        asset_id: AssetId,
        owner_pubkey: [u8; 32],
        blinding: [u8; 32],
        commitment: [u8; 32],
    ) -> Self {
        Self {
            value,
            asset_id,
            owner_pubkey,
            blinding,
            commitment,
        }
    }

    pub fn commitment(&self) -> Commitment {
        Commitment::from_bytes_unchecked(self.commitment)
    }
}

/// Nullifier data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierData {
    pub nullifier: [u8; 32],
    pub commitment: [u8; 32],
}

impl NullifierData {
    pub fn new(nullifier: [u8; 32], commitment: [u8; 32]) -> Self {
        Self {
            nullifier,
            commitment,
        }
    }

    pub fn nullifier(&self) -> Nullifier {
        Nullifier::from_bytes_unchecked(self.nullifier)
    }
}

/// Merkle proof data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProofData {
    pub root: [u8; 32],
    pub leaf: [u8; 32],
    pub siblings: alloc::vec::Vec<[u8; 32]>,
    pub leaf_index: u32,
}

// Re-exported compliance parameters from application layer

pub use crate::application::params::{
    ApproveDisclosureParams, AuditorInfo, BatchSubmitDisclosureParams, DisclosureConditionType,
    DisclosureSubmission, RejectDisclosureParams, RequestDisclosureParams, SetAuditPolicyParams,
    SubmitDisclosureParams,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_data_new_and_commitment_accessor() {
        let note = NoteData::new(100, AssetId::new(1), [1u8; 32], [2u8; 32], [3u8; 32]);

        assert_eq!(note.value, 100);
        assert_eq!(note.asset_id.as_u32(), 1);
        assert_eq!(note.owner_pubkey, [1u8; 32]);
        assert_eq!(note.blinding, [2u8; 32]);
        assert_eq!(note.commitment, [3u8; 32]);
        assert_eq!(note.commitment().as_bytes(), &[3u8; 32]);
    }

    #[test]
    fn test_nullifier_data_new_and_accessor() {
        let data = NullifierData::new([4u8; 32], [5u8; 32]);

        assert_eq!(data.nullifier, [4u8; 32]);
        assert_eq!(data.commitment, [5u8; 32]);
        assert_eq!(data.nullifier().as_bytes(), &[4u8; 32]);
    }

    #[test]
    fn test_merkle_proof_data_construction() {
        let proof = MerkleProofData {
            root: [6u8; 32],
            leaf: [7u8; 32],
            siblings: vec![[8u8; 32], [9u8; 32]],
            leaf_index: 3,
        };

        assert_eq!(proof.root, [6u8; 32]);
        assert_eq!(proof.leaf, [7u8; 32]);
        assert_eq!(proof.siblings.len(), 2);
        assert_eq!(proof.leaf_index, 3);
    }

    #[test]
    fn test_reexported_compliance_types_are_usable() {
        let params = SetAuditPolicyParams {
            auditors: vec![AuditorInfo {
                account: crate::domain::types::Address::from_slice_unchecked(&[10u8; 32]),
                public_key: Some([11u8; 32]),
                authorized_from: 1,
            }],
            conditions: vec![DisclosureConditionType::ManualApproval],
            max_frequency: Some(5),
        };

        assert_eq!(params.auditors.len(), 1);
        assert_eq!(params.conditions.len(), 1);
        assert_eq!(params.max_frequency, Some(5));
    }
}
