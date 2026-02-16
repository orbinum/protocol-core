//! Application Layer Parameters
//!
//! Input parameters for application use cases.
//! These are contracts between application layer and external consumers.

use crate::domain::types::*;
use serde::{Deserialize, Serialize};
extern crate alloc;

// Core Transaction Parameters

/// Parameters for Shield (deposit) use case
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldParams {
    pub amount: u128,
    pub asset_id: AssetId,
    #[serde(with = "crate::infrastructure::serde_adapters::commitment")]
    pub commitment: Commitment,
}

/// Parameters for Unshield (withdrawal) use case
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnshieldParams {
    #[serde(with = "crate::infrastructure::serde_adapters::nullifier")]
    pub nullifier: Nullifier,
    pub amount: u128,
    #[serde(with = "crate::infrastructure::serde_adapters::address")]
    pub recipient: Address,
    #[serde(with = "crate::infrastructure::serde_adapters::hash")]
    pub root: Hash,
    pub proof: alloc::vec::Vec<u8>,
}

/// Parameters for Private Transfer use case
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferParams {
    #[serde(with = "crate::infrastructure::serde_adapters::nullifier_array")]
    pub input_nullifiers: [Nullifier; 2],
    #[serde(with = "crate::infrastructure::serde_adapters::commitment_array")]
    pub output_commitments: [Commitment; 2],
    #[serde(with = "crate::infrastructure::serde_adapters::hash")]
    pub root: Hash,
    pub proof: alloc::vec::Vec<u8>,
    pub encrypted_memos: [alloc::vec::Vec<u8>; 2],
}

/// Parameters for Shield Batch use case
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldBatchParams {
    pub operations: alloc::vec::Vec<ShieldOperation>,
}

/// An individual shield operation in a batch
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldOperation {
    pub asset_id: AssetId,
    pub amount: u128,
    #[serde(with = "crate::infrastructure::serde_adapters::commitment")]
    pub commitment: Commitment,
    pub encrypted_memo: alloc::vec::Vec<u8>,
}

// Compliance & Disclosure Parameters

/// Parameters for Set Audit Policy transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetAuditPolicyParams {
    pub auditors: alloc::vec::Vec<AuditorInfo>,
    pub conditions: alloc::vec::Vec<DisclosureConditionType>,
    pub max_frequency: Option<u32>,
}

/// Auditor information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditorInfo {
    #[serde(with = "crate::infrastructure::serde_adapters::address")]
    pub account: Address,
    pub public_key: Option<[u8; 32]>,
    pub authorized_from: u32,
}

/// Disclosure condition types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DisclosureConditionType {
    AmountAbove(u128),
    TimeElapsed(u32),
    ManualApproval,
}

/// Parameters for Request Disclosure transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestDisclosureParams {
    #[serde(with = "crate::infrastructure::serde_adapters::address")]
    pub target: Address,
    pub reason: alloc::vec::Vec<u8>,
    pub evidence: Option<alloc::vec::Vec<u8>>,
}

/// Parameters for Approve Disclosure transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApproveDisclosureParams {
    #[serde(with = "crate::infrastructure::serde_adapters::address")]
    pub auditor: Address,
    #[serde(with = "crate::infrastructure::serde_adapters::commitment")]
    pub commitment: Commitment,
    pub zk_proof: alloc::vec::Vec<u8>,
    pub disclosed_data: alloc::vec::Vec<u8>,
}

/// Parameters for Reject Disclosure transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectDisclosureParams {
    #[serde(with = "crate::infrastructure::serde_adapters::address")]
    pub auditor: Address,
    pub reason: alloc::vec::Vec<u8>,
}

/// Parameters for Submit Disclosure transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitDisclosureParams {
    #[serde(with = "crate::infrastructure::serde_adapters::commitment")]
    pub commitment: Commitment,
    pub proof_bytes: alloc::vec::Vec<u8>,
    pub public_signals: alloc::vec::Vec<u8>,
    pub partial_data: alloc::vec::Vec<u8>,
    #[serde(with = "crate::infrastructure::serde_adapters::option_address")]
    pub auditor: Option<Address>,
}

/// Parameters for Batch Submit Disclosure transactions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchSubmitDisclosureParams {
    pub submissions: alloc::vec::Vec<DisclosureSubmission>,
}

/// An individual disclosure submission
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureSubmission {
    #[serde(with = "crate::infrastructure::serde_adapters::commitment")]
    pub commitment: Commitment,
    pub proof: alloc::vec::Vec<u8>,
    pub public_signals: alloc::vec::Vec<u8>,
    pub disclosed_data: alloc::vec::Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_params_construction() {
        let shield = ShieldParams {
            amount: 100,
            asset_id: AssetId::new(1),
            commitment: Commitment::from_bytes_unchecked([1u8; 32]),
        };
        assert_eq!(shield.amount, 100);
        assert_eq!(shield.asset_id.as_u32(), 1);

        let unshield = UnshieldParams {
            nullifier: Nullifier::from_bytes_unchecked([2u8; 32]),
            amount: 50,
            recipient: Address::from_slice_unchecked(&[3u8; 20]),
            root: Hash::from_slice(&[4u8; 32]),
            proof: vec![5u8; 64],
        };
        assert_eq!(unshield.amount, 50);
        assert_eq!(unshield.proof.len(), 64);
    }

    #[test]
    fn test_transfer_params_construction() {
        let transfer = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([6u8; 32]),
                Nullifier::from_bytes_unchecked([7u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([8u8; 32]),
                Commitment::from_bytes_unchecked([9u8; 32]),
            ],
            root: Hash::from_slice(&[10u8; 32]),
            proof: vec![11u8; 192],
            encrypted_memos: [vec![12u8; 16], vec![13u8; 16]],
        };

        assert_eq!(transfer.input_nullifiers.len(), 2);
        assert_eq!(transfer.output_commitments.len(), 2);
        assert_eq!(transfer.encrypted_memos[0].len(), 16);
    }

    #[test]
    fn test_shield_batch_params_construction() {
        let batch = ShieldBatchParams {
            operations: vec![
                ShieldOperation {
                    asset_id: AssetId::ORB,
                    amount: 10,
                    commitment: Commitment::from_bytes_unchecked([14u8; 32]),
                    encrypted_memo: vec![15u8; 8],
                },
                ShieldOperation {
                    asset_id: AssetId::new(2),
                    amount: 20,
                    commitment: Commitment::from_bytes_unchecked([16u8; 32]),
                    encrypted_memo: vec![17u8; 8],
                },
            ],
        };

        assert_eq!(batch.operations.len(), 2);
        assert_eq!(batch.operations[0].asset_id.as_u32(), 0);
        assert_eq!(batch.operations[1].amount, 20);
    }

    #[test]
    fn test_compliance_params_construction() {
        let params = SetAuditPolicyParams {
            auditors: vec![AuditorInfo {
                account: Address::from_slice_unchecked(&[18u8; 20]),
                public_key: Some([19u8; 32]),
                authorized_from: 100,
            }],
            conditions: vec![DisclosureConditionType::ManualApproval],
            max_frequency: Some(12),
        };

        assert_eq!(params.auditors.len(), 1);
        assert_eq!(params.conditions.len(), 1);
        assert_eq!(params.max_frequency, Some(12));
    }

    #[test]
    fn test_disclosure_condition_variants() {
        let amount = DisclosureConditionType::AmountAbove(1_000);
        let elapsed = DisclosureConditionType::TimeElapsed(60);
        let manual = DisclosureConditionType::ManualApproval;

        match amount {
            DisclosureConditionType::AmountAbove(v) => assert_eq!(v, 1_000),
            _ => panic!("wrong variant"),
        }

        match elapsed {
            DisclosureConditionType::TimeElapsed(v) => assert_eq!(v, 60),
            _ => panic!("wrong variant"),
        }

        match manual {
            DisclosureConditionType::ManualApproval => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_disclosure_transaction_params_construction() {
        let request = RequestDisclosureParams {
            target: Address::from_slice_unchecked(&[20u8; 20]),
            reason: b"regulatory request".to_vec(),
            evidence: Some(vec![21u8; 4]),
        };
        assert!(request.evidence.is_some());

        let approve = ApproveDisclosureParams {
            auditor: Address::from_slice_unchecked(&[22u8; 20]),
            commitment: Commitment::from_bytes_unchecked([23u8; 32]),
            zk_proof: vec![24u8; 64],
            disclosed_data: vec![25u8; 12],
        };
        assert_eq!(approve.zk_proof.len(), 64);

        let reject = RejectDisclosureParams {
            auditor: Address::from_slice_unchecked(&[26u8; 20]),
            reason: b"insufficient basis".to_vec(),
        };
        assert!(!reject.reason.is_empty());

        let submit = SubmitDisclosureParams {
            commitment: Commitment::from_bytes_unchecked([27u8; 32]),
            proof_bytes: vec![28u8; 64],
            public_signals: vec![29u8; 16],
            partial_data: vec![30u8; 8],
            auditor: Some(Address::from_slice_unchecked(&[31u8; 20])),
        };
        assert!(submit.auditor.is_some());

        let batch = BatchSubmitDisclosureParams {
            submissions: vec![DisclosureSubmission {
                commitment: Commitment::from_bytes_unchecked([32u8; 32]),
                proof: vec![33u8; 32],
                public_signals: vec![34u8; 16],
                disclosed_data: vec![35u8; 8],
            }],
        };
        assert_eq!(batch.submissions.len(), 1);
    }
}
