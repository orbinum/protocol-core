//! Compliance and Disclosure API
//!
//! Build unsigned compliance-related transactions.

use crate::application::builders::*;
use crate::application::params::*;
use crate::domain::types::*;
use crate::infrastructure::serializers::SubstrateTransactionEncoder;
use crate::presentation::api::core::TransactionApi;

extern crate alloc;
use alloc::vec::Vec;

impl TransactionApi {
    /// Builds unsigned Set Audit Policy transaction.
    pub fn build_set_audit_policy_unsigned(
        auditors: Vec<AuditorInfo>,
        conditions: Vec<DisclosureConditionType>,
        max_frequency: Option<u32>,
        nonce: u32,
    ) -> Vec<u8> {
        let params = SetAuditPolicyParams {
            auditors,
            conditions,
            max_frequency,
        };
        let encoder = SubstrateTransactionEncoder::new();
        let tx = SetAuditPolicyBuilder::build_unsigned(&encoder, params, nonce);
        tx.call_data().to_vec()
    }

    /// Builds unsigned Request Disclosure transaction.
    pub fn build_request_disclosure_unsigned(
        target: [u8; 20],
        reason: Vec<u8>,
        evidence: Option<Vec<u8>>,
        nonce: u32,
    ) -> Vec<u8> {
        let params = RequestDisclosureParams {
            target: Address::from_slice(&target).expect("Invalid target address"),
            reason,
            evidence,
        };
        let encoder = SubstrateTransactionEncoder::new();
        let tx = RequestDisclosureBuilder::build_unsigned(&encoder, params, nonce);
        tx.call_data().to_vec()
    }

    /// Builds unsigned Approve Disclosure transaction.
    pub fn build_approve_disclosure_unsigned(
        auditor: [u8; 20],
        commitment: [u8; 32],
        zk_proof: Vec<u8>,
        disclosed_data: Vec<u8>,
        nonce: u32,
    ) -> Vec<u8> {
        let params = ApproveDisclosureParams {
            auditor: Address::from_slice(&auditor).expect("Invalid auditor address"),
            commitment: Commitment::from_bytes(commitment).expect("Invalid commitment"),
            zk_proof,
            disclosed_data,
        };
        let encoder = SubstrateTransactionEncoder::new();
        let tx = ApproveDisclosureBuilder::build_unsigned(&encoder, params, nonce);
        tx.call_data().to_vec()
    }

    /// Builds unsigned Reject Disclosure transaction.
    pub fn build_reject_disclosure_unsigned(
        auditor: [u8; 20],
        reason: Vec<u8>,
        nonce: u32,
    ) -> Vec<u8> {
        let params = RejectDisclosureParams {
            auditor: Address::from_slice(&auditor).expect("Invalid auditor address"),
            reason,
        };
        let encoder = SubstrateTransactionEncoder::new();
        let tx = RejectDisclosureBuilder::build_unsigned(&encoder, params, nonce);
        tx.call_data().to_vec()
    }

    /// Builds unsigned Submit Disclosure transaction.
    pub fn build_submit_disclosure_unsigned(
        commitment: [u8; 32],
        proof_bytes: Vec<u8>,
        public_signals: Vec<u8>,
        partial_data: Vec<u8>,
        auditor: Option<[u8; 20]>,
        nonce: u32,
    ) -> Vec<u8> {
        let params = SubmitDisclosureParams {
            commitment: Commitment::from_bytes(commitment).expect("Invalid commitment"),
            proof_bytes,
            public_signals,
            partial_data,
            auditor: auditor.map(|a| Address::from_slice(&a).expect("Invalid auditor address")),
        };
        let encoder = SubstrateTransactionEncoder::new();
        let tx = SubmitDisclosureBuilder::build_unsigned(&encoder, params, nonce);
        tx.call_data().to_vec()
    }

    /// Builds unsigned Batch Submit Disclosure transaction.
    pub fn build_batch_submit_disclosure_unsigned(
        submissions: Vec<DisclosureSubmission>,
        nonce: u32,
    ) -> Vec<u8> {
        let params = BatchSubmitDisclosureParams { submissions };
        let encoder = SubstrateTransactionEncoder::new();
        let tx = BatchSubmitDisclosureBuilder::build_unsigned(&encoder, params, nonce);
        tx.call_data().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presentation::config::{compliance_calls, PALLET_INDEX};

    #[test]
    fn test_build_set_audit_policy_unsigned() {
        let call_data = TransactionApi::build_set_audit_policy_unsigned(
            vec![AuditorInfo {
                account: Address::from_slice_unchecked(&[1u8; 20]),
                public_key: None,
                authorized_from: 1,
            }],
            vec![DisclosureConditionType::ManualApproval],
            Some(1),
            0,
        );
        assert_eq!(call_data[0], PALLET_INDEX);
        assert_eq!(call_data[1], compliance_calls::SET_AUDIT_POLICY);
    }

    #[test]
    fn test_build_request_disclosure_unsigned() {
        let call_data = TransactionApi::build_request_disclosure_unsigned(
            [2u8; 20],
            b"valid reason".to_vec(),
            Some(vec![3u8; 4]),
            1,
        );
        assert_eq!(call_data[0], PALLET_INDEX);
        assert_eq!(call_data[1], compliance_calls::REQUEST_DISCLOSURE);
    }

    #[test]
    fn test_build_approve_reject_submit_batch_disclosure_unsigned() {
        let approve = TransactionApi::build_approve_disclosure_unsigned(
            [4u8; 20],
            [5u8; 32],
            vec![6u8; 8],
            vec![7u8; 8],
            2,
        );
        assert_eq!(approve[0], PALLET_INDEX);
        assert_eq!(approve[1], compliance_calls::APPROVE_DISCLOSURE);

        let reject = TransactionApi::build_reject_disclosure_unsigned(
            [8u8; 20],
            b"reject reason".to_vec(),
            3,
        );
        assert_eq!(reject[0], PALLET_INDEX);
        assert_eq!(reject[1], compliance_calls::REJECT_DISCLOSURE);

        let submit = TransactionApi::build_submit_disclosure_unsigned(
            [9u8; 32],
            vec![10u8; 8],
            vec![11u8; 8],
            vec![12u8; 8],
            Some([13u8; 20]),
            4,
        );
        assert_eq!(submit[0], PALLET_INDEX);
        assert_eq!(submit[1], compliance_calls::SUBMIT_DISCLOSURE);

        let batch = TransactionApi::build_batch_submit_disclosure_unsigned(
            vec![DisclosureSubmission {
                commitment: Commitment::from_bytes_unchecked([14u8; 32]),
                proof: vec![15u8; 8],
                public_signals: vec![16u8; 8],
                disclosed_data: vec![17u8; 8],
            }],
            5,
        );
        assert_eq!(batch[0], PALLET_INDEX);
        assert_eq!(batch[1], compliance_calls::BATCH_SUBMIT_DISCLOSURE);
    }

    #[test]
    #[should_panic(expected = "Invalid commitment")]
    fn test_build_submit_disclosure_unsigned_panics_with_zero_commitment() {
        let _ = TransactionApi::build_submit_disclosure_unsigned(
            [0u8; 32],
            vec![1u8; 8],
            vec![2u8; 8],
            vec![3u8; 8],
            None,
            0,
        );
    }
}
