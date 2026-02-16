// Compliance builders module
//! Compliance and disclosure builders (not yet implemented - pending)

pub mod approve_disclosure;
pub mod audit_policy;
pub mod batch_submit_disclosure;
pub mod reject_disclosure;
pub mod request_disclosure;
pub mod submit_disclosure;

pub use approve_disclosure::ApproveDisclosureBuilder;
pub use audit_policy::SetAuditPolicyBuilder;
pub use batch_submit_disclosure::BatchSubmitDisclosureBuilder;
pub use reject_disclosure::RejectDisclosureBuilder;
pub use request_disclosure::RequestDisclosureBuilder;
pub use submit_disclosure::SubmitDisclosureBuilder;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::params::{
        ApproveDisclosureParams, AuditorInfo, BatchSubmitDisclosureParams, DisclosureConditionType,
        DisclosureSubmission, RejectDisclosureParams, RequestDisclosureParams,
        SetAuditPolicyParams, SubmitDisclosureParams,
    };
    use crate::domain::types::{Address, Commitment};
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_compliance_reexports_builders_end_to_end() {
        let encoder = SubstrateTransactionEncoder::new();

        let set_policy = SetAuditPolicyBuilder::build_unsigned(
            &encoder,
            SetAuditPolicyParams {
                auditors: vec![AuditorInfo {
                    account: Address::from_slice_unchecked(&[1u8; 20]),
                    public_key: None,
                    authorized_from: 0,
                }],
                conditions: vec![DisclosureConditionType::ManualApproval],
                max_frequency: Some(10),
            },
            1,
        );

        let request = RequestDisclosureBuilder::build_unsigned(
            &encoder,
            RequestDisclosureParams {
                target: Address::from_slice_unchecked(&[2u8; 20]),
                reason: b"review".to_vec(),
                evidence: None,
            },
            2,
        );

        let approve = ApproveDisclosureBuilder::build_unsigned(
            &encoder,
            ApproveDisclosureParams {
                auditor: Address::from_slice_unchecked(&[3u8; 20]),
                commitment: Commitment::from_bytes_unchecked([4u8; 32]),
                zk_proof: vec![1u8; 64],
                disclosed_data: vec![2u8; 8],
            },
            3,
        );

        let reject = RejectDisclosureBuilder::build_unsigned(
            &encoder,
            RejectDisclosureParams {
                auditor: Address::from_slice_unchecked(&[5u8; 20]),
                reason: b"not enough".to_vec(),
            },
            4,
        );

        let submit = SubmitDisclosureBuilder::build_unsigned(
            &encoder,
            SubmitDisclosureParams {
                commitment: Commitment::from_bytes_unchecked([6u8; 32]),
                proof_bytes: vec![7u8; 64],
                public_signals: vec![8u8; 32],
                partial_data: vec![9u8; 16],
                auditor: Some(Address::from_slice_unchecked(&[10u8; 20])),
            },
            5,
        );

        let batch = BatchSubmitDisclosureBuilder::build_unsigned(
            &encoder,
            BatchSubmitDisclosureParams {
                submissions: vec![DisclosureSubmission {
                    commitment: Commitment::from_bytes_unchecked([11u8; 32]),
                    proof: vec![12u8; 64],
                    public_signals: vec![13u8; 32],
                    disclosed_data: vec![14u8; 16],
                }],
            },
            6,
        );

        assert_eq!(set_policy.call_data()[1], 4);
        assert_eq!(request.call_data()[1], 5);
        assert_eq!(approve.call_data()[1], 6);
        assert_eq!(reject.call_data()[1], 7);
        assert_eq!(submit.call_data()[1], 8);
        assert_eq!(batch.call_data()[1], 13);
    }
}
