// Application Layer - Ports
//! High-level interfaces for application services
//!
//! These ports abstract infrastructure concerns from application logic,
//! following the Dependency Inversion Principle.

pub mod transaction_encoder;

pub use transaction_encoder::TransactionEncoderPort;

#[cfg(test)]
mod tests {
    use super::TransactionEncoderPort;
    use crate::application::params::{
        ApproveDisclosureParams, BatchSubmitDisclosureParams, RejectDisclosureParams,
        RequestDisclosureParams, SetAuditPolicyParams, SubmitDisclosureParams,
    };
    use crate::application::params::{
        ShieldBatchParams, ShieldParams, TransferParams, UnshieldParams,
    };
    use crate::domain::types::AssetId;

    struct Dummy;

    impl TransactionEncoderPort for Dummy {
        fn encode_shield_call_data(
            &self,
            _params: &ShieldParams,
            _encrypted_memo: &[u8],
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_shield_batch_call_data(
            &self,
            _params: &ShieldBatchParams,
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_unshield_call_data(
            &self,
            _params: &UnshieldParams,
            _asset_id: AssetId,
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_transfer_call_data(&self, _params: &TransferParams) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_set_audit_policy_call_data(
            &self,
            _params: &SetAuditPolicyParams,
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_request_disclosure_call_data(
            &self,
            _params: &RequestDisclosureParams,
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_approve_disclosure_call_data(
            &self,
            _params: &ApproveDisclosureParams,
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_reject_disclosure_call_data(
            &self,
            _params: &RejectDisclosureParams,
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_submit_disclosure_call_data(
            &self,
            _params: &SubmitDisclosureParams,
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
        fn encode_batch_submit_disclosure_call_data(
            &self,
            _params: &BatchSubmitDisclosureParams,
        ) -> alloc::vec::Vec<u8> {
            vec![42]
        }
    }

    #[test]
    fn test_ports_module_reexports_transaction_encoder_port() {
        let encoder: &dyn TransactionEncoderPort = &Dummy;
        let out = encoder.encode_batch_submit_disclosure_call_data(&BatchSubmitDisclosureParams {
            submissions: vec![],
        });
        assert_eq!(out, vec![42]);
    }
}
