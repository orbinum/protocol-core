//! Transaction Validators Module
//! Validation logic for transaction parameters

pub mod compliance_validator;
pub mod transaction_validator;

pub use compliance_validator::ComplianceValidator;
pub use transaction_validator::TransactionValidator;

#[cfg(test)]
mod tests {
    use super::{ComplianceValidator, TransactionValidator};
    use crate::application::params::AuditorInfo;
    use crate::domain::types::{Address, Commitment};

    #[test]
    fn test_validators_module_reexports() {
        let commitment = Commitment::from_bytes_unchecked([1u8; 32]);
        assert!(TransactionValidator::validate_commitment(&commitment).is_ok());

        let auditors = vec![AuditorInfo {
            account: Address::from_slice_unchecked(&[1u8; 32]),
            public_key: None,
            authorized_from: 1,
        }];
        assert!(ComplianceValidator::validate_auditor_list(&auditors).is_ok());
    }
}
