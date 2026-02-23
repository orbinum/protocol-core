//! Application Layer
//!
//! Use cases and application services following Clean Architecture principles.
//! Modules are organized by dependency hierarchy:
//! - Foundation: errors, ports, params
//! - Validation: validators
//! - Construction: builders
//! - Utilities: memo, keys, notes

// Foundation Layer
pub mod errors;
pub mod params;
pub mod ports;

pub use errors::*;
pub use params::{
    ShieldBatchParams, ShieldOperation, ShieldParams, TransferParams, UnshieldParams,
};
pub use ports::*;

// Validation Layer
pub mod validators;
pub use validators::*;

// Construction Layer
pub mod builders;
pub use builders::*;

// Utilities
pub mod key_manager;
pub mod memo_utils;
pub mod note_manager;

pub use key_manager::*;
pub use memo_utils::*;
pub use note_manager::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::{Address, Commitment};

    #[test]
    fn test_application_reexports_foundation_and_validation() {
        let commitment = Commitment::from_bytes_unchecked([1u8; 32]);
        assert!(TransactionValidator::validate_commitment(&commitment).is_ok());

        let auditors = vec![crate::application::params::AuditorInfo {
            account: Address::from_slice_unchecked(&[1u8; 32]),
            public_key: None,
            authorized_from: 1,
        }];
        assert!(ComplianceValidator::validate_auditor_list(&auditors).is_ok());
    }

    #[test]
    fn test_application_reexports_params_types() {
        let params = ShieldParams {
            amount: 10,
            asset_id: crate::domain::types::AssetId::ORB,
            commitment: Commitment::from_bytes_unchecked([2u8; 32]),
        };

        assert_eq!(params.amount, 10);
        assert_eq!(params.asset_id.as_u32(), 0);
    }
}
