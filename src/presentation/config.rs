//! Chain configuration constants
//!
//! Centralizes all chain-specific values for Substrate interaction.

/// Pallet index for Shield operations.
pub const PALLET_INDEX: u8 = 50;

/// Pallet name for Shield operations.
pub const PALLET_NAME: &str = "ShieldedPool";

/// Shield call indices.
pub mod shield_calls {
    /// Shield (deposit) operation.
    pub const SHIELD: u8 = 0;

    /// Private transfer operation.
    pub const TRANSFER: u8 = 1;

    /// Unshield (withdrawal) operation.
    pub const UNSHIELD: u8 = 2;

    /// Shield batch operation.
    pub const SHIELD_BATCH: u8 = 12;
}

/// Compliance call indices.
pub mod compliance_calls {
    /// Set audit policy.
    pub const SET_AUDIT_POLICY: u8 = 4;

    /// Request disclosure.
    pub const REQUEST_DISCLOSURE: u8 = 5;

    /// Approve disclosure.
    pub const APPROVE_DISCLOSURE: u8 = 6;

    /// Reject disclosure.
    pub const REJECT_DISCLOSURE: u8 = 7;

    /// Submit disclosure.
    pub const SUBMIT_DISCLOSURE: u8 = 8;

    /// Batch submit disclosure.
    pub const BATCH_SUBMIT_DISCLOSURE: u8 = 13;
}

/// Chain specification version.
pub const SPEC_VERSION: u32 = 1;

/// Transaction version.
pub const TRANSACTION_VERSION: u32 = 1;

/// Genesis hash placeholder.
///
/// Configure at runtime with the actual genesis hash.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pallet_config() {
        assert_eq!(PALLET_INDEX, 50);
        assert_eq!(PALLET_NAME, "ShieldedPool");
    }

    #[test]
    fn test_shield_call_indices() {
        assert_eq!(shield_calls::SHIELD, 0);
        assert_eq!(shield_calls::TRANSFER, 1);
        assert_eq!(shield_calls::UNSHIELD, 2);
        assert_eq!(shield_calls::SHIELD_BATCH, 12);
    }

    #[test]
    fn test_compliance_call_indices() {
        assert_eq!(compliance_calls::SET_AUDIT_POLICY, 4);
        assert_eq!(compliance_calls::REQUEST_DISCLOSURE, 5);
        assert_eq!(compliance_calls::APPROVE_DISCLOSURE, 6);
        assert_eq!(compliance_calls::REJECT_DISCLOSURE, 7);
        assert_eq!(compliance_calls::SUBMIT_DISCLOSURE, 8);
        assert_eq!(compliance_calls::BATCH_SUBMIT_DISCLOSURE, 13);
    }

    #[test]
    fn test_chain_versions() {
        assert_eq!(SPEC_VERSION, 1);
        assert_eq!(TRANSACTION_VERSION, 1);
    }

    #[test]
    fn test_genesis_hash_is_placeholder() {
        assert_eq!(GENESIS_HASH, [0u8; 32]);
    }
}
