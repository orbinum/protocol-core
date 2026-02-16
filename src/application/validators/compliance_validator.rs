//! Compliance Parameter Validator
//! Validates inputs for compliance and disclosure transactions

use crate::application::errors::ValidationError;
use crate::application::params::{AuditorInfo, DisclosureConditionType};
use crate::domain::types::Address;

/// Validator for compliance-related parameters
pub struct ComplianceValidator;

impl ComplianceValidator {
    /// Validates a list of auditors.
    ///
    /// Checks: at least one auditor, max 100 auditors, no duplicate addresses.
    pub fn validate_auditor_list(auditors: &[AuditorInfo]) -> Result<(), ValidationError> {
        const MAX_AUDITORS: usize = 100;

        if auditors.is_empty() {
            return Err(ValidationError::MissingField {
                field: "auditors".to_string(),
            });
        }

        if auditors.len() > MAX_AUDITORS {
            return Err(ValidationError::OutOfRange {
                field: "auditors".to_string(),
                min: Some(1),
                max: Some(MAX_AUDITORS as u128),
                actual: auditors.len() as u128,
            });
        }

        // Check for duplicate auditor addresses
        for i in 0..auditors.len() {
            for j in (i + 1)..auditors.len() {
                if auditors[i].account.as_bytes() == auditors[j].account.as_bytes() {
                    return Err(ValidationError::DuplicateValue {
                        field: "auditors".to_string(),
                        reason: format!("duplicate auditor address at indices {} and {}", i, j),
                    });
                }
            }
        }

        // Validate each auditor
        for (i, auditor) in auditors.iter().enumerate() {
            Self::validate_auditor(auditor).map_err(|e| {
                ValidationError::Other(format!("auditor[{}] validation failed: {}", i, e))
            })?;
        }

        Ok(())
    }

    /// Validates a single auditor.
    pub fn validate_auditor(auditor: &AuditorInfo) -> Result<(), ValidationError> {
        // Validate address is not all zeros
        if auditor.account.as_bytes() == &[0u8; 20] {
            return Err(ValidationError::AddressInvalid {
                field: "auditor.account".to_string(),
                reason: "address cannot be all zeros".to_string(),
            });
        }

        // If public key is provided, validate it's not all zeros
        if let Some(pubkey) = auditor.public_key {
            if pubkey == [0u8; 32] {
                return Err(ValidationError::Other(
                    "auditor public key cannot be all zeros".to_string(),
                ));
            }
        }

        // authorized_from should be reasonable (not in distant future)
        // This is a sanity check - adjust based on your chain's block number system
        const MAX_REASONABLE_BLOCK: u32 = u32::MAX / 2;
        if auditor.authorized_from > MAX_REASONABLE_BLOCK {
            return Err(ValidationError::OutOfRange {
                field: "auditor.authorized_from".to_string(),
                min: Some(0),
                max: Some(MAX_REASONABLE_BLOCK as u128),
                actual: auditor.authorized_from as u128,
            });
        }

        Ok(())
    }

    /// Validates disclosure conditions
    ///
    /// # Arguments
    /// * `conditions` - List of disclosure conditions to validate
    ///
    /// # Returns
    /// `Ok(())` if valid, `ValidationError` otherwise
    pub fn validate_disclosure_conditions(
        conditions: &[DisclosureConditionType],
    ) -> Result<(), ValidationError> {
        const MAX_CONDITIONS: usize = 50;

        if conditions.is_empty() {
            return Err(ValidationError::MissingField {
                field: "conditions".to_string(),
            });
        }

        if conditions.len() > MAX_CONDITIONS {
            return Err(ValidationError::OutOfRange {
                field: "conditions".to_string(),
                min: Some(1),
                max: Some(MAX_CONDITIONS as u128),
                actual: conditions.len() as u128,
            });
        }

        // Validate each condition
        for (i, condition) in conditions.iter().enumerate() {
            Self::validate_disclosure_condition(condition).map_err(|e| {
                ValidationError::Other(format!("condition[{}] validation failed: {}", i, e))
            })?;
        }

        Ok(())
    }

    /// Validates a single disclosure condition
    ///
    /// # Arguments
    /// * `condition` - Disclosure condition to validate
    ///
    /// # Returns
    /// `Ok(())` if valid, `ValidationError` otherwise
    pub fn validate_disclosure_condition(
        condition: &DisclosureConditionType,
    ) -> Result<(), ValidationError> {
        match condition {
            DisclosureConditionType::AmountAbove(amount) => {
                if *amount == 0 {
                    return Err(ValidationError::AmountInvalid {
                        field: "condition.amount_above".to_string(),
                        reason: "amount threshold must be greater than zero".to_string(),
                    });
                }
            }
            DisclosureConditionType::TimeElapsed(blocks) => {
                if *blocks == 0 {
                    return Err(ValidationError::Other(
                        "time elapsed threshold must be greater than zero".to_string(),
                    ));
                }
            }
            DisclosureConditionType::ManualApproval => {
                // No additional validation needed
            }
        }

        Ok(())
    }

    /// Validates a ZK proof for disclosure
    ///
    /// # Arguments
    /// * `proof` - ZK proof bytes to validate
    ///
    /// # Returns
    /// `Ok(())` if valid, `ValidationError` otherwise
    pub fn validate_zk_proof(proof: &[u8]) -> Result<(), ValidationError> {
        // Similar to transaction validator, but might have different length requirements
        const MIN_PROOF_LENGTH: usize = 64;
        const MAX_PROOF_LENGTH: usize = 1024;

        if proof.is_empty() {
            return Err(ValidationError::ProofInvalid {
                field: "zk_proof".to_string(),
                reason: "proof cannot be empty".to_string(),
            });
        }

        if proof.len() < MIN_PROOF_LENGTH || proof.len() > MAX_PROOF_LENGTH {
            return Err(ValidationError::ProofInvalid {
                field: "zk_proof".to_string(),
                reason: format!(
                    "proof length must be between {} and {} bytes, got {}",
                    MIN_PROOF_LENGTH,
                    MAX_PROOF_LENGTH,
                    proof.len()
                ),
            });
        }

        Ok(())
    }

    /// Validates disclosed data
    ///
    /// # Arguments
    /// * `disclosed_data` - Data being disclosed
    ///
    /// # Returns
    /// `Ok(())` if valid, `ValidationError` otherwise
    pub fn validate_disclosed_data(disclosed_data: &[u8]) -> Result<(), ValidationError> {
        const MAX_DISCLOSED_DATA_LENGTH: usize = 2048;

        if disclosed_data.is_empty() {
            return Err(ValidationError::Other(
                "disclosed data cannot be empty".to_string(),
            ));
        }

        if disclosed_data.len() > MAX_DISCLOSED_DATA_LENGTH {
            return Err(ValidationError::Other(format!(
                "disclosed data too large, maximum {} bytes, got {}",
                MAX_DISCLOSED_DATA_LENGTH,
                disclosed_data.len()
            )));
        }

        Ok(())
    }

    /// Validates reason field (for request/reject disclosure)
    ///
    /// # Arguments
    /// * `reason` - Reason text
    ///
    /// # Returns
    /// `Ok(())` if valid, `ValidationError` otherwise
    pub fn validate_reason(reason: &[u8]) -> Result<(), ValidationError> {
        const MIN_REASON_LENGTH: usize = 10; // At least 10 chars for meaningful reason
        const MAX_REASON_LENGTH: usize = 1024;

        if reason.is_empty() {
            return Err(ValidationError::MissingField {
                field: "reason".to_string(),
            });
        }

        if reason.len() < MIN_REASON_LENGTH {
            return Err(ValidationError::Other(format!(
                "reason too short, minimum {} bytes, got {}",
                MIN_REASON_LENGTH,
                reason.len()
            )));
        }

        if reason.len() > MAX_REASON_LENGTH {
            return Err(ValidationError::Other(format!(
                "reason too long, maximum {} bytes, got {}",
                MAX_REASON_LENGTH,
                reason.len()
            )));
        }

        Ok(())
    }

    /// Validates target address for disclosure request
    ///
    /// # Arguments
    /// * `target` - Target address
    ///
    /// # Returns
    /// `Ok(())` if valid, `ValidationError` otherwise
    pub fn validate_target_address(target: &Address) -> Result<(), ValidationError> {
        if target.as_bytes() == &[0u8; 20] {
            return Err(ValidationError::AddressInvalid {
                field: "target".to_string(),
                reason: "target address cannot be all zeros".to_string(),
            });
        }
        Ok(())
    }

    /// Validates max_frequency parameter for audit policy
    ///
    /// # Arguments
    /// * `max_frequency` - Maximum frequency value (optional)
    ///
    /// # Returns
    /// `Ok(())` if valid, `ValidationError` otherwise
    pub fn validate_max_frequency(max_frequency: Option<u32>) -> Result<(), ValidationError> {
        if let Some(freq) = max_frequency {
            if freq == 0 {
                return Err(ValidationError::Other(
                    "max_frequency must be greater than zero if provided".to_string(),
                ));
            }

            // Sanity check: not more than once per second for a year
            const MAX_FREQUENCY: u32 = 31_536_000; // seconds in a year
            if freq > MAX_FREQUENCY {
                return Err(ValidationError::OutOfRange {
                    field: "max_frequency".to_string(),
                    min: Some(1),
                    max: Some(MAX_FREQUENCY as u128),
                    actual: freq as u128,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_auditor() -> AuditorInfo {
        AuditorInfo {
            account: Address::from_slice_unchecked(&[1u8; 20]),
            public_key: Some([2u8; 32]),
            authorized_from: 100,
        }
    }

    #[test]
    fn test_validate_auditor_success() {
        let auditor = create_valid_auditor();
        assert!(ComplianceValidator::validate_auditor(&auditor).is_ok());
    }

    #[test]
    fn test_validate_auditor_zero_address() {
        let mut auditor = create_valid_auditor();
        auditor.account = Address::from_slice_unchecked(&[0u8; 20]);
        let result = ComplianceValidator::validate_auditor(&auditor);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auditor_list_success() {
        let auditors = vec![
            create_valid_auditor(),
            AuditorInfo {
                account: Address::from_slice_unchecked(&[2u8; 20]),
                public_key: None,
                authorized_from: 200,
            },
        ];
        assert!(ComplianceValidator::validate_auditor_list(&auditors).is_ok());
    }

    #[test]
    fn test_validate_auditor_list_empty() {
        let auditors: Vec<AuditorInfo> = vec![];
        let result = ComplianceValidator::validate_auditor_list(&auditors);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MissingField { .. }
        ));
    }

    #[test]
    fn test_validate_auditor_list_duplicate() {
        let auditor = create_valid_auditor();
        let auditors = vec![auditor.clone(), auditor.clone()];
        let result = ComplianceValidator::validate_auditor_list(&auditors);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::DuplicateValue { .. }
        ));
    }

    #[test]
    fn test_validate_disclosure_condition_amount_above() {
        let condition = DisclosureConditionType::AmountAbove(1000);
        assert!(ComplianceValidator::validate_disclosure_condition(&condition).is_ok());

        let invalid = DisclosureConditionType::AmountAbove(0);
        assert!(ComplianceValidator::validate_disclosure_condition(&invalid).is_err());
    }

    #[test]
    fn test_validate_disclosure_conditions_success() {
        let conditions = vec![
            DisclosureConditionType::AmountAbove(1000),
            DisclosureConditionType::TimeElapsed(100),
            DisclosureConditionType::ManualApproval,
        ];
        assert!(ComplianceValidator::validate_disclosure_conditions(&conditions).is_ok());
    }

    #[test]
    fn test_validate_zk_proof_success() {
        let proof = vec![0u8; 192];
        assert!(ComplianceValidator::validate_zk_proof(&proof).is_ok());
    }

    #[test]
    fn test_validate_zk_proof_empty() {
        let proof: Vec<u8> = vec![];
        assert!(ComplianceValidator::validate_zk_proof(&proof).is_err());
    }

    #[test]
    fn test_validate_reason_success() {
        let reason = b"Valid reason for disclosure request";
        assert!(ComplianceValidator::validate_reason(reason).is_ok());
    }

    #[test]
    fn test_validate_reason_too_short() {
        let reason = b"Short";
        let result = ComplianceValidator::validate_reason(reason);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_max_frequency_success() {
        assert!(ComplianceValidator::validate_max_frequency(Some(100)).is_ok());
        assert!(ComplianceValidator::validate_max_frequency(None).is_ok());
    }

    #[test]
    fn test_validate_max_frequency_zero() {
        let result = ComplianceValidator::validate_max_frequency(Some(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auditor_zero_pubkey() {
        let mut auditor = create_valid_auditor();
        auditor.public_key = Some([0u8; 32]);
        let result = ComplianceValidator::validate_auditor(&auditor);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_auditor_authorized_from_out_of_range() {
        let mut auditor = create_valid_auditor();
        auditor.authorized_from = (u32::MAX / 2) + 1;
        let result = ComplianceValidator::validate_auditor(&auditor);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::OutOfRange { .. }
        ));
    }

    #[test]
    fn test_validate_auditor_list_too_many() {
        let mut auditors = Vec::new();
        for i in 0..101u8 {
            let mut bytes = [0u8; 20];
            bytes[0] = i.saturating_add(1);
            auditors.push(AuditorInfo {
                account: Address::from_slice_unchecked(&bytes),
                public_key: None,
                authorized_from: 1,
            });
        }

        let result = ComplianceValidator::validate_auditor_list(&auditors);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::OutOfRange { .. }
        ));
    }

    #[test]
    fn test_validate_disclosure_condition_time_elapsed_zero() {
        let condition = DisclosureConditionType::TimeElapsed(0);
        let result = ComplianceValidator::validate_disclosure_condition(&condition);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_disclosure_condition_manual_approval_success() {
        let condition = DisclosureConditionType::ManualApproval;
        assert!(ComplianceValidator::validate_disclosure_condition(&condition).is_ok());
    }

    #[test]
    fn test_validate_disclosure_conditions_empty() {
        let conditions: Vec<DisclosureConditionType> = vec![];
        let result = ComplianceValidator::validate_disclosure_conditions(&conditions);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MissingField { .. }
        ));
    }

    #[test]
    fn test_validate_disclosure_conditions_too_many() {
        let conditions = vec![DisclosureConditionType::ManualApproval; 51];
        let result = ComplianceValidator::validate_disclosure_conditions(&conditions);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::OutOfRange { .. }
        ));
    }

    #[test]
    fn test_validate_zk_proof_too_short() {
        let proof = vec![0u8; 16];
        let result = ComplianceValidator::validate_zk_proof(&proof);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::ProofInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_zk_proof_too_long() {
        let proof = vec![0u8; 2048];
        let result = ComplianceValidator::validate_zk_proof(&proof);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::ProofInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_disclosed_data_success() {
        let data = vec![1u8; 32];
        assert!(ComplianceValidator::validate_disclosed_data(&data).is_ok());
    }

    #[test]
    fn test_validate_disclosed_data_empty() {
        let data: Vec<u8> = vec![];
        let result = ComplianceValidator::validate_disclosed_data(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_disclosed_data_too_large() {
        let data = vec![1u8; 2049];
        let result = ComplianceValidator::validate_disclosed_data(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_reason_empty() {
        let reason: Vec<u8> = vec![];
        let result = ComplianceValidator::validate_reason(&reason);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MissingField { .. }
        ));
    }

    #[test]
    fn test_validate_reason_too_long() {
        let reason = vec![b'a'; 1025];
        let result = ComplianceValidator::validate_reason(&reason);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_target_address_success() {
        let target = Address::from_slice_unchecked(&[9u8; 20]);
        assert!(ComplianceValidator::validate_target_address(&target).is_ok());
    }

    #[test]
    fn test_validate_target_address_zero() {
        let target = Address::from_slice_unchecked(&[0u8; 20]);
        let result = ComplianceValidator::validate_target_address(&target);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::AddressInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_max_frequency_too_large() {
        let result = ComplianceValidator::validate_max_frequency(Some(31_536_001));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::OutOfRange { .. }
        ));
    }
}
