//! Transaction Parameter Validator
//! Validates inputs for core transaction types (Shield, Unshield, Transfer)

use crate::application::errors::ValidationError;
use crate::domain::types::{Commitment, Nullifier};
use alloc::format;
use alloc::string::ToString;

/// Validator for transaction parameters
pub struct TransactionValidator;

impl TransactionValidator {
    /// Validates that an amount is non-zero and within valid range.
    pub fn validate_amount(amount: u128) -> Result<(), ValidationError> {
        if amount == 0 {
            return Err(ValidationError::AmountInvalid {
                field: "amount".to_string(),
                reason: "amount must be greater than zero".to_string(),
            });
        }

        // Check for reasonable upper bound (optional, adjust based on your chain's limits)
        const MAX_AMOUNT: u128 = u128::MAX / 2; // Half of u128::MAX as safety margin
        if amount > MAX_AMOUNT {
            return Err(ValidationError::OutOfRange {
                field: "amount".to_string(),
                min: Some(1),
                max: Some(MAX_AMOUNT),
                actual: amount,
            });
        }

        Ok(())
    }

    /// Validates that a commitment is not all zeros.
    pub fn validate_commitment(commitment: &Commitment) -> Result<(), ValidationError> {
        if commitment.as_bytes() == &[0u8; 32] {
            return Err(ValidationError::CommitmentInvalid {
                field: "commitment".to_string(),
                reason: "commitment cannot be all zeros".to_string(),
            });
        }
        Ok(())
    }

    /// Validates that a nullifier is not all zeros.
    pub fn validate_nullifier(nullifier: &Nullifier) -> Result<(), ValidationError> {
        if nullifier.as_bytes() == &[0u8; 32] {
            return Err(ValidationError::NullifierInvalid {
                field: "nullifier".to_string(),
                reason: "nullifier cannot be all zeros".to_string(),
            });
        }
        Ok(())
    }

    /// Validates that nullifiers in an array are unique.
    pub fn validate_nullifiers_unique(nullifiers: &[Nullifier]) -> Result<(), ValidationError> {
        for i in 0..nullifiers.len() {
            for j in (i + 1)..nullifiers.len() {
                if nullifiers[i].as_bytes() == nullifiers[j].as_bytes() {
                    return Err(ValidationError::DuplicateValue {
                        field: "nullifiers".to_string(),
                        reason: format!("duplicate nullifier at indices {} and {}", i, j),
                    });
                }
            }
        }
        Ok(())
    }

    /// Validates proof length.
    ///
    /// Typical Groth16 proofs are 192 bytes. Adjust constants for your ZK system.
    pub fn validate_proof_length(proof: &[u8]) -> Result<(), ValidationError> {
        // Typical Groth16 proofs are around 192 bytes (3 * 64 bytes for G1/G2 points)
        // Adjust these constants based on your actual ZK system
        const MIN_PROOF_LENGTH: usize = 64;
        const MAX_PROOF_LENGTH: usize = 512;

        if proof.is_empty() {
            return Err(ValidationError::ProofInvalid {
                field: "proof".to_string(),
                reason: "proof cannot be empty".to_string(),
            });
        }

        if proof.len() < MIN_PROOF_LENGTH || proof.len() > MAX_PROOF_LENGTH {
            return Err(ValidationError::ProofInvalid {
                field: "proof".to_string(),
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

    /// Validates encrypted memo length and format.
    pub fn validate_encrypted_memo(memo: &[u8]) -> Result<(), ValidationError> {
        // Encrypted memos typically have a minimum size due to encryption overhead
        const MIN_MEMO_LENGTH: usize = 32; // e.g., nonce + minimal ciphertext
        const MAX_MEMO_LENGTH: usize = 1024; // Adjust based on your system

        if memo.is_empty() {
            // Empty memos might be allowed depending on your system
            return Ok(());
        }

        if memo.len() < MIN_MEMO_LENGTH {
            return Err(ValidationError::MemoInvalid {
                field: "encrypted_memo".to_string(),
                reason: format!(
                    "encrypted memo too short, minimum {} bytes, got {}",
                    MIN_MEMO_LENGTH,
                    memo.len()
                ),
            });
        }

        if memo.len() > MAX_MEMO_LENGTH {
            return Err(ValidationError::MemoInvalid {
                field: "encrypted_memo".to_string(),
                reason: format!(
                    "encrypted memo too long, maximum {} bytes, got {}",
                    MAX_MEMO_LENGTH,
                    memo.len()
                ),
            });
        }

        Ok(())
    }

    /// Validates all parameters for a Shield transaction
    ///
    /// # Arguments
    /// * `amount` - Transaction amount
    /// * `commitment` - Note commitment
    /// * `encrypted_memo` - Encrypted memo
    ///
    /// # Returns
    /// `Ok(())` if all valid, first `ValidationError` otherwise
    pub fn validate_shield_params(
        amount: u128,
        commitment: &Commitment,
        encrypted_memo: &[u8],
    ) -> Result<(), ValidationError> {
        Self::validate_amount(amount)?;
        Self::validate_commitment(commitment)?;
        Self::validate_encrypted_memo(encrypted_memo)?;
        Ok(())
    }

    /// Validates all parameters for an Unshield transaction
    ///
    /// # Arguments
    /// * `nullifier` - Note nullifier being spent
    /// * `amount` - Withdrawal amount
    /// * `proof` - ZK proof
    ///
    /// # Returns
    /// `Ok(())` if all valid, first `ValidationError` otherwise
    pub fn validate_unshield_params(
        nullifier: &Nullifier,
        amount: u128,
        proof: &[u8],
    ) -> Result<(), ValidationError> {
        Self::validate_nullifier(nullifier)?;
        Self::validate_amount(amount)?;
        Self::validate_proof_length(proof)?;
        Ok(())
    }

    /// Validates all parameters for a Transfer transaction
    ///
    /// # Arguments
    /// * `input_nullifiers` - Nullifiers of notes being spent
    /// * `output_commitments` - Commitments of new notes being created
    /// * `proof` - ZK proof
    ///
    /// # Returns
    /// `Ok(())` if all valid, first `ValidationError` otherwise
    pub fn validate_transfer_params(
        input_nullifiers: &[Nullifier],
        output_commitments: &[Commitment],
        proof: &[u8],
    ) -> Result<(), ValidationError> {
        // Validate each nullifier
        for (i, nullifier) in input_nullifiers.iter().enumerate() {
            Self::validate_nullifier(nullifier).map_err(|_| ValidationError::NullifierInvalid {
                field: format!("input_nullifiers[{}]", i),
                reason: "invalid nullifier".to_string(),
            })?;
        }

        // Check for duplicate nullifiers
        Self::validate_nullifiers_unique(input_nullifiers)?;

        // Validate each commitment
        for (i, commitment) in output_commitments.iter().enumerate() {
            Self::validate_commitment(commitment).map_err(|_| {
                ValidationError::CommitmentInvalid {
                    field: format!("output_commitments[{}]", i),
                    reason: "invalid commitment".to_string(),
                }
            })?;
        }

        // Validate proof
        Self::validate_proof_length(proof)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_amount_success() {
        assert!(TransactionValidator::validate_amount(1).is_ok());
        assert!(TransactionValidator::validate_amount(1000).is_ok());
        assert!(TransactionValidator::validate_amount(u128::MAX / 4).is_ok());
    }

    #[test]
    fn test_validate_amount_zero() {
        let result = TransactionValidator::validate_amount(0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::AmountInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_commitment_success() {
        let commitment = Commitment::from_bytes_unchecked([1u8; 32]);
        assert!(TransactionValidator::validate_commitment(&commitment).is_ok());
    }

    #[test]
    fn test_validate_commitment_all_zeros() {
        let commitment = Commitment::from_bytes_unchecked([0u8; 32]);
        let result = TransactionValidator::validate_commitment(&commitment);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::CommitmentInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_nullifier_success() {
        let nullifier = Nullifier::from_bytes_unchecked([2u8; 32]);
        assert!(TransactionValidator::validate_nullifier(&nullifier).is_ok());
    }

    #[test]
    fn test_validate_nullifier_all_zeros() {
        let nullifier = Nullifier::from_bytes_unchecked([0u8; 32]);
        let result = TransactionValidator::validate_nullifier(&nullifier);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::NullifierInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_nullifiers_unique_success() {
        let nullifiers = vec![
            Nullifier::from_bytes_unchecked([1u8; 32]),
            Nullifier::from_bytes_unchecked([2u8; 32]),
            Nullifier::from_bytes_unchecked([3u8; 32]),
        ];
        assert!(TransactionValidator::validate_nullifiers_unique(&nullifiers).is_ok());
    }

    #[test]
    fn test_validate_nullifiers_duplicate() {
        let nullifiers = vec![
            Nullifier::from_bytes_unchecked([1u8; 32]),
            Nullifier::from_bytes_unchecked([2u8; 32]),
            Nullifier::from_bytes_unchecked([1u8; 32]), // duplicate
        ];
        let result = TransactionValidator::validate_nullifiers_unique(&nullifiers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::DuplicateValue { .. }
        ));
    }

    #[test]
    fn test_validate_proof_length_success() {
        let proof = vec![0u8; 192]; // Typical Groth16 proof size
        assert!(TransactionValidator::validate_proof_length(&proof).is_ok());
    }

    #[test]
    fn test_validate_proof_length_too_short() {
        let proof = vec![0u8; 32]; // Too short
        let result = TransactionValidator::validate_proof_length(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_proof_length_empty() {
        let proof: Vec<u8> = vec![];
        let result = TransactionValidator::validate_proof_length(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_proof_length_too_long() {
        let proof = vec![0u8; 513];
        let result = TransactionValidator::validate_proof_length(&proof);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::ProofInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_amount_out_of_range() {
        let amount = (u128::MAX / 2) + 1;
        let result = TransactionValidator::validate_amount(amount);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::OutOfRange { .. }
        ));
    }

    #[test]
    fn test_validate_encrypted_memo_empty_is_allowed() {
        let memo: Vec<u8> = vec![];
        assert!(TransactionValidator::validate_encrypted_memo(&memo).is_ok());
    }

    #[test]
    fn test_validate_encrypted_memo_too_short() {
        let memo = vec![1u8; 16];
        let result = TransactionValidator::validate_encrypted_memo(&memo);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MemoInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_encrypted_memo_too_long() {
        let memo = vec![1u8; 1025];
        let result = TransactionValidator::validate_encrypted_memo(&memo);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MemoInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_shield_params_success() {
        let commitment = Commitment::from_bytes_unchecked([9u8; 32]);
        let memo = vec![1u8; 64];
        let result = TransactionValidator::validate_shield_params(100, &commitment, &memo);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_shield_params_fail_on_invalid_memo() {
        let commitment = Commitment::from_bytes_unchecked([9u8; 32]);
        let memo = vec![1u8; 8];
        let result = TransactionValidator::validate_shield_params(100, &commitment, &memo);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MemoInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_unshield_params_success() {
        let nullifier = Nullifier::from_bytes_unchecked([3u8; 32]);
        let proof = vec![0u8; 192];
        let result = TransactionValidator::validate_unshield_params(&nullifier, 50, &proof);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_unshield_params_fail_on_invalid_nullifier() {
        let nullifier = Nullifier::from_bytes_unchecked([0u8; 32]);
        let proof = vec![0u8; 192];
        let result = TransactionValidator::validate_unshield_params(&nullifier, 50, &proof);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::NullifierInvalid { .. }
        ));
    }

    #[test]
    fn test_validate_transfer_params_success() {
        let input_nullifiers = vec![
            Nullifier::from_bytes_unchecked([1u8; 32]),
            Nullifier::from_bytes_unchecked([2u8; 32]),
        ];
        let output_commitments = vec![
            Commitment::from_bytes_unchecked([3u8; 32]),
            Commitment::from_bytes_unchecked([4u8; 32]),
        ];
        let proof = vec![0u8; 192];

        let result = TransactionValidator::validate_transfer_params(
            &input_nullifiers,
            &output_commitments,
            &proof,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_transfer_params_fail_on_duplicate_nullifier() {
        let input_nullifiers = vec![
            Nullifier::from_bytes_unchecked([1u8; 32]),
            Nullifier::from_bytes_unchecked([1u8; 32]),
        ];
        let output_commitments = vec![
            Commitment::from_bytes_unchecked([3u8; 32]),
            Commitment::from_bytes_unchecked([4u8; 32]),
        ];
        let proof = vec![0u8; 192];

        let result = TransactionValidator::validate_transfer_params(
            &input_nullifiers,
            &output_commitments,
            &proof,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::DuplicateValue { .. }
        ));
    }
}
