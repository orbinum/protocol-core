//! Application Layer Errors
//!
//! Unified error types for transaction building and signing operations.

extern crate alloc;
use alloc::string::{String, ToString};
use core::fmt;

// Builder Errors

/// Errors that can occur during transaction building
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// Invalid amount provided (e.g., zero or exceeds limits)
    InvalidAmount(String),

    /// Invalid commitment provided (e.g., all zeros)
    InvalidCommitment(String),

    /// Invalid nullifier provided (e.g., all zeros or duplicate)
    InvalidNullifier(String),

    /// Invalid address provided (e.g., wrong length)
    InvalidAddress(String),

    /// Invalid proof provided (e.g., wrong length or format)
    InvalidProof(String),

    /// Encoding failed during call data construction
    EncodingFailed(String),

    /// Validation failed for transaction parameters
    ValidationFailed(String),

    /// Invalid encrypted memo
    InvalidMemo(String),

    /// Generic builder error with custom message
    Other(String),
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuilderError::InvalidAmount(msg) => write!(f, "Invalid amount: {}", msg),
            BuilderError::InvalidCommitment(msg) => write!(f, "Invalid commitment: {}", msg),
            BuilderError::InvalidNullifier(msg) => write!(f, "Invalid nullifier: {}", msg),
            BuilderError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            BuilderError::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            BuilderError::EncodingFailed(msg) => write!(f, "Encoding failed: {}", msg),
            BuilderError::ValidationFailed(msg) => write!(f, "Validation failed: {}", msg),
            BuilderError::InvalidMemo(msg) => write!(f, "Invalid memo: {}", msg),
            BuilderError::Other(msg) => write!(f, "Builder error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuilderError {}

// Signer Errors

/// Errors that can occur during transaction signing
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// Invalid private key format or value
    InvalidPrivateKey(String),

    /// Signature generation failed
    SignatureFailed(String),

    /// Invalid address derived from key
    InvalidAddress(String),

    /// Builder error occurred during transaction construction
    BuilderError(BuilderError),

    /// Invalid signer configuration
    InvalidConfiguration(String),

    /// Generic signer error with custom message
    Other(String),
}

#[cfg(feature = "crypto")]
impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignerError::InvalidPrivateKey(msg) => write!(f, "Invalid private key: {}", msg),
            SignerError::SignatureFailed(msg) => write!(f, "Signature failed: {}", msg),
            SignerError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            SignerError::BuilderError(err) => write!(f, "Builder error: {}", err),
            SignerError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            SignerError::Other(msg) => write!(f, "Signer error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(feature = "crypto")]
impl std::error::Error for SignerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignerError::BuilderError(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(feature = "crypto")]
impl From<BuilderError> for SignerError {
    fn from(err: BuilderError) -> Self {
        SignerError::BuilderError(err)
    }
}

#[cfg(feature = "crypto")]
impl From<crate::domain::ports::SignerError> for SignerError {
    fn from(err: crate::domain::ports::SignerError) -> Self {
        match err {
            crate::domain::ports::SignerError::InvalidKey => {
                SignerError::InvalidPrivateKey("Invalid key".into())
            }
            crate::domain::ports::SignerError::SigningFailed => {
                SignerError::SignatureFailed("Signing failed".into())
            }
            crate::domain::ports::SignerError::InvalidMessage => {
                SignerError::SignatureFailed("Invalid message".into())
            }
        }
    }
}

// ============================================================================
// Validation Errors
// ============================================================================

/// Errors that can occur during input validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Amount validation failed
    AmountInvalid { field: String, reason: String },

    /// Commitment validation failed
    CommitmentInvalid { field: String, reason: String },

    /// Nullifier validation failed
    NullifierInvalid { field: String, reason: String },

    /// Address validation failed
    AddressInvalid { field: String, reason: String },

    /// Proof validation failed
    ProofInvalid { field: String, reason: String },

    /// Memo validation failed
    MemoInvalid { field: String, reason: String },

    /// Duplicate values found
    DuplicateValue { field: String, reason: String },

    /// Required field is missing
    MissingField { field: String },

    /// Field value out of allowed range
    OutOfRange {
        field: String,
        min: Option<u128>,
        max: Option<u128>,
        actual: u128,
    },

    /// Generic validation error
    Other(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::AmountInvalid { field, reason } => {
                write!(f, "Invalid amount in '{}': {}", field, reason)
            }
            ValidationError::CommitmentInvalid { field, reason } => {
                write!(f, "Invalid commitment in '{}': {}", field, reason)
            }
            ValidationError::NullifierInvalid { field, reason } => {
                write!(f, "Invalid nullifier in '{}': {}", field, reason)
            }
            ValidationError::AddressInvalid { field, reason } => {
                write!(f, "Invalid address in '{}': {}", field, reason)
            }
            ValidationError::ProofInvalid { field, reason } => {
                write!(f, "Invalid proof in '{}': {}", field, reason)
            }
            ValidationError::MemoInvalid { field, reason } => {
                write!(f, "Invalid memo in '{}': {}", field, reason)
            }
            ValidationError::DuplicateValue { field, reason } => {
                write!(f, "Duplicate value in '{}': {}", field, reason)
            }
            ValidationError::MissingField { field } => {
                write!(f, "Missing required field: '{}'", field)
            }
            ValidationError::OutOfRange {
                field,
                min,
                max,
                actual,
            } => {
                let min_str = min
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let max_str = max
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string());
                write!(
                    f,
                    "Value in '{}' out of range [min: {}, max: {}], actual: {}",
                    field, min_str, max_str, actual
                )
            }
            ValidationError::Other(msg) => write!(f, "Validation error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {}

impl From<ValidationError> for BuilderError {
    fn from(err: ValidationError) -> Self {
        BuilderError::ValidationFailed(err.to_string())
    }
}

#[cfg(feature = "crypto")]
impl From<ValidationError> for SignerError {
    fn from(err: ValidationError) -> Self {
        SignerError::BuilderError(BuilderError::ValidationFailed(err.to_string()))
    }
}

// ============================================================================
// Helper Macros
// ============================================================================

/// Helper macro to create BuilderError::InvalidAmount
#[macro_export]
macro_rules! invalid_amount {
    ($msg:expr) => {
        $crate::application::errors::BuilderError::InvalidAmount($msg.into())
    };
}

/// Helper macro to create BuilderError::InvalidCommitment
#[macro_export]
macro_rules! invalid_commitment {
    ($msg:expr) => {
        $crate::application::errors::BuilderError::InvalidCommitment($msg.into())
    };
}

/// Helper macro to create BuilderError::InvalidNullifier
#[macro_export]
macro_rules! invalid_nullifier {
    ($msg:expr) => {
        $crate::application::errors::BuilderError::InvalidNullifier($msg.into())
    };
}

/// Helper macro to create ValidationError with field info
#[macro_export]
macro_rules! validation_error {
    ($variant:ident, $field:expr, $reason:expr) => {
        $crate::application::errors::ValidationError::$variant {
            field: $field.into(),
            reason: $reason.into(),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_error_display() {
        let err = BuilderError::InvalidAmount("amount is zero".to_string());
        assert_eq!(err.to_string(), "Invalid amount: amount is zero");
    }

    #[test]
    fn test_validation_error_to_builder_error() {
        let val_err = ValidationError::AmountInvalid {
            field: "amount".to_string(),
            reason: "must be positive".to_string(),
        };
        let builder_err: BuilderError = val_err.into();
        assert!(matches!(builder_err, BuilderError::ValidationFailed(_)));
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_builder_error_to_signer_error() {
        let builder_err = BuilderError::InvalidCommitment("invalid".to_string());
        let signer_err: SignerError = builder_err.into();
        assert!(matches!(signer_err, SignerError::BuilderError(_)));
    }

    #[test]
    fn test_validation_error_out_of_range() {
        let err = ValidationError::OutOfRange {
            field: "amount".to_string(),
            min: Some(1),
            max: Some(1000),
            actual: 2000,
        };
        let display = err.to_string();
        assert!(display.contains("out of range"));
        assert!(display.contains("2000"));
    }
}
