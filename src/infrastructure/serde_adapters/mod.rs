//! Serde Serialization Support
//!
//! This module provides Serialize/Deserialize implementations as adapters
//! to keep domain types free from serialization framework dependencies.
//!
//! Organized by type categories:
//! - **primitives**: Address, Hash
//! - **crypto**: Commitment, Nullifier
//! - **collections**: Arrays, Options, Vecs

pub mod collections;
pub mod crypto;
pub mod primitives;

// Re-export all commonly used helpers for backward compatibility
pub use collections::{commitment_array, nullifier_array, option_address};
pub use crypto::{commitment, nullifier};
pub use primitives::{address, hash};
