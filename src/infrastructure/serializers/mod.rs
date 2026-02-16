//! Infrastructure Serializers Module
//!
//! Logic to build call data and serialize transactions.
//! Organized by responsibility:
//! - **core**: Basic SCALE encoding and transaction serialization
//! - **extrinsic**: Complete extrinsic serialization
//! - **adapters**: Port adapters for application layer integration

pub mod adapters;
pub mod core;
pub mod extrinsic;

// Re-export commonly used types
pub use adapters::SubstrateTransactionEncoder;
pub use core::CallDataBuilder;

// Re-export serialization function for backward compatibility
pub use core::serialize_signed_transaction;

pub const SHIELDED_POOL_PALLET_INDEX: u8 = 50;
