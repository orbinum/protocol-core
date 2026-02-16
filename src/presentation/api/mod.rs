//! Presentation API Module
//!
//! Public APIs for building and signing transactions:
//! - TransactionApi: unsigned transactions (always available)
//! - SigningApi: signed transactions (requires "crypto" feature)

pub mod batch;
pub mod compliance;
pub mod core;
pub mod extrinsic;

#[cfg(feature = "crypto")]
pub mod signing;

// Re-export main API structs
pub use core::TransactionApi;
#[cfg(feature = "crypto")]
pub use signing::SigningApi;
