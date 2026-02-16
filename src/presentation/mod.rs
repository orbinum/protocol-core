//! Presentation Layer
//!
//! Public APIs for transaction building and WASM bindings.
//! Modules organized by responsibility:
//! - Foundation: config, zk_models
//! - APIs: api (core, batch, compliance, signing)
//! - Optional: crypto_api, wasm_bindings

// Foundation Layer
pub mod config;
pub mod zk_models;

// API Layer
pub mod api;

// Optional Features
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub mod crypto_api;

#[cfg(target_arch = "wasm32")]
pub mod wasm_bindings;

// Re-exports
pub use api::*;
pub use config::*;
pub use zk_models::*;

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub use crypto_api::*;
