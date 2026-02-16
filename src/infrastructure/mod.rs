//! Infrastructure Layer
//!
//! Technical implementations of domain ports and serialization.
//! Modules organized by responsibility:
//! - Foundation: codec, serde_adapters
//! - High-level: serializers
//! - Optional: crypto, subxt_client

// Foundation Layer (always available)
pub mod codec;
pub mod serde_adapters;

// High-level serialization
pub mod serializers;

pub use codec::*;
pub use serializers::*;

// Optional Features
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub mod crypto;

#[cfg(feature = "subxt")]
pub mod subxt_client;

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub use crypto::*;

#[cfg(feature = "subxt")]
pub use subxt_client::*;
