//! Orbinum Wallet Core - WASM Library (Clean Architecture)
//!
//! Type-safe library for interacting with Orbinum runtime using Subxt.
//! Compiles to both native Rust and WebAssembly.
//!
//! # Features
//!
//! - **Type-safe**: Generated from runtime metadata using Subxt
//! - **WASM-ready**: Works in browser, Node.js, and native Rust
//! - **Ethereum-compatible**: Uses ECDSA signatures for H160 accounts
//! - **Privacy operations**: Shield, unshield, private transfers
//! - **Conditional Crypto**: Signing available only in native builds
//!
//! # Architecture - Clean Architecture Layers
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │           WALLET CORE CLEAN ARCHITECTURE               │
//! ├────────────────────────────────────────────────────────┤
//! │  Presentation: WASM Bindings + Rust API                │
//! │  ────────────────────────────────────────────          │
//! │  Application: Transaction Builders, Signers            │
//! │  ────────────────────────────────────────────          │
//! │  Infrastructure: Crypto (ECDSA), Subxt Client          │
//! │  ────────────────────────────────────────────          │
//! │  Domain: Types, Entities, Ports (Interfaces)           │
//! └────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ## Native with Crypto (CLI, Python SDK)
//! ```rust,ignore
//! use wallet_core_wasm::SigningApi;
//!
//! // Firma directamente en Rust
//! let tx_bytes = SigningApi::sign_and_build_shield(
//!     1000,
//!     1,
//!     commitment,
//!     0,
//!     "0x1234..."
//! )?;
//! ```
//!
//! ## WASM without Crypto (Browser, TypeScript)
//! ```javascript
//! import { WasmTransactionBuilder } from '@orbinum/wallet-core-wasm';
//! import { signPayload } from '@polkadot/extension-dapp';
//!
//! // Construir sin firmar
//! const callData = WasmTransactionBuilder.buildShieldUnsigned(
//!   "1000", 1, commitment, 0
//! );
//!
//! // Firmar externamente (extensión del navegador)
//! const signature = await signPayload(callData);
//!
//! // Combinar
//! const signedTx = WasmTransactionBuilder.buildSignedExtrinsic(
//!   callData, signature, address, 0
//! );
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use ::core::fmt;
use ::core::result;
use alloc::string::String;

// Panic handler for no_std
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Global allocator for no_std (WASM will use wasm allocator)
#[cfg(all(not(feature = "std"), target_arch = "wasm32"))]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// Clean Architecture Layers
pub mod application;
pub mod domain;
pub mod infrastructure;
pub mod presentation;

// Re-exports para API pública
pub use presentation::api::*;

#[cfg(target_arch = "wasm32")]
pub use presentation::wasm_bindings::*;

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub use infrastructure::crypto::*;

// Re-export validators
pub use application::validators::TransactionValidator;

/// Result type for wallet operations
pub type Result<T> = result::Result<T, Error>;

/// Wallet errors
#[derive(Debug)]
pub enum Error {
    /// Subxt error
    Subxt(String),

    /// Hex decoding error
    HexDecode(String),

    /// Serialization error
    Serialization(String),

    /// Crypto error
    Crypto(String),

    /// Invalid input
    InvalidInput(String),

    /// RPC error
    Rpc(String),

    /// Other error
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Subxt(e) => write!(f, "Subxt error: {}", e),
            Error::HexDecode(e) => write!(f, "Hex decode error: {}", e),
            Error::Serialization(e) => write!(f, "Serialization error: {}", e),
            Error::Crypto(e) => write!(f, "Crypto error: {}", e),
            Error::InvalidInput(e) => write!(f, "Invalid input: {}", e),
            Error::Rpc(e) => write!(f, "RPC error: {}", e),
            Error::Other(e) => write!(f, "{}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
