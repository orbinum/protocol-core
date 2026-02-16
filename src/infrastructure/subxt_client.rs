//! Subxt client configuration (requires "subxt" feature)

#[cfg(feature = "subxt")]
use subxt::config::{Config, DefaultExtrinsicParams};
#[cfg(feature = "subxt")]
use subxt::utils::{MultiSignature, H160 as SubxtH160, H256 as SubxtH256};

/// Orbinum configuration for Subxt (Frontier-compatible).
///
/// Uses Subxt types exclusively without sp-* dependencies.
#[cfg(feature = "subxt")]
pub enum OrbinumConfig {}

#[cfg(feature = "subxt")]
impl Config for OrbinumConfig {
    type Hash = SubxtH256;
    type AccountId = SubxtH160;
    type Address = subxt::utils::MultiAddress<Self::AccountId, ()>;
    type Signature = MultiSignature;
    type Hasher = subxt::config::substrate::BlakeTwo256;
    type Header = subxt::config::substrate::SubstrateHeader<u32, Self::Hasher>;
    type ExtrinsicParams = DefaultExtrinsicParams<Self>;
    type AssetId = u32;
}

#[cfg(feature = "subxt")]
pub type OrbinumAddress = SubxtH160;
#[cfg(feature = "subxt")]
pub type OrbinumHash = SubxtH256;
