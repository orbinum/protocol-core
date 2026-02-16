//! Domain identifier types
//!
//! Wrapper types for identifiers providing type safety and preventing
//! accidental mixing of different ID types.

use serde::{Deserialize, Serialize};

/// Asset identifier wrapper for type safety
///
/// Prevents accidentally passing the wrong ID type to functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetId(pub u32);

impl AssetId {
    /// ORB token asset ID (default)
    pub const ORB: Self = AssetId(0);

    /// Create a new AssetId
    pub fn new(id: u32) -> Self {
        AssetId(id)
    }

    /// Get the underlying u32 value
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl From<u32> for AssetId {
    fn from(id: u32) -> Self {
        AssetId(id)
    }
}

impl From<AssetId> for u32 {
    fn from(asset_id: AssetId) -> Self {
        asset_id.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_id_creation() {
        let asset = AssetId::new(42);
        assert_eq!(asset.as_u32(), 42);
    }

    #[test]
    fn test_asset_id_orb_constant() {
        assert_eq!(AssetId::ORB.as_u32(), 0);
    }

    #[test]
    fn test_asset_id_from_u32() {
        let asset: AssetId = 123u32.into();
        assert_eq!(asset.as_u32(), 123);
    }

    #[test]
    fn test_asset_id_to_u32() {
        let asset = AssetId::new(456);
        let id: u32 = asset.into();
        assert_eq!(id, 456);
    }

    #[test]
    fn test_asset_id_equality() {
        let asset1 = AssetId::new(1);
        let asset2 = AssetId::new(1);
        let asset3 = AssetId::new(2);

        assert_eq!(asset1, asset2);
        assert_ne!(asset1, asset3);
    }
}
