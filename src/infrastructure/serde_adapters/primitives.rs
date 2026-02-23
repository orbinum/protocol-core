//! Serde serialization support for primitive domain types

use crate::domain::types::{Address, Hash};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod address {
    use super::*;

    pub fn serialize<S>(address: &Address, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        address.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Address::from_slice_unchecked(&bytes))
    }
}

pub mod hash {
    use super::*;

    pub fn serialize<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        hash.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Hash::from_slice(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct AddressWrapper {
        #[serde(with = "crate::infrastructure::serde_adapters::primitives::address")]
        address: Address,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct HashWrapper {
        #[serde(with = "crate::infrastructure::serde_adapters::primitives::hash")]
        hash: Hash,
    }

    #[test]
    fn test_address_adapter_roundtrip_json() {
        let original = AddressWrapper {
            address: Address::from_slice_unchecked(&[1u8; 32]),
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: AddressWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.address.as_bytes(), &[1u8; 32]);
    }

    #[test]
    fn test_hash_adapter_roundtrip_json() {
        let original = HashWrapper {
            hash: Hash::from_slice(&[2u8; 32]),
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: HashWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.hash.as_bytes(), &[2u8; 32]);
    }
}
