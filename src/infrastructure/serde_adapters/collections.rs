//! Serde serialization support for collections of domain types

use crate::domain::types::{Address, Commitment, Nullifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod nullifier_array {
    use super::*;

    pub fn serialize<S>(nullifiers: &[Nullifier; 2], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: [[u8; 32]; 2] = [*nullifiers[0].as_bytes(), *nullifiers[1].as_bytes()];
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[Nullifier; 2], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [[u8; 32]; 2] = Deserialize::deserialize(deserializer)?;
        Ok([
            Nullifier::from_bytes_unchecked(bytes[0]),
            Nullifier::from_bytes_unchecked(bytes[1]),
        ])
    }
}

pub mod commitment_array {
    use super::*;

    pub fn serialize<S>(commitments: &[Commitment; 2], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: [[u8; 32]; 2] = [*commitments[0].as_bytes(), *commitments[1].as_bytes()];
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[Commitment; 2], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [[u8; 32]; 2] = Deserialize::deserialize(deserializer)?;
        Ok([
            Commitment::from_bytes_unchecked(bytes[0]),
            Commitment::from_bytes_unchecked(bytes[1]),
        ])
    }
}

pub mod option_address {
    use super::*;

    pub fn serialize<S>(address: &Option<Address>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match address {
            Some(addr) => addr.as_bytes().serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Option<[u8; 20]> = Deserialize::deserialize(deserializer)?;
        Ok(bytes.map(|b| Address::from_slice_unchecked(&b)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct NullifierArrayWrapper {
        #[serde(with = "crate::infrastructure::serde_adapters::collections::nullifier_array")]
        nullifiers: [Nullifier; 2],
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct CommitmentArrayWrapper {
        #[serde(with = "crate::infrastructure::serde_adapters::collections::commitment_array")]
        commitments: [Commitment; 2],
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct OptionAddressWrapper {
        #[serde(with = "crate::infrastructure::serde_adapters::collections::option_address")]
        address: Option<Address>,
    }

    #[test]
    fn test_nullifier_array_adapter_roundtrip_json() {
        let original = NullifierArrayWrapper {
            nullifiers: [
                Nullifier::from_bytes_unchecked([5u8; 32]),
                Nullifier::from_bytes_unchecked([6u8; 32]),
            ],
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: NullifierArrayWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.nullifiers[0].as_bytes(), &[5u8; 32]);
        assert_eq!(decoded.nullifiers[1].as_bytes(), &[6u8; 32]);
    }

    #[test]
    fn test_commitment_array_adapter_roundtrip_json() {
        let original = CommitmentArrayWrapper {
            commitments: [
                Commitment::from_bytes_unchecked([7u8; 32]),
                Commitment::from_bytes_unchecked([8u8; 32]),
            ],
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: CommitmentArrayWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.commitments[0].as_bytes(), &[7u8; 32]);
        assert_eq!(decoded.commitments[1].as_bytes(), &[8u8; 32]);
    }

    #[test]
    fn test_option_address_adapter_some_roundtrip_json() {
        let original = OptionAddressWrapper {
            address: Some(Address::from_slice_unchecked(&[9u8; 20])),
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: OptionAddressWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.address.unwrap().as_bytes(), &[9u8; 20]);
    }

    #[test]
    fn test_option_address_adapter_none_roundtrip_json() {
        let original = OptionAddressWrapper { address: None };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: OptionAddressWrapper = serde_json::from_str(&json).unwrap();

        assert!(decoded.address.is_none());
    }
}
