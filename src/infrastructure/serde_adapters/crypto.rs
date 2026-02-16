//! Serde serialization support for cryptographic domain types

use crate::domain::types::{Commitment, Nullifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod commitment {
    use super::*;

    pub fn serialize<S>(commitment: &Commitment, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        commitment.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Commitment, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Commitment::from_bytes_unchecked(bytes))
    }
}

pub mod nullifier {
    use super::*;

    pub fn serialize<S>(nullifier: &Nullifier, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        nullifier.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Nullifier, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Nullifier::from_bytes_unchecked(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct CommitmentWrapper {
        #[serde(with = "crate::infrastructure::serde_adapters::crypto::commitment")]
        commitment: Commitment,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct NullifierWrapper {
        #[serde(with = "crate::infrastructure::serde_adapters::crypto::nullifier")]
        nullifier: Nullifier,
    }

    #[test]
    fn test_commitment_adapter_roundtrip_json() {
        let original = CommitmentWrapper {
            commitment: Commitment::from_bytes_unchecked([3u8; 32]),
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: CommitmentWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.commitment.as_bytes(), &[3u8; 32]);
    }

    #[test]
    fn test_nullifier_adapter_roundtrip_json() {
        let original = NullifierWrapper {
            nullifier: Nullifier::from_bytes_unchecked([4u8; 32]),
        };

        let json = serde_json::to_string(&original).unwrap();
        let decoded: NullifierWrapper = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.nullifier.as_bytes(), &[4u8; 32]);
    }
}
