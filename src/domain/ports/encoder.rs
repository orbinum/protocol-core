// Domain Port - Encoder abstraction
//! Defines the contract for encoding domain types to bytes
//! This allows the domain to remain independent of specific serialization formats

use super::super::types::*;
extern crate alloc;
use alloc::vec::Vec;

/// Port for encoding domain types to bytes
///
/// This trait abstracts the serialization mechanism, allowing the domain
/// to remain independent of specific implementations (SCALE, Protobuf, etc.)
///
/// # Design Notes
/// - Domain defines WHAT needs to be encoded
/// - Infrastructure defines HOW it's encoded
/// - This enables changing serialization format without touching domain
pub trait EncoderPort {
    /// Encode a u8 to bytes
    fn encode_u8(&self, value: u8) -> Vec<u8>;

    /// Encode a u32 to bytes (compact encoding preferred)
    fn encode_u32(&self, value: u32) -> Vec<u8>;

    /// Encode a u128 to bytes (compact encoding preferred)
    fn encode_u128(&self, value: u128) -> Vec<u8>;

    /// Encode variable-length bytes with length prefix
    fn encode_bytes(&self, bytes: &[u8]) -> Vec<u8>;

    /// Encode Address to bytes
    fn encode_address(&self, addr: &Address) -> Vec<u8>;

    /// Encode Hash to bytes
    fn encode_hash(&self, hash: &Hash) -> Vec<u8>;

    /// Encode Commitment to bytes
    fn encode_commitment(&self, commitment: &Commitment) -> Vec<u8>;

    /// Encode Nullifier to bytes
    fn encode_nullifier(&self, nullifier: &Nullifier) -> Vec<u8>;

    /// Encode array of Commitments
    fn encode_commitment_array(&self, commitments: &[Commitment]) -> Vec<u8>;

    /// Encode array of Nullifiers
    fn encode_nullifier_array(&self, nullifiers: &[Nullifier]) -> Vec<u8>;

    /// Encode fixed-size array of 2 Commitments (optimized for common case)
    fn encode_commitment_pair(&self, pair: &[Commitment; 2]) -> Vec<u8> {
        self.encode_commitment_array(pair)
    }

    /// Encode fixed-size array of 2 Nullifiers (optimized for common case)
    fn encode_nullifier_pair(&self, pair: &[Nullifier; 2]) -> Vec<u8> {
        self.encode_nullifier_array(pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyEncoder;

    impl EncoderPort for DummyEncoder {
        fn encode_u8(&self, value: u8) -> Vec<u8> {
            vec![value]
        }

        fn encode_u32(&self, value: u32) -> Vec<u8> {
            value.to_le_bytes().to_vec()
        }

        fn encode_u128(&self, value: u128) -> Vec<u8> {
            value.to_le_bytes().to_vec()
        }

        fn encode_bytes(&self, bytes: &[u8]) -> Vec<u8> {
            bytes.to_vec()
        }

        fn encode_address(&self, addr: &Address) -> Vec<u8> {
            addr.as_bytes().to_vec()
        }

        fn encode_hash(&self, hash: &Hash) -> Vec<u8> {
            hash.as_bytes().to_vec()
        }

        fn encode_commitment(&self, commitment: &Commitment) -> Vec<u8> {
            commitment.as_bytes().to_vec()
        }

        fn encode_nullifier(&self, nullifier: &Nullifier) -> Vec<u8> {
            nullifier.as_bytes().to_vec()
        }

        fn encode_commitment_array(&self, commitments: &[Commitment]) -> Vec<u8> {
            commitments
                .iter()
                .flat_map(|c| c.as_bytes().to_vec())
                .collect()
        }

        fn encode_nullifier_array(&self, nullifiers: &[Nullifier]) -> Vec<u8> {
            nullifiers
                .iter()
                .flat_map(|n| n.as_bytes().to_vec())
                .collect()
        }
    }

    #[test]
    fn test_encoder_port_contract_methods() {
        let encoder = DummyEncoder;

        assert_eq!(encoder.encode_u8(9), vec![9u8]);
        assert_eq!(encoder.encode_u32(10).len(), 4);
        assert_eq!(encoder.encode_u128(11).len(), 16);
        assert_eq!(encoder.encode_bytes(&[1u8, 2u8]), vec![1u8, 2u8]);

        let addr = Address::from_slice_unchecked(&[1u8; 20]);
        let hash = Hash::from_slice(&[2u8; 32]);
        let commitment = Commitment::from_bytes_unchecked([3u8; 32]);
        let nullifier = Nullifier::from_bytes_unchecked([4u8; 32]);

        assert_eq!(encoder.encode_address(&addr).len(), 20);
        assert_eq!(encoder.encode_hash(&hash).len(), 32);
        assert_eq!(encoder.encode_commitment(&commitment).len(), 32);
        assert_eq!(encoder.encode_nullifier(&nullifier).len(), 32);
    }

    #[test]
    fn test_encoder_port_default_pair_methods() {
        let encoder = DummyEncoder;

        let commitments = [
            Commitment::from_bytes_unchecked([5u8; 32]),
            Commitment::from_bytes_unchecked([6u8; 32]),
        ];
        let nullifiers = [
            Nullifier::from_bytes_unchecked([7u8; 32]),
            Nullifier::from_bytes_unchecked([8u8; 32]),
        ];

        assert_eq!(encoder.encode_commitment_pair(&commitments).len(), 64);
        assert_eq!(encoder.encode_nullifier_pair(&nullifiers).len(), 64);
    }
}
