//! SCALE encoder implementation
use crate::domain::ports::EncoderPort;
use crate::domain::types::{Address, Commitment, Hash, Nullifier};
use crate::infrastructure::codec::types::{
    AddressCodec, CommitmentCodec, HashCodec, NullifierCodec,
};
use alloc::vec::Vec;
use codec::Encode;

pub struct ScaleEncoder;

impl ScaleEncoder {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ScaleEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderPort for ScaleEncoder {
    fn encode_u8(&self, value: u8) -> Vec<u8> {
        value.encode()
    }

    fn encode_u32(&self, value: u32) -> Vec<u8> {
        value.encode()
    }

    fn encode_u128(&self, value: u128) -> Vec<u8> {
        value.encode()
    }

    fn encode_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        bytes.encode()
    }

    fn encode_address(&self, addr: &Address) -> Vec<u8> {
        AddressCodec::from(*addr).encode()
    }

    fn encode_hash(&self, hash: &Hash) -> Vec<u8> {
        HashCodec::from(*hash).encode()
    }

    fn encode_commitment(&self, commitment: &Commitment) -> Vec<u8> {
        CommitmentCodec::from(*commitment).encode()
    }

    fn encode_nullifier(&self, nullifier: &Nullifier) -> Vec<u8> {
        NullifierCodec::from(*nullifier).encode()
    }

    fn encode_commitment_array(&self, commitments: &[Commitment]) -> Vec<u8> {
        let codecs: Vec<CommitmentCodec> = commitments
            .iter()
            .map(|c| CommitmentCodec::from(*c))
            .collect();
        codecs.encode()
    }

    fn encode_nullifier_array(&self, nullifiers: &[Nullifier]) -> Vec<u8> {
        let codecs: Vec<NullifierCodec> = nullifiers
            .iter()
            .map(|n| NullifierCodec::from(*n))
            .collect();
        codecs.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scale_encoder_primitives() {
        let encoder = ScaleEncoder::new();

        assert_eq!(encoder.encode_u8(1), vec![1u8]);
        assert_eq!(encoder.encode_u32(42).len(), 4);
        assert_eq!(encoder.encode_u128(99).len(), 16);

        let encoded_bytes = encoder.encode_bytes(&[7u8, 8u8, 9u8]);
        assert!(!encoded_bytes.is_empty());
        assert!(encoded_bytes.len() >= 4);
    }

    #[test]
    fn test_scale_encoder_domain_types() {
        let encoder = ScaleEncoder::new();
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
    fn test_scale_encoder_arrays_and_pairs() {
        let encoder = ScaleEncoder::new();

        let commitments = [
            Commitment::from_bytes_unchecked([5u8; 32]),
            Commitment::from_bytes_unchecked([6u8; 32]),
        ];
        let nullifiers = [
            Nullifier::from_bytes_unchecked([7u8; 32]),
            Nullifier::from_bytes_unchecked([8u8; 32]),
        ];

        let commitment_vec = encoder.encode_commitment_array(&commitments);
        let commitment_pair = encoder.encode_commitment_pair(&commitments);
        let nullifier_vec = encoder.encode_nullifier_array(&nullifiers);
        let nullifier_pair = encoder.encode_nullifier_pair(&nullifiers);

        assert_eq!(commitment_vec, commitment_pair);
        assert_eq!(nullifier_vec, nullifier_pair);
        assert!(!commitment_vec.is_empty());
        assert!(!nullifier_vec.is_empty());
    }
}
