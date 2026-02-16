// Domain Layer - Pure business logic without external dependencies

pub mod entities;
pub mod ports;
pub mod types;

pub use entities::*;
pub use ports::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_reexports_types_and_entities() {
        let address = Address::from_slice_unchecked(&[1u8; 20]);
        let unsigned = UnsignedTransaction::new(vec![1u8], 0);

        assert_eq!(address.as_bytes(), &[1u8; 20]);
        assert_eq!(unsigned.nonce(), 0);
    }

    #[test]
    fn test_domain_reexports_ports() {
        fn accepts_encoder_trait_object(_encoder: &dyn EncoderPort) {}

        struct LocalEncoder;
        impl EncoderPort for LocalEncoder {
            fn encode_u8(&self, value: u8) -> alloc::vec::Vec<u8> {
                vec![value]
            }
            fn encode_u32(&self, value: u32) -> alloc::vec::Vec<u8> {
                value.to_le_bytes().to_vec()
            }
            fn encode_u128(&self, value: u128) -> alloc::vec::Vec<u8> {
                value.to_le_bytes().to_vec()
            }
            fn encode_bytes(&self, bytes: &[u8]) -> alloc::vec::Vec<u8> {
                bytes.to_vec()
            }
            fn encode_address(&self, addr: &Address) -> alloc::vec::Vec<u8> {
                addr.as_bytes().to_vec()
            }
            fn encode_hash(&self, hash: &Hash) -> alloc::vec::Vec<u8> {
                hash.as_bytes().to_vec()
            }
            fn encode_commitment(&self, commitment: &Commitment) -> alloc::vec::Vec<u8> {
                commitment.as_bytes().to_vec()
            }
            fn encode_nullifier(&self, nullifier: &Nullifier) -> alloc::vec::Vec<u8> {
                nullifier.as_bytes().to_vec()
            }
            fn encode_commitment_array(&self, commitments: &[Commitment]) -> alloc::vec::Vec<u8> {
                commitments
                    .iter()
                    .flat_map(|c| c.as_bytes().to_vec())
                    .collect()
            }
            fn encode_nullifier_array(&self, nullifiers: &[Nullifier]) -> alloc::vec::Vec<u8> {
                nullifiers
                    .iter()
                    .flat_map(|n| n.as_bytes().to_vec())
                    .collect()
            }
        }

        let encoder = LocalEncoder;
        accepts_encoder_trait_object(&encoder);
        assert_eq!(encoder.encode_u8(5), vec![5u8]);
    }
}
