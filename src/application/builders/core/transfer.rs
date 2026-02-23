//! Private transfer transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;

#[cfg(feature = "crypto")]
use crate::application::builders::ExtrinsicBuilder;
#[cfg(feature = "crypto")]
use crate::application::errors::SignerError;
#[cfg(feature = "crypto")]
use crate::domain::ports::SignerPort;

/// Builder for Private Transfer transactions
pub struct TransferBuilder;

impl TransferBuilder {
    /// Builds an unsigned private transfer transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: TransferParams,
        nonce: u32,
    ) -> UnsignedTransaction {
        // Use encoder port to create call data
        let call_data = encoder.encode_transfer_call_data(&params);
        UnsignedTransaction::new(call_data, nonce)
    }

    /// Builds, signs, and serializes a complete Transfer transaction.
    #[cfg(feature = "crypto")]
    pub fn build_signed<S: SignerPort>(
        encoder: &dyn TransactionEncoderPort,
        params: TransferParams,
        nonce: u32,
        signer: &S,
    ) -> Result<Vec<u8>, SignerError> {
        // 1. Build unsigned transaction
        let unsigned_tx = Self::build_unsigned(encoder, params, nonce);

        // 2. Sign
        let signature = signer.sign(unsigned_tx.call_data())?;

        // 3. Build signed transaction
        let signed_tx =
            ExtrinsicBuilder::build_signed(unsigned_tx, &signature.to_bytes(), signer.address());

        // 4. Serialize
        Ok(ExtrinsicBuilder::serialize(&signed_tx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "crypto")]
    use crate::domain::ports::{SignerError as DomainSignerError, SignerPort};
    use crate::domain::types::*;
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;

    #[test]
    fn test_transfer_build() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([6u8; 32]),
                Nullifier::from_bytes_unchecked([7u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([8u8; 32]),
                Commitment::from_bytes_unchecked([9u8; 32]),
            ],
            root: Hash::from_slice(&[10u8; 32]),
            proof: vec![11u8; 128],
            encrypted_memos: [vec![0u8; 32], vec![0u8; 32]],
        };

        let tx = TransferBuilder::build_unsigned(&encoder, params, 10);

        assert!(!tx.call_data().is_empty());
        assert_eq!(tx.nonce(), 10);
        assert_eq!(tx.tip(), 0);
        // Verify call data contains correct indices
        assert_eq!(tx.call_data()[0], 50u8); // pallet_index
        assert_eq!(tx.call_data()[1], 1u8); // call_index for private_transfer
    }

    #[test]
    fn test_transfer_with_different_nullifiers() {
        let encoder = SubstrateTransactionEncoder::new();
        let params1 = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([1u8; 32]),
                Nullifier::from_bytes_unchecked([2u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([8u8; 32]),
                Commitment::from_bytes_unchecked([9u8; 32]),
            ],
            root: Hash::from_slice(&[10u8; 32]),
            proof: vec![11u8; 128],
            encrypted_memos: [vec![0u8; 32], vec![0u8; 32]],
        };

        let params2 = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([99u8; 32]),
                Nullifier::from_bytes_unchecked([88u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([8u8; 32]),
                Commitment::from_bytes_unchecked([9u8; 32]),
            ],
            root: Hash::from_slice(&[10u8; 32]),
            proof: vec![11u8; 128],
            encrypted_memos: [vec![0u8; 32], vec![0u8; 32]],
        };

        let tx1 = TransferBuilder::build_unsigned(&encoder, params1, 0);
        let tx2 = TransferBuilder::build_unsigned(&encoder, params2, 0);

        assert!(!tx1.call_data().is_empty());
        assert!(!tx2.call_data().is_empty());
        // Different nullifiers should produce different call data
        assert_ne!(tx1.call_data(), tx2.call_data());
    }

    #[test]
    fn test_transfer_with_different_memo_sizes() {
        let encoder = SubstrateTransactionEncoder::new();
        let params_small = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([6u8; 32]),
                Nullifier::from_bytes_unchecked([7u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([8u8; 32]),
                Commitment::from_bytes_unchecked([9u8; 32]),
            ],
            root: Hash::from_slice(&[10u8; 32]),
            proof: vec![11u8; 128],
            encrypted_memos: [vec![0u8; 8], vec![0u8; 8]],
        };

        let params_large = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([6u8; 32]),
                Nullifier::from_bytes_unchecked([7u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([8u8; 32]),
                Commitment::from_bytes_unchecked([9u8; 32]),
            ],
            root: Hash::from_slice(&[10u8; 32]),
            proof: vec![11u8; 128],
            encrypted_memos: [vec![0u8; 128], vec![0u8; 128]],
        };

        let tx_small = TransferBuilder::build_unsigned(&encoder, params_small, 0);
        let tx_large = TransferBuilder::build_unsigned(&encoder, params_large, 0);

        assert!(!tx_small.call_data().is_empty());
        assert!(!tx_large.call_data().is_empty());
        assert!(tx_large.call_data().len() > tx_small.call_data().len());
    }

    #[test]
    fn test_transfer_with_different_proofs_changes_encoding() {
        let encoder = SubstrateTransactionEncoder::new();
        let base = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([24u8; 32]),
                Nullifier::from_bytes_unchecked([25u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([26u8; 32]),
                Commitment::from_bytes_unchecked([27u8; 32]),
            ],
            root: Hash::from_slice(&[28u8; 32]),
            proof: vec![29u8; 64],
            encrypted_memos: [vec![30u8; 16], vec![31u8; 16]],
        };

        let tx_a = TransferBuilder::build_unsigned(&encoder, base.clone(), 0);

        let mut changed = base;
        changed.proof = vec![99u8; 64];
        let tx_b = TransferBuilder::build_unsigned(&encoder, changed, 0);

        assert_ne!(tx_a.call_data(), tx_b.call_data());
    }

    #[cfg(feature = "crypto")]
    struct MockSigner;

    #[cfg(feature = "crypto")]
    impl SignerPort for MockSigner {
        fn sign(&self, _message: &[u8]) -> Result<Signature, DomainSignerError> {
            Ok(Signature::new([32u8; 32], [33u8; 32], 27))
        }

        fn address(&self) -> Address {
            Address::from_slice_unchecked(&[34u8; 32])
        }

        fn public_key(&self) -> PublicKey {
            PublicKey::from_bytes([35u8; 64])
        }
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_transfer_build_signed_serializes_extrinsic() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = TransferParams {
            input_nullifiers: [
                Nullifier::from_bytes_unchecked([36u8; 32]),
                Nullifier::from_bytes_unchecked([37u8; 32]),
            ],
            output_commitments: [
                Commitment::from_bytes_unchecked([38u8; 32]),
                Commitment::from_bytes_unchecked([39u8; 32]),
            ],
            root: Hash::from_slice(&[40u8; 32]),
            proof: vec![41u8; 128],
            encrypted_memos: [vec![42u8; 16], vec![43u8; 16]],
        };

        let encoded = TransferBuilder::build_signed(&encoder, params, 0, &MockSigner).unwrap();

        assert!(!encoded.is_empty());
    }
}
