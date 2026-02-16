//! Shield (deposit) transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
extern crate alloc;
use alloc::vec::Vec;

#[cfg(feature = "crypto")]
use crate::application::builders::ExtrinsicBuilder;
#[cfg(feature = "crypto")]
use crate::application::errors::SignerError;
#[cfg(feature = "crypto")]
use crate::domain::ports::SignerPort;

/// Builder for Shield transactions (deposit)
pub struct ShieldBuilder;

impl ShieldBuilder {
    /// Builds an unsigned Shield transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: ShieldParams,
        encrypted_memo: Vec<u8>,
        nonce: u32,
    ) -> UnsignedTransaction {
        // Use encoder port to create call data
        let call_data = encoder.encode_shield_call_data(&params, &encrypted_memo);
        UnsignedTransaction::new(call_data, nonce)
    }

    /// Builds, signs, and serializes a complete Shield transaction.
    #[cfg(feature = "crypto")]
    pub fn build_signed<S: SignerPort>(
        encoder: &dyn TransactionEncoderPort,
        params: ShieldParams,
        encrypted_memo: Vec<u8>,
        nonce: u32,
        signer: &S,
    ) -> Result<Vec<u8>, SignerError> {
        // 1. Build unsigned transaction
        let unsigned_tx = Self::build_unsigned(encoder, params, encrypted_memo, nonce);

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
    fn test_shield_build() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = ShieldParams {
            asset_id: AssetId::new(1),
            amount: 1000,
            commitment: Commitment::from_bytes_unchecked([1u8; 32]),
        };
        let memo = vec![0u8; 104];
        let tx = ShieldBuilder::build_unsigned(&encoder, params, memo, 0);

        assert!(tx.call_data().len() > 0);
        assert_eq!(tx.call_data()[0], 50); // pallet_index
        assert_eq!(tx.call_data()[1], 0); // call_index
    }

    #[test]
    fn test_shield_with_different_amounts() {
        let encoder = SubstrateTransactionEncoder::new();
        let amounts = [100u128, 1_000, 1_000_000, u128::MAX];

        for amount in amounts {
            let params = ShieldParams {
                asset_id: AssetId::ORB,
                amount,
                commitment: Commitment::from_bytes_unchecked([2u8; 32]),
            };
            let memo = vec![0u8; 104];
            let tx = ShieldBuilder::build_unsigned(&encoder, params, memo, 0);

            assert!(tx.call_data().len() > 50);
        }
    }

    #[test]
    fn test_shield_with_different_assets() {
        let encoder = SubstrateTransactionEncoder::new();
        let asset_ids = [0u32, 1, 2, 100, u32::MAX];

        for asset_id in asset_ids {
            let params = ShieldParams {
                asset_id: AssetId::new(asset_id),
                amount: 1000,
                commitment: Commitment::from_bytes_unchecked([3u8; 32]),
            };
            let memo = vec![0u8; 104];
            let tx = ShieldBuilder::build_unsigned(&encoder, params, memo, 0);

            assert_eq!(tx.call_data()[0], 50);
            assert_eq!(tx.call_data()[1], 0);
        }
    }

    #[test]
    fn test_shield_nonce_is_preserved() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = ShieldParams {
            asset_id: AssetId::new(7),
            amount: 777,
            commitment: Commitment::from_bytes_unchecked([7u8; 32]),
        };
        let tx = ShieldBuilder::build_unsigned(&encoder, params, vec![0u8; 8], 42);

        assert_eq!(tx.nonce(), 42);
    }

    #[cfg(feature = "crypto")]
    struct MockSigner;

    #[cfg(feature = "crypto")]
    impl SignerPort for MockSigner {
        fn sign(&self, _message: &[u8]) -> Result<Signature, DomainSignerError> {
            Ok(Signature::new([1u8; 32], [2u8; 32], 27))
        }

        fn address(&self) -> Address {
            Address::from_slice_unchecked(&[9u8; 20])
        }

        fn public_key(&self) -> PublicKey {
            PublicKey::from_bytes([3u8; 64])
        }
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_shield_build_signed_serializes_extrinsic() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = ShieldParams {
            asset_id: AssetId::ORB,
            amount: 1234,
            commitment: Commitment::from_bytes_unchecked([4u8; 32]),
        };

        let encoded =
            ShieldBuilder::build_signed(&encoder, params, vec![0u8; 16], 0, &MockSigner).unwrap();

        assert!(!encoded.is_empty());
    }
}
