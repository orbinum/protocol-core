//! Unshield (withdrawal) transaction builder

use crate::application::params::*;
use crate::application::ports::TransactionEncoderPort;
use crate::domain::entities::*;
use crate::domain::types::AssetId;
extern crate alloc;

#[cfg(feature = "crypto")]
use crate::application::builders::ExtrinsicBuilder;
#[cfg(feature = "crypto")]
use crate::application::errors::SignerError;
#[cfg(feature = "crypto")]
use crate::domain::ports::SignerPort;

/// Builder for Unshield transactions (withdrawal)
pub struct UnshieldBuilder;

impl UnshieldBuilder {
    /// Builds an unsigned Unshield transaction.
    pub fn build_unsigned(
        encoder: &dyn TransactionEncoderPort,
        params: UnshieldParams,
        asset_id: AssetId,
        nonce: u32,
    ) -> UnsignedTransaction {
        // Use encoder port to create call data
        let call_data = encoder.encode_unshield_call_data(&params, asset_id);
        UnsignedTransaction::new(call_data, nonce)
    }

    /// Builds, signs, and serializes a complete Unshield transaction.
    #[cfg(feature = "crypto")]
    pub fn build_signed<S: SignerPort>(
        encoder: &dyn TransactionEncoderPort,
        params: UnshieldParams,
        asset_id: AssetId,
        nonce: u32,
        signer: &S,
    ) -> Result<Vec<u8>, SignerError> {
        // 1. Build unsigned transaction
        let unsigned_tx = Self::build_unsigned(encoder, params, asset_id, nonce);

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
    fn test_unshield_build() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = UnshieldParams {
            nullifier: Nullifier::from_bytes_unchecked([2u8; 32]),
            amount: 500u128,
            recipient: Address::from_slice_unchecked(&[3u8; 32]),
            root: Hash::from_slice(&[4u8; 32]),
            proof: vec![5u8; 128],
        };

        let tx = UnshieldBuilder::build_unsigned(&encoder, params, AssetId::new(1), 5);

        assert!(!tx.call_data().is_empty());
        assert_eq!(tx.nonce(), 5);
        assert_eq!(tx.tip(), 0);
        // Verify call data contains correct indices
        assert_eq!(tx.call_data()[0], 50u8); // pallet_index
        assert_eq!(tx.call_data()[1], 2u8); // call_index for unshield
    }

    #[test]
    fn test_unshield_with_proof_sizes() {
        let encoder = SubstrateTransactionEncoder::new();
        let nullifier = Nullifier::from_bytes_unchecked([2u8; 32]);
        let recipient = Address::from_slice_unchecked(&[3u8; 32]);
        let root = Hash::from_slice(&[4u8; 32]);

        let params_small = UnshieldParams {
            nullifier,
            amount: 500u128,
            recipient,
            root,
            proof: vec![5u8; 64],
        };
        let params_large = UnshieldParams {
            nullifier,
            amount: 500u128,
            recipient,
            root,
            proof: vec![5u8; 256],
        };

        let tx_small = UnshieldBuilder::build_unsigned(&encoder, params_small, AssetId::new(1), 0);
        let tx_large = UnshieldBuilder::build_unsigned(&encoder, params_large, AssetId::new(1), 0);

        assert!(!tx_small.call_data().is_empty());
        assert!(!tx_large.call_data().is_empty());
        // Larger proof should result in longer call data
        assert!(tx_large.call_data().len() > tx_small.call_data().len());
    }

    #[test]
    fn test_unshield_with_different_assets_changes_encoding() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = UnshieldParams {
            nullifier: Nullifier::from_bytes_unchecked([12u8; 32]),
            amount: 900,
            recipient: Address::from_slice_unchecked(&[13u8; 32]),
            root: Hash::from_slice(&[14u8; 32]),
            proof: vec![15u8; 128],
        };

        let tx_orb = UnshieldBuilder::build_unsigned(&encoder, params.clone(), AssetId::new(0), 1);
        let tx_other = UnshieldBuilder::build_unsigned(&encoder, params, AssetId::new(99), 1);

        assert_ne!(tx_orb.call_data(), tx_other.call_data());
    }

    #[cfg(feature = "crypto")]
    struct MockSigner;

    #[cfg(feature = "crypto")]
    impl SignerPort for MockSigner {
        fn sign(&self, _message: &[u8]) -> Result<Signature, DomainSignerError> {
            Ok(Signature::new([16u8; 32], [17u8; 32], 28))
        }

        fn address(&self) -> Address {
            Address::from_slice_unchecked(&[18u8; 32])
        }

        fn public_key(&self) -> PublicKey {
            PublicKey::from_bytes([19u8; 64])
        }
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn test_unshield_build_signed_serializes_extrinsic() {
        let encoder = SubstrateTransactionEncoder::new();
        let params = UnshieldParams {
            nullifier: Nullifier::from_bytes_unchecked([20u8; 32]),
            amount: 1500,
            recipient: Address::from_slice_unchecked(&[21u8; 32]),
            root: Hash::from_slice(&[22u8; 32]),
            proof: vec![23u8; 128],
        };

        let encoded =
            UnshieldBuilder::build_signed(&encoder, params, AssetId::new(1), 0, &MockSigner)
                .unwrap();

        assert!(!encoded.is_empty());
    }
}
