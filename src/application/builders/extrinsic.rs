// Extrinsic Builder
//! Builder for final signed extrinsics

use crate::domain::entities::*;
use crate::domain::types::*;
use crate::infrastructure::serializers::serialize_signed_transaction;
extern crate alloc;
use alloc::vec::Vec;

/// Builds the final extrinsic with external signature
pub struct ExtrinsicBuilder;

impl ExtrinsicBuilder {
    /// Combines call data and signature to create signed extrinsic
    ///
    /// # Arguments
    /// * `unsigned_tx` - Unsigned transaction with call data
    /// * `signature` - Signature bytes
    /// * `address` - Sender address
    ///
    /// # Returns
    /// Signed transaction ready for broadcast
    pub fn build_signed(
        unsigned_tx: UnsignedTransaction,
        signature: &[u8],
        address: Address,
    ) -> SignedTransaction {
        SignedTransaction::new(
            unsigned_tx.call_data().to_vec(),
            signature.to_vec(),
            address,
            unsigned_tx.nonce(),
        )
    }

    /// Serializes the signed extrinsic for broadcast
    ///
    /// # Arguments
    /// * `signed_tx` - Signed transaction
    ///
    /// # Returns
    /// Encoded bytes ready for submission
    pub fn serialize(signed_tx: &SignedTransaction) -> Vec<u8> {
        serialize_signed_transaction(signed_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_signed() {
        let call_data = vec![1, 2, 3];
        let unsigned_tx = UnsignedTransaction::new(call_data, 0);
        let signature = vec![4u8; 65]; // ECDSA signature must be 65 bytes
        let address = Address::from_slice_unchecked(&[7u8; 20]);

        let signed_tx = ExtrinsicBuilder::build_signed(unsigned_tx, &signature, address);

        assert_eq!(signed_tx.nonce(), 0);
    }

    #[test]
    fn test_serialize() {
        let call_data = vec![1, 2, 3];
        let unsigned_tx = UnsignedTransaction::new(call_data, 0);
        let signature = vec![4u8; 65]; // ECDSA signature must be 65 bytes
        let address = Address::from_slice_unchecked(&[7u8; 20]);

        let signed_tx = ExtrinsicBuilder::build_signed(unsigned_tx, &signature, address);
        let serialized = ExtrinsicBuilder::serialize(&signed_tx);

        assert!(!serialized.is_empty());
    }
}
