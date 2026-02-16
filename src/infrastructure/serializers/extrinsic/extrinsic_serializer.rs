//! Extrinsic serialization utilities

use crate::domain::entities::SignedTransaction;
use crate::infrastructure::codec::types::SignedTransactionCodec;
use codec::Encode;
extern crate alloc;
use alloc::vec::Vec;

/// Serializes a signed transaction to SCALE-encoded bytes for broadcast.
pub fn serialize_signed_transaction(signed_tx: &SignedTransaction) -> Vec<u8> {
    // Convert domain entity to codec wrapper and encode
    let codec_tx = SignedTransactionCodec::from(signed_tx.clone());
    codec_tx.encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Address;

    #[test]
    fn test_serialize_signed_transaction() {
        let call_data = alloc::vec![1, 2, 3];
        let signature = alloc::vec![4u8; 65];
        let address = Address::from_slice_unchecked(&[7u8; 20]);

        let signed_tx = SignedTransaction::new(call_data, signature, address, 0);
        let serialized = serialize_signed_transaction(&signed_tx);

        assert!(!serialized.is_empty());
    }
}
