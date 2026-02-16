//! Transaction serialization utilities
use crate::domain::entities::SignedTransaction;
use crate::infrastructure::codec::types::SignedTransactionCodec;
use alloc::vec::Vec;
use codec::Encode;

pub fn serialize_signed_transaction(tx: &SignedTransaction) -> Vec<u8> {
    SignedTransactionCodec::from(tx.clone()).encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::types::Address;

    #[test]
    fn test_core_transaction_serializer_outputs_bytes() {
        let tx = SignedTransaction::new(
            vec![1u8, 2u8],
            vec![3u8; 65],
            Address::from_slice_unchecked(&[4u8; 20]),
            9,
        );

        let out = serialize_signed_transaction(&tx);
        assert!(!out.is_empty());
    }
}
