//! Extrinsic Building API
//!
//! Combine call data with external signatures.

use crate::application::builders::ExtrinsicBuilder;
use crate::domain::entities::*;
use crate::domain::types::*;
use crate::presentation::api::core::TransactionApi;

extern crate alloc;
use alloc::vec::Vec;

impl TransactionApi {
    /// Combines call data with external signature to create signed extrinsic.
    pub fn build_signed_extrinsic(
        call_data: Vec<u8>,
        signature: Vec<u8>,
        address: [u8; 20],
        nonce: u32,
    ) -> Vec<u8> {
        let unsigned_tx = UnsignedTransaction::new(call_data, nonce);
        let signed_tx = ExtrinsicBuilder::build_signed(
            unsigned_tx,
            &signature,
            Address::from_slice(&address).expect("Invalid address"),
        );
        ExtrinsicBuilder::serialize(&signed_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_signed_extrinsic() {
        let out = TransactionApi::build_signed_extrinsic(
            vec![1u8, 2u8, 3u8],
            vec![4u8; 65],
            [5u8; 20],
            1,
        );

        assert!(!out.is_empty());
    }
}
