// Domain Entities - Business entities with behavior

use super::types::*;

/// Domain error for entity validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityError {
    EmptyCallData,
    InvalidSignatureLength,
    EmptySignature,
    InvalidTipAmount,
}

/// Unsigned transaction (call data ready to be signed)
#[derive(Clone, Debug)]
pub struct UnsignedTransaction {
    call_data: alloc::vec::Vec<u8>,
    nonce: u32,
    tip: u128,
}

impl UnsignedTransaction {
    /// Creates a new unsigned transaction with validation
    pub fn new(call_data: alloc::vec::Vec<u8>, nonce: u32) -> Self {
        // Business rule: call data must not be empty
        assert!(!call_data.is_empty(), "Call data cannot be empty");

        UnsignedTransaction {
            call_data,
            nonce,
            tip: 0,
        }
    }

    /// Adds a tip to the transaction
    /// Tips incentivize block producers to include the transaction
    pub fn with_tip(mut self, tip: u128) -> Self {
        self.tip = tip;
        self
    }

    /// Gets the call data
    pub fn call_data(&self) -> &[u8] {
        &self.call_data
    }

    /// Gets the nonce
    pub fn nonce(&self) -> u32 {
        self.nonce
    }

    /// Gets the tip
    pub fn tip(&self) -> u128 {
        self.tip
    }

    /// Validates the transaction is ready for signing
    pub fn validate(&self) -> Result<(), EntityError> {
        if self.call_data.is_empty() {
            return Err(EntityError::EmptyCallData);
        }
        Ok(())
    }
}

/// Signed transaction ready for broadcast
#[derive(Clone, Debug)]
pub struct SignedTransaction {
    call_data: alloc::vec::Vec<u8>,
    signature: alloc::vec::Vec<u8>,
    address: Address,
    nonce: u32,
}

impl SignedTransaction {
    /// Creates a new signed transaction with validation
    pub fn new(
        call_data: alloc::vec::Vec<u8>,
        signature: alloc::vec::Vec<u8>,
        address: Address,
        nonce: u32,
    ) -> Self {
        // Business rules enforcement
        assert!(!call_data.is_empty(), "Call data cannot be empty");
        assert!(!signature.is_empty(), "Signature cannot be empty");
        assert_eq!(signature.len(), 65, "ECDSA signature must be 65 bytes");

        SignedTransaction {
            call_data,
            signature,
            address,
            nonce,
        }
    }

    /// Gets the call data
    pub fn call_data(&self) -> &[u8] {
        &self.call_data
    }

    /// Gets the signature
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Gets the address
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Gets the nonce
    pub fn nonce(&self) -> u32 {
        self.nonce
    }

    /// Validates the signed transaction is ready for broadcast
    pub fn validate(&self) -> Result<(), EntityError> {
        if self.call_data.is_empty() {
            return Err(EntityError::EmptyCallData);
        }
        if self.signature.is_empty() {
            return Err(EntityError::EmptySignature);
        }
        if self.signature.len() != 65 {
            return Err(EntityError::InvalidSignatureLength);
        }
        Ok(())
    }

    /// Checks if this transaction can be broadcast to the network
    pub fn is_ready_for_broadcast(&self) -> bool {
        self.validate().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsigned_transaction_new_and_accessors() {
        let tx = UnsignedTransaction::new(vec![1u8, 2u8, 3u8], 7);
        assert_eq!(tx.call_data(), &[1u8, 2u8, 3u8]);
        assert_eq!(tx.nonce(), 7);
        assert_eq!(tx.tip(), 0);
        assert!(tx.validate().is_ok());
    }

    #[test]
    fn test_unsigned_transaction_with_tip() {
        let tx = UnsignedTransaction::new(vec![9u8], 1).with_tip(123);
        assert_eq!(tx.tip(), 123);
    }

    #[test]
    #[should_panic(expected = "Call data cannot be empty")]
    fn test_unsigned_transaction_new_panics_on_empty_call_data() {
        let _ = UnsignedTransaction::new(vec![], 0);
    }

    #[test]
    fn test_signed_transaction_new_and_accessors() {
        let address = Address::from_slice_unchecked(&[7u8; 20]);
        let signature = vec![5u8; 65];
        let tx = SignedTransaction::new(vec![1u8, 2u8], signature.clone(), address, 3);

        assert_eq!(tx.call_data(), &[1u8, 2u8]);
        assert_eq!(tx.signature(), &signature);
        assert_eq!(tx.address().as_bytes(), &[7u8; 20]);
        assert_eq!(tx.nonce(), 3);
        assert!(tx.validate().is_ok());
        assert!(tx.is_ready_for_broadcast());
    }

    #[test]
    #[should_panic(expected = "Signature cannot be empty")]
    fn test_signed_transaction_new_panics_on_empty_signature() {
        let address = Address::from_slice_unchecked(&[1u8; 20]);
        let _ = SignedTransaction::new(vec![1u8], vec![], address, 0);
    }

    #[test]
    #[should_panic(expected = "ECDSA signature must be 65 bytes")]
    fn test_signed_transaction_new_panics_on_invalid_signature_length() {
        let address = Address::from_slice_unchecked(&[1u8; 20]);
        let _ = SignedTransaction::new(vec![1u8], vec![2u8; 64], address, 0);
    }
}
