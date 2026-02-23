// Domain Ports - Traits that define interfaces without implementation

use super::types::*;

// Encoder port module
pub mod encoder;
pub use encoder::EncoderPort;

/// Port for signing operations (Signer Port)
pub trait SignerPort {
    /// Signs an arbitrary message
    fn sign(&self, message: &[u8]) -> Result<Signature, SignerError>;

    /// Gets the associated Ethereum address
    fn address(&self) -> Address;

    /// Gets the public key
    fn public_key(&self) -> PublicKey;
}

/// Port for cryptographic hashing
pub trait HashPort {
    /// Hash Keccak256 (Ethereum compatible)
    fn keccak256(data: &[u8]) -> Hash;
}

/// Port for types that can be serialized to/from bytes
///
/// This trait enables domain types to be serialized and deserialized
/// following the Dependency Inversion Principle - domain defines the interface,
/// infrastructure provides implementations.
pub trait Serializable {
    /// Serialize this type to a byte vector
    fn to_bytes(&self) -> alloc::vec::Vec<u8>;

    /// Deserialize this type from bytes
    ///
    /// Returns an error message if deserialization fails
    fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized;
}

/// Signer errors
#[derive(Debug)]
pub enum SignerError {
    InvalidKey,
    SigningFailed,
    InvalidMessage,
}

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignerError::InvalidKey => write!(f, "Invalid key"),
            SignerError::SigningFailed => write!(f, "Signing failed"),
            SignerError::InvalidMessage => write!(f, "Invalid message"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignerError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummySigner;

    impl SignerPort for DummySigner {
        fn sign(&self, _message: &[u8]) -> Result<Signature, SignerError> {
            Ok(Signature::new([1u8; 32], [2u8; 32], 27))
        }

        fn address(&self) -> Address {
            Address::from_slice_unchecked(&[3u8; 32])
        }

        fn public_key(&self) -> PublicKey {
            PublicKey::from_bytes([4u8; 64])
        }
    }

    struct DummyHash;

    impl HashPort for DummyHash {
        fn keccak256(_data: &[u8]) -> Hash {
            Hash::from_slice(&[5u8; 32])
        }
    }

    #[test]
    fn test_signer_port_contract() {
        let signer = DummySigner;
        let signature = signer.sign(&[9u8; 4]).unwrap();

        assert_eq!(signature.to_bytes().len(), 65);
        assert_eq!(signer.address().as_bytes(), &[3u8; 32]);
        assert_eq!(signer.public_key().as_bytes(), &[4u8; 64]);
    }

    #[test]
    fn test_hash_port_contract() {
        let hash = DummyHash::keccak256(&[1u8, 2u8]);
        assert_eq!(hash.as_bytes(), &[5u8; 32]);
    }

    #[test]
    fn test_signer_error_display() {
        assert_eq!(SignerError::InvalidKey.to_string(), "Invalid key");
        assert_eq!(SignerError::SigningFailed.to_string(), "Signing failed");
        assert_eq!(SignerError::InvalidMessage.to_string(), "Invalid message");
    }
}
