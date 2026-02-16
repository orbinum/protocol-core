//! Cryptographic implementations
//! - ZK operations: require "crypto-zk" or "crypto" feature
//! - Signing operations: require "crypto-signing" or "crypto" feature

// Imports for signing (ECDSA, Keccak)
#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
use crate::domain::ports::{HashPort, SignerError, SignerPort};
#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
use crate::domain::types::*;

#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
use libsecp256k1::{Message, PublicKey as Secp256k1PublicKey, SecretKey as Secp256k1SecretKey};
#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
use tiny_keccak::{Hasher, Keccak};

// Imports for ZK operations (Poseidon, commitments)
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
use orbinum_zk_core::{
    domain::ports::PoseidonHasher, Blinding, FieldElement, LightPoseidonHasher, Note, NoteDto,
    OwnerPubkey,
};

/// ZK cryptography provider using orbinum-zk-core.
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub struct ZkCryptoProvider;

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
impl ZkCryptoProvider {
    pub fn new() -> Self {
        Self
    }

    /// Converts bytes to FieldElement using NoteDto roundtrip.
    fn bytes_to_field(bytes: [u8; 32]) -> Result<FieldElement, String> {
        // Create DTO with bytes in owner_pubkey field
        let dto = NoteDto::new(0, 0, bytes, [0u8; 32]);
        // Convert to domain (validates and converts)
        let note = dto.to_domain()?;
        // Extract field element
        Ok(note.owner_pubkey().inner())
    }

    /// Converts FieldElement to bytes using NoteDto roundtrip.
    fn field_to_bytes(field: FieldElement) -> [u8; 32] {
        // Create Note with field in owner_pubkey
        // Use from_u64(0) instead of zero() to be safe if zero() is not exposed on Blinding
        let note = Note::new(
            0,
            0,
            OwnerPubkey::from(field),
            Blinding::from(FieldElement::from_u64(0)), // dummy blinding
        );
        // Convert to DTO
        let dto = NoteDto::from_domain(&note);
        dto.owner_pubkey
    }

    pub fn get_note_commitment(&self, note: &Note) -> [u8; 32] {
        let hasher = LightPoseidonHasher::default();
        let commitment = note.commitment(hasher);
        Self::field_to_bytes(commitment.inner())
    }

    pub fn create_note(
        &self,
        value: u128,
        asset_id: u32,
        owner_pubkey: [u8; 32],
        blinding: [u8; 32],
    ) -> Result<Note, String> {
        // Use helper to convert bytes to Scalar/FieldElement
        let owner_pubkey_field = Self::bytes_to_field(owner_pubkey)?;
        let blinding_field = Self::bytes_to_field(blinding)?;

        let note = Note::new(
            value as u64,
            asset_id as u64,
            OwnerPubkey::from(owner_pubkey_field),
            Blinding::from(blinding_field),
        );
        Ok(note)
    }

    pub fn compute_commitment(
        &self,
        value: u128,
        asset_id: u32,
        owner_pubkey: [u8; 32],
        blinding: [u8; 32],
    ) -> Result<[u8; 32], String> {
        let note = self.create_note(value, asset_id, owner_pubkey, blinding)?;
        Ok(self.get_note_commitment(&note))
    }

    pub fn compute_nullifier(
        &self,
        commitment: [u8; 32],
        spending_key: [u8; 32],
    ) -> Result<[u8; 32], String> {
        let commitment_field = Self::bytes_to_field(commitment)?;
        let spending_key_field = Self::bytes_to_field(spending_key)?;

        let hasher = LightPoseidonHasher::default();
        let nullifier = hasher.hash_2([commitment_field, spending_key_field]);

        Ok(Self::field_to_bytes(nullifier))
    }

    pub fn poseidon_hash_2(&self, left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32], String> {
        let left_field = Self::bytes_to_field(left)?;
        let right_field = Self::bytes_to_field(right)?;

        let hasher = LightPoseidonHasher::default();
        let result = hasher.hash_2([left_field, right_field]);

        Ok(Self::field_to_bytes(result))
    }

    pub fn poseidon_hash_4(&self, inputs: [[u8; 32]; 4]) -> Result<[u8; 32], String> {
        let mut field_inputs = [FieldElement::from_u64(0); 4];
        for (i, input) in inputs.iter().enumerate() {
            field_inputs[i] = Self::bytes_to_field(*input)?;
        }

        let hasher = LightPoseidonHasher::default();
        let result = hasher.hash_4(field_inputs);

        Ok(Self::field_to_bytes(result))
    }
}

/// Keccak256 hash implementation.
#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
pub struct Keccak256Hasher;

#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
impl HashPort for Keccak256Hasher {
    fn keccak256(data: &[u8]) -> Hash {
        let mut keccak = Keccak::v256();
        let mut output = [0u8; 32];
        keccak.update(data);
        keccak.finalize(&mut output);
        Hash(output)
    }
}

/// ECDSA signer using secp256k1.
#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
pub struct EcdsaSigner {
    secret_key: Secp256k1SecretKey,
    public_key: Secp256k1PublicKey,
    address: Address,
}

#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
impl EcdsaSigner {
    /// Crea un signer desde una clave privada
    pub fn from_secret_key(secret: &SecretKey) -> Result<Self, SignerError> {
        let secret_key = Secp256k1SecretKey::parse_slice(secret.as_bytes())
            .map_err(|_| SignerError::InvalidKey)?;

        let public_key = Secp256k1PublicKey::from_secret_key(&secret_key);

        // Derivar dirección Ethereum: keccak256(pubkey)[12..]
        let pubkey_bytes = public_key.serialize();
        let hash = Keccak256Hasher::keccak256(&pubkey_bytes[1..]); // Sin el prefijo 0x04
        let address =
            Address::from_slice(&hash.as_bytes()[12..]).map_err(|_| SignerError::InvalidKey)?;

        Ok(EcdsaSigner {
            secret_key,
            public_key,
            address,
        })
    }

    /// Crea un signer desde un hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, SignerError> {
        let hex_clean = hex_str.trim_start_matches("0x");
        let bytes = hex::decode(hex_clean).map_err(|_| SignerError::InvalidKey)?;

        if bytes.len() != 32 {
            return Err(SignerError::InvalidKey);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);

        Self::from_secret_key(&SecretKey(key_bytes))
    }
}

#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
impl SignerPort for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Signature, SignerError> {
        // Hash del mensaje con Keccak256
        let hash = Keccak256Hasher::keccak256(message);
        let msg = Message::parse(hash.as_bytes());

        // Firmar
        let (sig, recovery_id) = libsecp256k1::sign(&msg, &self.secret_key);
        let sig_bytes = sig.serialize();

        // Convertir a formato Ethereum (r, s, v)
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..64]);
        let v = recovery_id.serialize() + 27; // Ethereum usa 27/28 en lugar de 0/1

        Ok(Signature::new(r, s, v))
    }

    fn address(&self) -> Address {
        self.address
    }

    fn public_key(&self) -> PublicKey {
        let bytes = self.public_key.serialize();
        let mut pk_bytes = [0u8; 64];
        pk_bytes.copy_from_slice(&bytes[1..]); // Sin el prefijo 0x04
        PublicKey(pk_bytes)
    }
}

#[cfg(test)]
#[cfg(any(feature = "crypto-signing", feature = "crypto"))]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256() {
        let data = b"hello world";
        let hash = Keccak256Hasher::keccak256(data);

        // Verificar que produce 32 bytes
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_ecdsa_signer_creation() {
        let secret = SecretKey([1u8; 32]);
        let signer = EcdsaSigner::from_secret_key(&secret);

        assert!(signer.is_ok());

        let signer = signer.unwrap();
        let addr = signer.address();

        // Verificar que la dirección tiene 20 bytes
        assert_eq!(addr.as_bytes().len(), 20);
    }

    #[test]
    fn test_sign_message() {
        let secret = SecretKey([1u8; 32]);
        let signer = EcdsaSigner::from_secret_key(&secret).unwrap();

        let message = b"test message";
        let signature = signer.sign(message);

        assert!(signature.is_ok());

        let sig = signature.unwrap();
        assert_eq!(sig.r.len(), 32);
        assert_eq!(sig.s.len(), 32);
        assert!(sig.v == 27 || sig.v == 28);
    }

    #[test]
    fn test_ecdsa_signer_from_hex_valid() {
        let hex_key = "0101010101010101010101010101010101010101010101010101010101010101";
        let signer = EcdsaSigner::from_hex(hex_key);
        assert!(signer.is_ok());
    }

    #[test]
    fn test_ecdsa_signer_from_hex_valid_with_prefix() {
        let hex_key = "0x0101010101010101010101010101010101010101010101010101010101010101";
        let signer = EcdsaSigner::from_hex(hex_key);
        assert!(signer.is_ok());
    }

    #[test]
    fn test_ecdsa_signer_from_hex_invalid_length() {
        let short_hex = "0101";
        let signer = EcdsaSigner::from_hex(short_hex);
        assert!(signer.is_err());
    }

    #[test]
    fn test_ecdsa_signer_from_hex_invalid_chars() {
        let invalid_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let signer = EcdsaSigner::from_hex(invalid_hex);
        assert!(signer.is_err());
    }

    #[test]
    fn test_signer_public_key_length() {
        let secret = SecretKey([2u8; 32]);
        let signer = EcdsaSigner::from_secret_key(&secret).unwrap();
        let pk = signer.public_key();
        assert_eq!(pk.as_bytes().len(), 64);
    }
}

#[cfg(test)]
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
mod zk_tests {
    use super::*;

    #[test]
    fn test_zk_provider_create_note_success() {
        let provider = ZkCryptoProvider::new();
        let note = provider.create_note(100, 1, [1u8; 32], [2u8; 32]);

        assert!(note.is_ok());
        let note = note.unwrap();
        assert_eq!(note.value(), 100);
        assert_eq!(note.asset_id(), 1);
    }

    #[test]
    fn test_zk_provider_compute_commitment_success() {
        let provider = ZkCryptoProvider::new();
        let commitment = provider.compute_commitment(50, 2, [3u8; 32], [4u8; 32]);

        assert!(commitment.is_ok());
        assert_ne!(commitment.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_zk_provider_compute_nullifier_success() {
        let provider = ZkCryptoProvider::new();
        let nullifier = provider.compute_nullifier([5u8; 32], [6u8; 32]);

        assert!(nullifier.is_ok());
        assert_ne!(nullifier.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_zk_provider_poseidon_hash_2_success() {
        let provider = ZkCryptoProvider::new();
        let hash = provider.poseidon_hash_2([7u8; 32], [8u8; 32]);

        assert!(hash.is_ok());
        assert_ne!(hash.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_zk_provider_poseidon_hash_4_success() {
        let provider = ZkCryptoProvider::new();
        let hash = provider.poseidon_hash_4([[9u8; 32], [10u8; 32], [11u8; 32], [12u8; 32]]);

        assert!(hash.is_ok());
        assert_ne!(hash.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_zk_provider_hashes_are_deterministic() {
        let provider = ZkCryptoProvider::new();

        let h1 = provider.poseidon_hash_2([13u8; 32], [14u8; 32]).unwrap();
        let h2 = provider.poseidon_hash_2([13u8; 32], [14u8; 32]).unwrap();
        assert_eq!(h1, h2);

        let h3 = provider
            .poseidon_hash_4([[15u8; 32], [16u8; 32], [17u8; 32], [18u8; 32]])
            .unwrap();
        let h4 = provider
            .poseidon_hash_4([[15u8; 32], [16u8; 32], [17u8; 32], [18u8; 32]])
            .unwrap();
        assert_eq!(h3, h4);
    }

    #[test]
    fn test_zk_provider_get_note_commitment_consistency() {
        let provider = ZkCryptoProvider::new();
        let note = provider.create_note(77, 3, [19u8; 32], [20u8; 32]).unwrap();

        let c1 = provider.get_note_commitment(&note);
        let c2 = provider.get_note_commitment(&note);
        assert_eq!(c1, c2);
    }
}
