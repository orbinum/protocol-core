//! Cryptographic operations API

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
use crate::domain::types::identifiers::AssetId;
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
use crate::infrastructure::crypto::ZkCryptoProvider;
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
use crate::presentation::zk_models::{NoteData, NullifierData};
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
use orbinum_zk_core::NoteDto;

/// API for ZK cryptographic operations.
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub struct CryptoApi {
    provider: ZkCryptoProvider,
}

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
impl CryptoApi {
    /// Creates a new CryptoApi instance.
    pub fn new() -> Self {
        Self {
            provider: ZkCryptoProvider::new(),
        }
    }

    /// Creates a new note with commitment.
    pub fn create_note(
        &self,
        value: u128,
        asset_id: u32,
        owner_pubkey: [u8; 32],
        blinding: [u8; 32],
    ) -> Result<NoteData, String> {
        let note = self
            .provider
            .create_note(value, asset_id, owner_pubkey, blinding)
            .map_err(|e| format!("Failed to create note: {:?}", e))?;

        // Use NoteDto for serialization
        let dto = NoteDto::from_domain(&note);

        Ok(NoteData::new(
            dto.value as u128,
            AssetId::new(dto.asset_id as u32),
            dto.owner_pubkey,
            dto.blinding,
            // Commitment is not in NoteDto but we can compute it using provider
            self.provider.get_note_commitment(&note),
        ))
    }

    /// Computes commitment for a note.
    pub fn compute_commitment(
        &self,
        value: u128,
        asset_id: u32,
        owner_pubkey: [u8; 32],
        blinding: [u8; 32],
    ) -> Result<[u8; 32], String> {
        self.provider
            .compute_commitment(value, asset_id, owner_pubkey, blinding)
            .map_err(|e| format!("Failed to compute commitment: {:?}", e))
    }

    /// Computes nullifier for a note.
    pub fn compute_nullifier(
        &self,
        commitment: [u8; 32],
        spending_key: [u8; 32],
    ) -> Result<NullifierData, String> {
        let nullifier = self
            .provider
            .compute_nullifier(commitment, spending_key)
            .map_err(|e| format!("Failed to compute nullifier: {:?}", e))?;

        Ok(NullifierData::new(nullifier, commitment))
    }

    /// Computes Poseidon hash of 2 inputs.
    pub fn poseidon_hash_2(&self, left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32], String> {
        self.provider
            .poseidon_hash_2(left, right)
            .map_err(|e| format!("Failed to compute hash: {:?}", e))
    }

    /// Compute Poseidon hash of 4 inputs
    ///
    /// # Arguments
    /// * `inputs` - Array of 4 inputs (32 bytes each)
    ///
    /// # Returns
    /// Hash as 32-byte array
    ///
    /// # Example
    /// ```no_run
    /// use wallet_core_wasm::CryptoApi;
    ///
    /// let api = CryptoApi::new();
    /// let inputs = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    /// let hash = api.poseidon_hash_4(inputs).unwrap();
    /// ```
    pub fn poseidon_hash_4(&self, inputs: [[u8; 32]; 4]) -> Result<[u8; 32], String> {
        self.provider
            .poseidon_hash_4(inputs)
            .map_err(|e| format!("Failed to compute hash: {:?}", e))
    }
}

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
impl Default for CryptoApi {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, any(feature = "crypto-zk", feature = "crypto")))]
mod tests {
    use super::*;

    #[test]
    fn test_create_note() {
        let api = CryptoApi::new();
        let owner_pubkey = [1u8; 32];
        let blinding = [2u8; 32];

        let result = api.create_note(1000, 0, owner_pubkey, blinding);
        assert!(result.is_ok());

        let note = result.unwrap();
        assert_eq!(note.value, 1000);
        assert_eq!(note.asset_id.as_u32(), 0);
        assert_eq!(note.owner_pubkey, owner_pubkey);
        assert_eq!(note.blinding, blinding);
        assert_ne!(note.commitment, [0u8; 32]);
    }

    #[test]
    fn test_compute_commitment() {
        let api = CryptoApi::new();
        let result = api.compute_commitment(1000, 0, [1u8; 32], [2u8; 32]);
        assert!(result.is_ok());
        assert_ne!(result.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_compute_nullifier() {
        let api = CryptoApi::new();
        let commitment = [3u8; 32];
        let spending_key = [4u8; 32];

        let result = api.compute_nullifier(commitment, spending_key);
        assert!(result.is_ok());

        let nullifier_data = result.unwrap();
        assert_eq!(nullifier_data.commitment, commitment);
        assert_ne!(nullifier_data.nullifier, [0u8; 32]);
    }

    #[test]
    fn test_poseidon_hash_2() {
        let api = CryptoApi::new();
        let result = api.poseidon_hash_2([1u8; 32], [2u8; 32]);
        assert!(result.is_ok());
        assert_ne!(result.unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_poseidon_hash_4() {
        let api = CryptoApi::new();
        let inputs = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let result = api.poseidon_hash_4(inputs);
        assert!(result.is_ok());
        assert_ne!(result.unwrap(), [0u8; 32]);
    }
}
