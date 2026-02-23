//! Selective Disclosure – Witness Builder
//!
//! Builds circuit inputs for the `disclosure.circom` Groth16 circuit.
//!
//! ## Circuit Interface
//!
//! **Public inputs** (auditor sees):
//!   - `commitment`         – Note commitment (always revealed)
//!   - `revealed_value`     – Note value, or 0 if not disclosed
//!   - `revealed_asset_id`  – Asset ID, or 0 if not disclosed
//!   - `revealed_owner_hash`– Poseidon(owner_pubkey), or 0 if not disclosed
//!
//! **Private inputs** (prover only):
//!   - `value`, `asset_id`, `owner_pubkey`, `blinding`
//!   - `viewing_key = Poseidon(owner_pubkey)` — NOT the wallet viewing key
//!   - `disclose_value`, `disclose_asset_id`, `disclose_owner` (0 or 1)
//!
//! ## Key Design Note
//!
//! The circuit's `viewing_key` is `Poseidon(owner_pubkey)` — a ZK-friendly
//! ownership proof. This is distinct from the wallet viewing key (SHA-256 based)
//! used for memo encryption.

extern crate alloc;

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
use crate::infrastructure::crypto::ZkCryptoProvider;

use orbinum_encrypted_memo::{DisclosureMask, MemoData};

/// All circuit inputs for `disclosure.circom`.
///
/// Each field element is stored as 32 little-endian bytes matching the
/// internal arkworks / snarkjs byte representation.
///
/// The TypeScript consumer (`proof-generator/src/disclosure.ts`) converts
/// these bytes to decimal BigInt strings before calling snarkjs.
#[derive(Debug, Clone)]
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub struct DisclosureWitness {
    // ── Public inputs (the auditor receives these) ──
    /// The note commitment. Always revealed so the auditor can link to the pool.
    pub commitment: [u8; 32],
    /// `value` if `disclose_value`, else `0`.
    pub revealed_value: [u8; 32],
    /// `asset_id` if `disclose_asset_id`, else `0`.
    pub revealed_asset_id: [u8; 32],
    /// `Poseidon(owner_pubkey)` if `disclose_owner`, else `0`.
    pub revealed_owner_hash: [u8; 32],

    // ── Private inputs (the prover keeps secret) ──
    /// Note value as a field element.
    pub value: [u8; 32],
    /// Note asset ID as a field element.
    pub asset_id: [u8; 32],
    /// Owner public key (already a 32-byte field element).
    pub owner_pubkey: [u8; 32],
    /// Blinding factor (already a 32-byte field element).
    pub blinding: [u8; 32],
    /// `Poseidon(owner_pubkey)` – proves ownership without revealing spending key.
    pub viewing_key: [u8; 32],
    /// `true` if the value field will be disclosed.
    pub disclose_value: bool,
    /// `true` if the asset_id field will be disclosed.
    pub disclose_asset_id: bool,
    /// `true` if the owner (hash) field will be disclosed.
    pub disclose_owner: bool,
}

/// Error type for witness construction failures.
#[derive(Debug)]
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub enum DisclosureError {
    /// The DisclosureMask failed validation (e.g., no fields selected, or blinding set).
    InvalidMask(&'static str),
    /// A Poseidon / field-element conversion error.
    CryptoError(alloc::string::String),
}

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
impl core::fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DisclosureError::InvalidMask(msg) => write!(f, "Invalid disclosure mask: {msg}"),
            DisclosureError::CryptoError(msg) => write!(f, "Crypto error: {msg}"),
        }
    }
}

/// Builds all circuit inputs for the selective disclosure proof.
///
/// # Arguments
///
/// - `memo`       – Decrypted memo data containing the note's private fields.
/// - `commitment` – The 32-byte commitment that anchors the note in the Merkle tree.
/// - `mask`       – Which fields to reveal to the auditor.
///
/// # Returns
///
/// A [`DisclosureWitness`] ready to be serialized to JSON and passed to snarkjs/groth16-proofs.
///
/// # Errors
///
/// Returns [`DisclosureError::InvalidMask`] if the mask is invalid (blinding set, or empty).
/// Returns [`DisclosureError::CryptoError`] if Poseidon or byte conversion fails.
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub fn create_disclosure_witness(
    memo: &MemoData,
    commitment: &[u8; 32],
    mask: &DisclosureMask,
) -> Result<DisclosureWitness, DisclosureError> {
    // 1. Validate mask
    mask.validate()
        .map_err(|_| DisclosureError::InvalidMask("Disclosure mask validation failed"))?;

    let crypto = ZkCryptoProvider::new();

    // 2. Convert scalar fields to 32-byte field element representations
    let value_bytes = ZkCryptoProvider::u64_to_field_bytes(memo.value);
    let asset_id_bytes = ZkCryptoProvider::u64_to_field_bytes(memo.asset_id as u64);

    // 3. Compute viewing_key = Poseidon(owner_pubkey)
    //    This is the circuit's ownership check — distinct from the wallet viewing key.
    let viewing_key = crypto
        .poseidon_hash_1(memo.owner_pk)
        .map_err(DisclosureError::CryptoError)?;

    // 4. Compute public (revealed) signals based on mask
    let zero = [0u8; 32];
    let revealed_value = if mask.disclose_value {
        value_bytes
    } else {
        zero
    };
    let revealed_asset_id = if mask.disclose_asset_id {
        asset_id_bytes
    } else {
        zero
    };
    let revealed_owner_hash = if mask.disclose_owner {
        viewing_key
    } else {
        zero
    };

    Ok(DisclosureWitness {
        // Public inputs
        commitment: *commitment,
        revealed_value,
        revealed_asset_id,
        revealed_owner_hash,
        // Private inputs
        value: value_bytes,
        asset_id: asset_id_bytes,
        owner_pubkey: memo.owner_pk,
        blinding: memo.blinding,
        viewing_key,
        disclose_value: mask.disclose_value,
        disclose_asset_id: mask.disclose_asset_id,
        disclose_owner: mask.disclose_owner,
    })
}

#[cfg(test)]
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
mod tests {
    use super::*;

    fn make_memo(value: u64, asset_id: u32) -> MemoData {
        MemoData::new(value, [0x11u8; 32], [0x99u8; 32], asset_id)
    }

    fn make_commitment() -> [u8; 32] {
        [0x42u8; 32]
    }

    // ── Mask validation ──────────────────────────────────────────────────────

    #[test]
    fn test_empty_mask_rejected() {
        let memo = make_memo(100, 0);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: false,
            disclose_owner: false,
            disclose_asset_id: false,
            disclose_blinding: false,
        };
        let result = create_disclosure_witness(&memo, &commitment, &mask);
        assert!(matches!(result, Err(DisclosureError::InvalidMask(_))));
    }

    #[test]
    fn test_blinding_mask_rejected() {
        let memo = make_memo(100, 0);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: false,
            disclose_asset_id: false,
            disclose_blinding: true,
        };
        let result = create_disclosure_witness(&memo, &commitment, &mask);
        assert!(matches!(result, Err(DisclosureError::InvalidMask(_))));
    }

    // ── Reveal value only ───────────────────────────────────────────────────

    #[test]
    fn test_disclose_value_only() {
        let memo = make_memo(12345, 1);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: false,
            disclose_asset_id: false,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

        assert_eq!(w.commitment, commitment);
        assert_ne!(w.revealed_value, [0u8; 32], "value should be revealed");
        assert_eq!(w.revealed_asset_id, [0u8; 32], "asset_id should be hidden");
        assert_eq!(w.revealed_owner_hash, [0u8; 32], "owner should be hidden");

        assert!(w.disclose_value);
        assert!(!w.disclose_asset_id);
        assert!(!w.disclose_owner);
    }

    // ── Reveal asset_id only ────────────────────────────────────────────────

    #[test]
    fn test_disclose_asset_id_only() {
        let memo = make_memo(100, 42);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: false,
            disclose_owner: false,
            disclose_asset_id: true,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

        assert_eq!(w.revealed_value, [0u8; 32], "value should be hidden");
        assert_ne!(
            w.revealed_asset_id, [0u8; 32],
            "asset_id should be revealed"
        );
        assert_eq!(w.revealed_owner_hash, [0u8; 32], "owner should be hidden");
    }

    // ── Reveal owner hash only ──────────────────────────────────────────────

    #[test]
    fn test_disclose_owner_only() {
        let memo = make_memo(100, 1);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: false,
            disclose_owner: true,
            disclose_asset_id: false,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

        assert_eq!(w.revealed_value, [0u8; 32], "value should be hidden");
        assert_eq!(w.revealed_asset_id, [0u8; 32], "asset_id should be hidden");
        assert_ne!(
            w.revealed_owner_hash, [0u8; 32],
            "owner hash should be revealed"
        );

        // viewing_key == revealed_owner_hash when owner is disclosed
        assert_eq!(w.viewing_key, w.revealed_owner_hash);
    }

    // ── Reveal all fields ───────────────────────────────────────────────────

    #[test]
    fn test_disclose_all_fields() {
        let memo = make_memo(999, 7);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: true,
            disclose_asset_id: true,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

        assert_ne!(w.revealed_value, [0u8; 32]);
        assert_ne!(w.revealed_asset_id, [0u8; 32]);
        assert_ne!(w.revealed_owner_hash, [0u8; 32]);
        assert_eq!(w.viewing_key, w.revealed_owner_hash);
    }

    // ── value consistency ───────────────────────────────────────────────────

    #[test]
    fn test_revealed_value_matches_private_value() {
        let memo = make_memo(777, 0);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: false,
            disclose_asset_id: false,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
        assert_eq!(w.revealed_value, w.value);
    }

    // ── asset_id consistency ─────────────────────────────────────────────────

    #[test]
    fn test_revealed_asset_matches_private_asset() {
        let memo = make_memo(1, 99);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: false,
            disclose_owner: false,
            disclose_asset_id: true,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
        assert_eq!(w.revealed_asset_id, w.asset_id);
    }

    // ── zero value edge case ────────────────────────────────────────────────

    #[test]
    fn test_zero_value_disclosed() {
        // value=0 is a valid field element; its byte repr is [0;32]
        // but the test for "value hidden" uses zero too — they happen to match.
        // This test verifies the code runs without panic.
        let memo = make_memo(0, 0);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: false,
            disclose_asset_id: false,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &commitment, &mask);
        assert!(w.is_ok());
    }

    // ── commitment passthrough ─────────────────────────────────────────────

    #[test]
    fn test_commitment_passthrough() {
        let memo = make_memo(100, 0);
        let commitment = [0xABu8; 32];
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: false,
            disclose_asset_id: false,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
        assert_eq!(w.commitment, commitment);
    }

    // ── determinism ─────────────────────────────────────────────────────────

    #[test]
    fn test_witness_is_deterministic() {
        let memo = make_memo(42, 3);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: true,
            disclose_asset_id: true,
            disclose_blinding: false,
        };
        let w1 = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
        let w2 = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
        assert_eq!(w1.viewing_key, w2.viewing_key);
        assert_eq!(w1.revealed_owner_hash, w2.revealed_owner_hash);
    }

    // ── ZkCryptoProvider consistency ─────────────────────────────────────────

    #[test]
    fn test_viewing_key_equals_poseidon_of_owner_pubkey() {
        // viewing_key must match Poseidon(owner_pubkey) computed independently.
        // This verifies the Rust impl matches the circom constraint:
        //   viewing_key === Poseidon(owner_pubkey)
        use crate::infrastructure::crypto::ZkCryptoProvider;

        let owner_pk = [0x55u8; 32];
        let memo = MemoData::new(100, owner_pk, [0x77u8; 32], 0);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: false,
            disclose_owner: true,
            disclose_asset_id: false,
            disclose_blinding: false,
        };

        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

        let expected_vk = ZkCryptoProvider::new()
            .poseidon_hash_1(owner_pk)
            .expect("poseidon_hash_1 should succeed");

        assert_eq!(
            w.viewing_key, expected_vk,
            "viewing_key must equal Poseidon(owner_pubkey)"
        );
        assert_eq!(
            w.revealed_owner_hash, expected_vk,
            "revealed_owner_hash must equal Poseidon(owner_pubkey) when owner is disclosed"
        );
    }

    #[test]
    fn test_viewing_key_differs_from_zero_when_owner_hidden() {
        // Even when not disclosing the owner, viewing_key must still be
        // computed (non-zero) — it is a required private input.
        let owner_pk = [0xAAu8; 32];
        let memo = MemoData::new(50, owner_pk, [0xBBu8; 32], 2);
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: false,
            disclose_asset_id: false,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&memo, &make_commitment(), &mask).unwrap();

        // viewing_key (private input) is always the real Poseidon hash
        assert_ne!(
            w.viewing_key, [0u8; 32],
            "viewing_key must be non-zero even when owner is not disclosed"
        );
        // revealed_owner_hash (public input) is zero when not disclosing
        assert_eq!(
            w.revealed_owner_hash, [0u8; 32],
            "revealed_owner_hash must be zero when owner is not disclosed"
        );
    }

    #[test]
    fn test_real_commitment_passthrough() {
        // Compute a real commitment from the note data and verify it is
        // forwarded unmodified into the witness.
        use crate::infrastructure::crypto::ZkCryptoProvider;

        let value: u64 = 12_345;
        let owner_pk = [0x11u8; 32];
        let blinding = [0x22u8; 32];
        let asset_id: u32 = 7;

        let real_commitment = ZkCryptoProvider::new()
            .compute_commitment(value as u128, asset_id, owner_pk, blinding)
            .expect("commitment should be computable");

        let memo = MemoData::new(value, owner_pk, blinding, asset_id);
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: false,
            disclose_asset_id: false,
            disclose_blinding: false,
        };

        let w = create_disclosure_witness(&memo, &real_commitment, &mask).unwrap();

        assert_eq!(
            w.commitment, real_commitment,
            "witness commitment must equal the real computed commitment"
        );
    }

    #[test]
    fn test_private_fields_match_memo_data() {
        // Every private input in the witness must correspond to the original
        // MemoData values (field element representation may differ from raw bytes,
        // but same Poseidon commitment must be computable from them).
        use crate::infrastructure::crypto::ZkCryptoProvider;

        let value: u64 = 999;
        let owner_pk = [0xCCu8; 32];
        let blinding = [0xDDu8; 32];
        let asset_id: u32 = 3;

        let memo = MemoData::new(value, owner_pk, blinding, asset_id);
        let commitment = make_commitment();
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: true,
            disclose_asset_id: true,
            disclose_blinding: false,
        };

        let w = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

        // owner_pubkey and blinding pass through as-is (already field element bytes)
        assert_eq!(w.owner_pubkey, owner_pk);
        assert_eq!(w.blinding, blinding);

        // value and asset_id are encoded as field elements;
        // re-encode and compare
        let expected_value_fe = ZkCryptoProvider::u64_to_field_bytes(value);
        let expected_asset_fe = ZkCryptoProvider::u64_to_field_bytes(asset_id as u64);
        assert_eq!(w.value, expected_value_fe);
        assert_eq!(w.asset_id, expected_asset_fe);
    }

    // ── all valid mask combinations ──────────────────────────────────────────

    #[test]
    fn test_all_7_valid_mask_combinations() {
        // There are 2^3 = 8 combinations excluding the empty mask → 7 valid.
        let memo = make_memo(100, 1);
        let commitment = make_commitment();

        let combinations = [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ];

        for (dv, do_, da) in combinations {
            let mask = DisclosureMask {
                disclose_value: dv,
                disclose_owner: do_,
                disclose_asset_id: da,
                disclose_blinding: false,
            };
            let result = create_disclosure_witness(&memo, &commitment, &mask);
            assert!(
                result.is_ok(),
                "mask (value={dv}, owner={do_}, asset={da}) should succeed"
            );

            let w = result.unwrap();
            // Zero iff not disclosed
            assert_eq!(w.revealed_value != [0u8; 32], dv);
            assert_eq!(w.revealed_owner_hash != [0u8; 32], do_);
            assert_eq!(w.revealed_asset_id != [0u8; 32], da);
        }
    }

    // ── full round-trip: encrypt → decrypt → witness ─────────────────────────

    #[test]
    #[cfg(feature = "std")]
    fn test_encrypt_decrypt_then_build_witness() {
        // Full integration: create a memo, encrypt it, decrypt it back,
        // then build the disclosure witness from the decrypted data.
        use crate::application::memo_utils::{create_encrypted_memo, decrypt_encrypted_memo};

        let value: u64 = 5_000;
        let owner_pk = [0x33u8; 32];
        let blinding = [0x44u8; 32];
        let asset_id: u32 = 7; // non-zero so its field element is also non-zero
        let commitment = [0xFFu8; 32];
        let viewing_key = [0x55u8; 32];

        // Encrypt
        let encrypted = create_encrypted_memo(
            value,
            owner_pk,
            blinding,
            asset_id,
            &commitment,
            &viewing_key,
        )
        .expect("encryption should succeed");

        assert_eq!(encrypted.len(), 104, "encrypted memo must be 104 bytes");

        // Decrypt
        let decrypted = decrypt_encrypted_memo(&encrypted, &commitment, &viewing_key)
            .expect("decryption should succeed");

        assert_eq!(decrypted.value, value);
        assert_eq!(decrypted.owner_pk, owner_pk);
        assert_eq!(decrypted.blinding, blinding);
        assert_eq!(decrypted.asset_id, asset_id);

        // Build witness from decrypted data
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: true,
            disclose_asset_id: true,
            disclose_blinding: false,
        };

        let w = create_disclosure_witness(&decrypted, &commitment, &mask)
            .expect("witness from decrypted memo should succeed");

        // Commitment passthrough
        assert_eq!(w.commitment, commitment);
        // Private fields match original
        assert_eq!(w.owner_pubkey, owner_pk);
        assert_eq!(w.blinding, blinding);
        // Disclosed: revealed == private input (exact field element equality)
        assert_eq!(
            w.revealed_value, w.value,
            "revealed_value must match private value"
        );
        assert_eq!(
            w.revealed_asset_id, w.asset_id,
            "revealed_asset_id must match private asset_id"
        );
        assert_eq!(
            w.revealed_owner_hash, w.viewing_key,
            "revealed_owner_hash must match viewing_key"
        );
        // All three are non-zero since we used non-zero inputs
        assert_ne!(w.revealed_value, [0u8; 32]);
        assert_ne!(w.revealed_owner_hash, [0u8; 32]);
        assert_ne!(w.revealed_asset_id, [0u8; 32]);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_encrypt_decrypt_witness_with_real_commitment() {
        // Full integration using a commitment computed from the actual note data —
        // the same commitment that would be stored on-chain.
        use crate::application::memo_utils::{create_encrypted_memo, decrypt_encrypted_memo};
        use crate::infrastructure::crypto::ZkCryptoProvider;

        let value: u64 = 100_000_000; // 100 ORB (in base units)
        let owner_pk = [0x77u8; 32];
        let blinding = [0x88u8; 32];
        let asset_id: u32 = 0; // ORB asset_id is 0 — field element == [0;32]
        let viewing_key = [0x99u8; 32];

        // Compute commitment exactly as the protocol does on shield
        let real_commitment = ZkCryptoProvider::new()
            .compute_commitment(value as u128, asset_id, owner_pk, blinding)
            .expect("commitment computation should succeed");

        // Encrypt and decrypt
        let encrypted = create_encrypted_memo(
            value,
            owner_pk,
            blinding,
            asset_id,
            &real_commitment,
            &viewing_key,
        )
        .expect("encryption should succeed");

        let decrypted = decrypt_encrypted_memo(&encrypted, &real_commitment, &viewing_key)
            .expect("decryption should succeed");

        // Build witness
        let mask = DisclosureMask {
            disclose_value: true,
            disclose_owner: false,
            disclose_asset_id: true,
            disclose_blinding: false,
        };
        let w = create_disclosure_witness(&decrypted, &real_commitment, &mask).unwrap();

        // The witness commitment is the on-chain commitment
        assert_eq!(w.commitment, real_commitment);
        // Disclosed: revealed == private (even for zero-valued fields)
        assert_eq!(
            w.revealed_value, w.value,
            "revealed_value must match private value"
        );
        assert_eq!(
            w.revealed_asset_id, w.asset_id,
            "revealed_asset_id must match private asset_id"
        );
        // value=100_000_000 → non-zero field element
        assert_ne!(w.revealed_value, [0u8; 32]);
        // asset_id=0 → zero field element (correct — ORB asset has id=0)
        assert_eq!(
            w.revealed_asset_id, [0u8; 32],
            "asset_id=0 field element is zero"
        );
        assert_eq!(w.revealed_owner_hash, [0u8; 32], "owner not disclosed");

        // viewing_key is always present (private circuit input)
        assert_ne!(w.viewing_key, [0u8; 32]);
    }
}
