//! WASM Bindings for JavaScript/TypeScript

use alloc::string::{String, ToString};
use alloc::vec::Vec;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use crate::presentation::api::TransactionApi;

#[cfg(target_arch = "wasm32")]
use crate::application::params::{
    AuditorInfo, DisclosureConditionType, DisclosureSubmission, ShieldOperation,
};

#[cfg(target_arch = "wasm32")]
use crate::domain::types::{Address, AssetId, Commitment};

#[cfg(all(target_arch = "wasm32", feature = "crypto-signing"))]
use crate::presentation::api::SigningApi;

/// WASM transaction builder.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct TransactionBuilder;

// CryptoApi available with crypto-zk feature (WASM-compatible)
#[cfg(all(target_arch = "wasm32", any(feature = "crypto-zk", feature = "crypto")))]
use crate::presentation::crypto_api::CryptoApi;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl TransactionBuilder {
    /// Builds unsigned Shield transaction.
    #[wasm_bindgen(js_name = buildShieldUnsigned)]
    pub fn build_shield_unsigned(
        amount: String,
        asset_id: u32,
        commitment: Vec<u8>,
        encrypted_memo: Vec<u8>,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        let amount: u128 = amount
            .parse()
            .map_err(|_| JsValue::from_str("Invalid amount"))?;

        if commitment.len() != 32 {
            return Err(JsValue::from_str("Commitment must be 32 bytes"));
        }

        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&commitment);

        Ok(TransactionApi::build_shield_unsigned(
            amount,
            asset_id,
            commitment_bytes,
            encrypted_memo,
            nonce,
        ))
    }

    /// Builds unsigned Unshield transaction.
    #[wasm_bindgen(js_name = buildUnshieldUnsigned)]
    pub fn build_unshield_unsigned(
        nullifier: Vec<u8>,
        amount: String,
        asset_id: u32,
        recipient: Vec<u8>,
        root: Vec<u8>,
        proof: Vec<u8>,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        let amount: u128 = amount
            .parse()
            .map_err(|_| JsValue::from_str("Invalid amount"))?;

        if nullifier.len() != 32 {
            return Err(JsValue::from_str("Nullifier must be 32 bytes"));
        }
        if recipient.len() != 32 {
            return Err(JsValue::from_str("Recipient must be 32 bytes"));
        }
        if root.len() != 32 {
            return Err(JsValue::from_str("Root must be 32 bytes"));
        }

        let mut nullifier_bytes = [0u8; 32];
        let mut recipient_bytes = [0u8; 32];
        let mut root_bytes = [0u8; 32];
        nullifier_bytes.copy_from_slice(&nullifier);
        recipient_bytes.copy_from_slice(&recipient);
        root_bytes.copy_from_slice(&root);

        Ok(TransactionApi::build_unshield_unsigned(
            nullifier_bytes,
            amount,
            asset_id,
            recipient_bytes,
            root_bytes,
            proof,
            nonce,
        ))
    }

    /// Builds unsigned Private Transfer transaction.
    #[wasm_bindgen(js_name = buildTransferUnsigned)]
    pub fn build_transfer_unsigned(
        input_nullifiers: Vec<u8>,
        output_commitments: Vec<u8>,
        root: Vec<u8>,
        proof: Vec<u8>,
        encrypted_memos_js: js_sys::Array,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        // Validate input nullifiers (2 × 32 bytes)
        if input_nullifiers.len() != 64 {
            return Err(JsValue::from_str(
                "Input nullifiers must be 64 bytes (2 × 32)",
            ));
        }

        // Validate output commitments (2 × 32 bytes)
        if output_commitments.len() != 64 {
            return Err(JsValue::from_str(
                "Output commitments must be 64 bytes (2 × 32)",
            ));
        }

        // Validate merkle root
        if root.len() != 32 {
            return Err(JsValue::from_str("Root must be 32 bytes"));
        }

        // Convert encrypted_memos from JS array
        if encrypted_memos_js.length() != 2 {
            return Err(JsValue::from_str("Must provide exactly 2 encrypted memos"));
        }

        let mut encrypted_memos: Vec<Vec<u8>> = Vec::new();
        for i in 0..2 {
            let val = encrypted_memos_js.get(i);
            if val.is_null() || val.is_undefined() {
                return Err(JsValue::from_str("Encrypted memo cannot be null/undefined"));
            }
            let array = js_sys::Uint8Array::new(&val);
            let vec = array.to_vec();
            if vec.is_empty() {
                // removed > 256 check for strict equality? or keep it?
                // Keep minimal check
                return Err(JsValue::from_str("Encrypted memo cannot be empty"));
            }
            encrypted_memos.push(vec);
        }

        // Convert to fixed-size arrays
        let mut nullifiers_array: [[u8; 32]; 2] = [[0u8; 32]; 2];
        nullifiers_array[0].copy_from_slice(&input_nullifiers[0..32]);
        nullifiers_array[1].copy_from_slice(&input_nullifiers[32..64]);

        let mut commitments_array: [[u8; 32]; 2] = [[0u8; 32]; 2];
        commitments_array[0].copy_from_slice(&output_commitments[0..32]);
        commitments_array[1].copy_from_slice(&output_commitments[32..64]);

        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(&root);

        let memos_array: [Vec<u8>; 2] = [encrypted_memos[0].clone(), encrypted_memos[1].clone()];

        Ok(TransactionApi::build_transfer_unsigned(
            nullifiers_array,
            commitments_array,
            root_bytes,
            proof,
            memos_array,
            nonce,
        ))
    }

    /// Builds unsigned Shield Batch transaction.
    #[wasm_bindgen(js_name = buildShieldBatchUnsigned)]
    pub fn build_shield_batch_unsigned(
        operations_js: js_sys::Array,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        let mut operations: Vec<ShieldOperation> = Vec::new();

        for i in 0..operations_js.length() {
            let op = operations_js.get(i);

            let asset_id_val = js_sys::Reflect::get(&op, &JsValue::from_str("assetId"))?;
            let amount_val = js_sys::Reflect::get(&op, &JsValue::from_str("amount"))?;
            let commitment_val = js_sys::Reflect::get(&op, &JsValue::from_str("commitment"))?;
            let memo_val = js_sys::Reflect::get(&op, &JsValue::from_str("encryptedMemo"))?;

            let asset_id = asset_id_val
                .as_f64()
                .ok_or_else(|| JsValue::from_str("assetId must be a number"))?
                as u32;

            let amount_str = amount_val
                .as_string()
                .ok_or_else(|| JsValue::from_str("amount must be a string"))?;
            let amount: u128 = amount_str
                .parse()
                .map_err(|_| JsValue::from_str("Invalid amount"))?;

            let commitment = js_sys::Uint8Array::new(&commitment_val).to_vec();
            if commitment.len() != 32 {
                return Err(JsValue::from_str("Commitment must be 32 bytes"));
            }
            let mut commitment_bytes = [0u8; 32];
            commitment_bytes.copy_from_slice(&commitment);

            let encrypted_memo = js_sys::Uint8Array::new(&memo_val).to_vec();

            operations.push(ShieldOperation {
                asset_id: AssetId::new(asset_id),
                amount,
                commitment: Commitment::from_bytes(commitment_bytes)
                    .map_err(|_| JsValue::from_str("Invalid commitment"))?,
                encrypted_memo,
            });
        }

        Ok(TransactionApi::build_shield_batch_unsigned(
            operations, nonce,
        ))
    }

    /// Builds unsigned Set Audit Policy transaction.
    #[wasm_bindgen(js_name = buildSetAuditPolicyUnsigned)]
    pub fn build_set_audit_policy_unsigned(
        auditors_js: js_sys::Array,
        conditions_js: js_sys::Array,
        max_frequency: Option<u32>,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        let mut auditors: Vec<AuditorInfo> = Vec::new();
        for i in 0..auditors_js.length() {
            let item = auditors_js.get(i);
            let account_val = js_sys::Reflect::get(&item, &JsValue::from_str("account"))?;
            let public_key_val = js_sys::Reflect::get(&item, &JsValue::from_str("publicKey"))?;
            let authorized_from_val =
                js_sys::Reflect::get(&item, &JsValue::from_str("authorizedFrom"))?;

            let account = js_sys::Uint8Array::new(&account_val).to_vec();
            if account.len() != 32 {
                return Err(JsValue::from_str("Auditor account must be 32 bytes"));
            }
            let mut account_bytes = [0u8; 32];
            account_bytes.copy_from_slice(&account);

            let public_key = if public_key_val.is_null() || public_key_val.is_undefined() {
                None
            } else {
                let pk = js_sys::Uint8Array::new(&public_key_val).to_vec();
                if pk.len() != 32 {
                    return Err(JsValue::from_str("Auditor publicKey must be 32 bytes"));
                }
                let mut pk_bytes = [0u8; 32];
                pk_bytes.copy_from_slice(&pk);
                Some(pk_bytes)
            };

            let authorized_from = authorized_from_val
                .as_f64()
                .ok_or_else(|| JsValue::from_str("authorizedFrom must be a number"))?
                as u32;

            auditors.push(AuditorInfo {
                account: Address::from_slice(&account_bytes)
                    .map_err(|_| JsValue::from_str("Invalid auditor account"))?,
                public_key,
                authorized_from,
            });
        }

        let mut conditions: Vec<DisclosureConditionType> = Vec::new();
        for i in 0..conditions_js.length() {
            let item = conditions_js.get(i);
            let cond_type = js_sys::Reflect::get(&item, &JsValue::from_str("type"))?
                .as_string()
                .ok_or_else(|| JsValue::from_str("condition.type must be a string"))?;

            let condition = match cond_type.as_str() {
                "AmountAbove" => {
                    let threshold = js_sys::Reflect::get(&item, &JsValue::from_str("threshold"))?
                        .as_string()
                        .ok_or_else(|| JsValue::from_str("threshold must be a string"))?
                        .parse::<u128>()
                        .map_err(|_| JsValue::from_str("Invalid threshold"))?;
                    DisclosureConditionType::AmountAbove(threshold)
                }
                "TimeElapsed" => {
                    let blocks = js_sys::Reflect::get(&item, &JsValue::from_str("blocks"))?
                        .as_f64()
                        .ok_or_else(|| JsValue::from_str("blocks must be a number"))?
                        as u32;
                    DisclosureConditionType::TimeElapsed(blocks)
                }
                "ManualApproval" => DisclosureConditionType::ManualApproval,
                _ => return Err(JsValue::from_str("Unknown condition type")),
            };

            conditions.push(condition);
        }

        Ok(TransactionApi::build_set_audit_policy_unsigned(
            auditors,
            conditions,
            max_frequency,
            nonce,
        ))
    }

    /// Builds unsigned Request Disclosure transaction.
    #[wasm_bindgen(js_name = buildRequestDisclosureUnsigned)]
    pub fn build_request_disclosure_unsigned(
        target: Vec<u8>,
        reason: Vec<u8>,
        evidence: Option<Vec<u8>>,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        if target.len() != 32 {
            return Err(JsValue::from_str("Target must be 32 bytes"));
        }

        let mut target_bytes = [0u8; 32];
        target_bytes.copy_from_slice(&target);

        Ok(TransactionApi::build_request_disclosure_unsigned(
            target_bytes,
            reason,
            evidence,
            nonce,
        ))
    }

    /// Builds unsigned Approve Disclosure transaction.
    #[wasm_bindgen(js_name = buildApproveDisclosureUnsigned)]
    pub fn build_approve_disclosure_unsigned(
        auditor: Vec<u8>,
        commitment: Vec<u8>,
        zk_proof: Vec<u8>,
        disclosed_data: Vec<u8>,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        if auditor.len() != 32 {
            return Err(JsValue::from_str("Auditor must be 32 bytes"));
        }
        if commitment.len() != 32 {
            return Err(JsValue::from_str("Commitment must be 32 bytes"));
        }

        let mut auditor_bytes = [0u8; 32];
        let mut commitment_bytes = [0u8; 32];
        auditor_bytes.copy_from_slice(&auditor);
        commitment_bytes.copy_from_slice(&commitment);

        Ok(TransactionApi::build_approve_disclosure_unsigned(
            auditor_bytes,
            commitment_bytes,
            zk_proof,
            disclosed_data,
            nonce,
        ))
    }

    /// Builds unsigned Reject Disclosure transaction.
    #[wasm_bindgen(js_name = buildRejectDisclosureUnsigned)]
    pub fn build_reject_disclosure_unsigned(
        auditor: Vec<u8>,
        reason: Vec<u8>,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        if auditor.len() != 32 {
            return Err(JsValue::from_str("Auditor must be 32 bytes"));
        }

        let mut auditor_bytes = [0u8; 32];
        auditor_bytes.copy_from_slice(&auditor);

        Ok(TransactionApi::build_reject_disclosure_unsigned(
            auditor_bytes,
            reason,
            nonce,
        ))
    }

    /// Builds unsigned Submit Disclosure transaction.
    #[wasm_bindgen(js_name = buildSubmitDisclosureUnsigned)]
    pub fn build_submit_disclosure_unsigned(
        commitment: Vec<u8>,
        proof_bytes: Vec<u8>,
        public_signals: Vec<u8>,
        partial_data: Vec<u8>,
        auditor: Option<Vec<u8>>,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        if commitment.len() != 32 {
            return Err(JsValue::from_str("Commitment must be 32 bytes"));
        }

        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&commitment);

        let auditor_bytes = match auditor {
            Some(a) => {
                if a.len() != 32 {
                    return Err(JsValue::from_str("Auditor must be 32 bytes"));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&a);
                Some(out)
            }
            None => None,
        };

        Ok(TransactionApi::build_submit_disclosure_unsigned(
            commitment_bytes,
            proof_bytes,
            public_signals,
            partial_data,
            auditor_bytes,
            nonce,
        ))
    }

    /// Builds unsigned Batch Submit Disclosure transaction.
    #[wasm_bindgen(js_name = buildBatchSubmitDisclosureUnsigned)]
    pub fn build_batch_submit_disclosure_unsigned(
        submissions_js: js_sys::Array,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        let mut submissions: Vec<DisclosureSubmission> = Vec::new();

        for i in 0..submissions_js.length() {
            let item = submissions_js.get(i);
            let commitment_val = js_sys::Reflect::get(&item, &JsValue::from_str("commitment"))?;
            let proof_val = js_sys::Reflect::get(&item, &JsValue::from_str("proof"))?;
            let public_signals_val =
                js_sys::Reflect::get(&item, &JsValue::from_str("publicSignals"))?;
            let disclosed_data_val =
                js_sys::Reflect::get(&item, &JsValue::from_str("disclosedData"))?;

            let commitment = js_sys::Uint8Array::new(&commitment_val).to_vec();
            if commitment.len() != 32 {
                return Err(JsValue::from_str("Submission commitment must be 32 bytes"));
            }
            let mut commitment_bytes = [0u8; 32];
            commitment_bytes.copy_from_slice(&commitment);

            submissions.push(DisclosureSubmission {
                commitment: Commitment::from_bytes(commitment_bytes)
                    .map_err(|_| JsValue::from_str("Invalid submission commitment"))?,
                proof: js_sys::Uint8Array::new(&proof_val).to_vec(),
                public_signals: js_sys::Uint8Array::new(&public_signals_val).to_vec(),
                disclosed_data: js_sys::Uint8Array::new(&disclosed_data_val).to_vec(),
            });
        }

        Ok(TransactionApi::build_batch_submit_disclosure_unsigned(
            submissions,
            nonce,
        ))
    }

    /// Combines call data with external signature.
    #[wasm_bindgen(js_name = buildSignedExtrinsic)]
    pub fn build_signed_extrinsic(
        call_data: Vec<u8>,
        signature: Vec<u8>,
        address: Vec<u8>,
        nonce: u32,
    ) -> Result<Vec<u8>, JsValue> {
        if address.len() != 32 {
            return Err(JsValue::from_str("Address must be 32 bytes"));
        }

        let mut address_bytes = [0u8; 32];
        address_bytes.copy_from_slice(&address);

        Ok(TransactionApi::build_signed_extrinsic(
            call_data,
            signature,
            address_bytes,
            nonce,
        ))
    }
}

/// WASM signing API (requires "crypto" feature).
#[cfg(all(target_arch = "wasm32", feature = "crypto"))]
#[wasm_bindgen]
pub struct Signer;

#[cfg(all(target_arch = "wasm32", feature = "crypto"))]
#[wasm_bindgen]
impl Signer {
    /// Signs and builds complete Shield transaction.
    #[wasm_bindgen(js_name = signAndBuildShield)]
    pub fn sign_and_build_shield(
        amount: String,
        asset_id: u32,
        commitment: Vec<u8>,
        nonce: u32,
        private_key_hex: String,
    ) -> Result<Vec<u8>, JsValue> {
        let amount: u128 = amount
            .parse()
            .map_err(|_| JsValue::from_str("Invalid amount"))?;

        if commitment.len() != 32 {
            return Err(JsValue::from_str("Commitment must be 32 bytes"));
        }

        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&commitment);

        SigningApi::sign_and_build_shield(
            amount,
            asset_id,
            commitment_bytes,
            nonce,
            &private_key_hex,
        )
        .map_err(|e| JsValue::from_str(&format!("Signing error: {:?}", e)))
    }

    /// Signs and builds complete Private Transfer transaction.
    #[wasm_bindgen(js_name = signAndBuildTransfer)]
    pub fn sign_and_build_transfer(
        input_nullifiers: Vec<u8>,
        output_commitments: Vec<u8>,
        root: Vec<u8>,
        proof: Vec<u8>,
        encrypted_memos_js: js_sys::Array,
        nonce: u32,
        private_key_hex: String,
    ) -> Result<Vec<u8>, JsValue> {
        // Validate input nullifiers (2 × 32 bytes)
        if input_nullifiers.len() != 64 {
            return Err(JsValue::from_str(
                "Input nullifiers must be 64 bytes (2 × 32)",
            ));
        }

        // Validate output commitments (2 × 32 bytes)
        if output_commitments.len() != 64 {
            return Err(JsValue::from_str(
                "Output commitments must be 64 bytes (2 × 32)",
            ));
        }

        // Validate merkle root
        if root.len() != 32 {
            return Err(JsValue::from_str("Root must be 32 bytes"));
        }

        // Convert encrypted_memos from JS array
        if encrypted_memos_js.length() != 2 {
            return Err(JsValue::from_str("Must provide exactly 2 encrypted memos"));
        }

        let mut encrypted_memos: Vec<Vec<u8>> = Vec::new();
        for i in 0..2 {
            let val = encrypted_memos_js.get(i);
            if val.is_null() || val.is_undefined() {
                return Err(JsValue::from_str("Encrypted memo cannot be null/undefined"));
            }
            let array = js_sys::Uint8Array::new(&val);
            let vec = array.to_vec();
            encrypted_memos.push(vec);
        }

        // Convert to fixed-size arrays
        let mut nullifiers_array: [[u8; 32]; 2] = [[0u8; 32]; 2];
        nullifiers_array[0].copy_from_slice(&input_nullifiers[0..32]);
        nullifiers_array[1].copy_from_slice(&input_nullifiers[32..64]);

        let mut commitments_array: [[u8; 32]; 2] = [[0u8; 32]; 2];
        commitments_array[0].copy_from_slice(&output_commitments[0..32]);
        commitments_array[1].copy_from_slice(&output_commitments[32..64]);

        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(&root);

        let memos_array: [Vec<u8>; 2] = [encrypted_memos[0].clone(), encrypted_memos[1].clone()];

        SigningApi::sign_and_build_transfer(
            nullifiers_array,
            commitments_array,
            root_bytes,
            proof,
            memos_array,
            nonce,
            &private_key_hex,
        )
        .map_err(|e| JsValue::from_str(&format!("Signing error: {:?}", e)))
    }

    /// Gets address from private key.
    #[wasm_bindgen(js_name = getAddress)]
    pub fn get_address(private_key_hex: String) -> Result<Vec<u8>, JsValue> {
        SigningApi::get_address(&private_key_hex)
            .map(|addr| addr.to_vec())
            .map_err(|e| JsValue::from_str(&format!("Invalid key: {:?}", e)))
    }
}

/// WASM bindings for ZK cryptographic operations
#[cfg(all(target_arch = "wasm32", any(feature = "crypto-zk", feature = "crypto")))]
#[wasm_bindgen]
pub struct Crypto;

#[cfg(all(target_arch = "wasm32", any(feature = "crypto-zk", feature = "crypto")))]
#[wasm_bindgen]
impl Crypto {
    /// Creates note with commitment.
    #[wasm_bindgen(js_name = createNote)]
    pub fn create_note(
        value: String,
        asset_id: u32,
        owner_pubkey: Vec<u8>,
        blinding: Vec<u8>,
    ) -> Result<JsValue, JsValue> {
        let value: u128 = value
            .parse()
            .map_err(|_| JsValue::from_str("Invalid value"))?;

        if owner_pubkey.len() != 32 {
            return Err(JsValue::from_str("Owner pubkey must be 32 bytes"));
        }
        if blinding.len() != 32 {
            return Err(JsValue::from_str("Blinding must be 32 bytes"));
        }

        let mut owner_bytes = [0u8; 32];
        let mut blinding_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&owner_pubkey);
        blinding_bytes.copy_from_slice(&blinding);

        let api = CryptoApi::new();
        let note = api
            .create_note(value, asset_id, owner_bytes, blinding_bytes)
            .map_err(|e: String| JsValue::from_str(&e))?;

        // Serialize to JSON
        serde_wasm_bindgen::to_value(&note).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Computes commitment for a note.
    #[cfg(any(feature = "crypto-zk", feature = "crypto"))]
    #[wasm_bindgen(js_name = computeCommitment)]
    pub fn compute_commitment(
        value: String,
        asset_id: u32,
        owner_pubkey: Vec<u8>,
        blinding: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        let value: u128 = value
            .parse()
            .map_err(|_| JsValue::from_str("Invalid value"))?;

        if owner_pubkey.len() != 32 {
            return Err(JsValue::from_str("Owner pubkey must be 32 bytes"));
        }
        if blinding.len() != 32 {
            return Err(JsValue::from_str("Blinding must be 32 bytes"));
        }

        let mut owner_bytes = [0u8; 32];
        let mut blinding_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&owner_pubkey);
        blinding_bytes.copy_from_slice(&blinding);

        let api = CryptoApi::new();
        let commitment = api
            .compute_commitment(value, asset_id, owner_bytes, blinding_bytes)
            .map_err(|e: String| JsValue::from_str(&e))?;

        Ok(commitment.to_vec())
    }

    /// Computes nullifier for a note.
    #[cfg(any(feature = "crypto-zk", feature = "crypto"))]
    #[wasm_bindgen(js_name = computeNullifier)]
    pub fn compute_nullifier(
        commitment: Vec<u8>,
        spending_key: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        if commitment.len() != 32 {
            return Err(JsValue::from_str("Commitment must be 32 bytes"));
        }
        if spending_key.len() != 32 {
            return Err(JsValue::from_str("Spending key must be 32 bytes"));
        }

        let mut commitment_bytes = [0u8; 32];
        let mut spending_key_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&commitment);
        spending_key_bytes.copy_from_slice(&spending_key);

        let api = CryptoApi::new();
        let nullifier_data = api
            .compute_nullifier(commitment_bytes, spending_key_bytes)
            .map_err(|e: String| JsValue::from_str(&e))?;

        Ok(nullifier_data.nullifier.to_vec())
    }

    /// Computes Poseidon hash of 2 inputs.
    #[cfg(any(feature = "crypto-zk", feature = "crypto"))]
    #[wasm_bindgen(js_name = poseidonHash2)]
    pub fn poseidon_hash_2(left: Vec<u8>, right: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        if left.len() != 32 {
            return Err(JsValue::from_str("Left input must be 32 bytes"));
        }
        if right.len() != 32 {
            return Err(JsValue::from_str("Right input must be 32 bytes"));
        }

        let mut left_bytes = [0u8; 32];
        let mut right_bytes = [0u8; 32];
        left_bytes.copy_from_slice(&left);
        right_bytes.copy_from_slice(&right);

        let api = CryptoApi::new();
        let hash = api
            .poseidon_hash_2(left_bytes, right_bytes)
            .map_err(|e: String| JsValue::from_str(&e))?;

        Ok(hash.to_vec())
    }

    /// Computes Poseidon hash of 4 inputs.
    #[cfg(any(feature = "crypto-zk", feature = "crypto"))]
    #[wasm_bindgen(js_name = poseidonHash4)]
    pub fn poseidon_hash_4(inputs: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        if inputs.len() != 128 {
            return Err(JsValue::from_str("Inputs must be 128 bytes (4 x 32)"));
        }

        let mut input_array: [[u8; 32]; 4] = [[0u8; 32]; 4];
        for i in 0..4 {
            input_array[i].copy_from_slice(&inputs[i * 32..(i + 1) * 32]);
        }

        let api = CryptoApi::new();
        let hash = api
            .poseidon_hash_4(input_array)
            .map_err(|e: String| JsValue::from_str(&e))?;

        Ok(hash.to_vec())
    }

    /// Builds all circuit inputs for the selective disclosure proof.
    ///
    /// Returns a JSON object with the following fields (all as hex strings):
    /// - `commitment`, `revealed_value`, `revealed_asset_id`, `revealed_owner_hash`
    ///   (public inputs – what the auditor receives)
    /// - `value`, `asset_id`, `owner_pubkey`, `blinding`, `viewing_key`
    ///   (private inputs – kept secret by the prover)
    /// - `disclose_value`, `disclose_asset_id`, `disclose_owner` (booleans as 0/1 strings)
    ///
    /// The TypeScript consumer converts hex values to BigInt decimal strings before
    /// passing them to snarkjs / groth16-proofs.
    ///
    /// # Parameters
    ///
    /// - `value`              – Note value (u64 as decimal string, e.g. `"100000000"`)
    /// - `owner_pk`           – Owner public key (32 bytes)
    /// - `blinding`           – Blinding factor (32 bytes)
    /// - `asset_id`           – Asset ID (u32)
    /// - `commitment`         – Note commitment (32 bytes)
    /// - `disclose_value`     – Whether to reveal the value
    /// - `disclose_owner`     – Whether to reveal the owner hash
    /// - `disclose_asset_id`  – Whether to reveal the asset ID
    #[cfg(any(feature = "crypto-zk", feature = "crypto"))]
    #[wasm_bindgen(js_name = buildDisclosureInputs)]
    pub fn build_disclosure_inputs(
        value: String,
        owner_pk: Vec<u8>,
        blinding: Vec<u8>,
        asset_id: u32,
        commitment: Vec<u8>,
        disclose_value: bool,
        disclose_owner: bool,
        disclose_asset_id: bool,
    ) -> Result<JsValue, JsValue> {
        use crate::application::disclosure::create_disclosure_witness;
        use orbinum_encrypted_memo::{DisclosureMask, MemoData};

        // Parse value
        let value_u64: u64 = value
            .parse()
            .map_err(|_| JsValue::from_str("Invalid value: must be a u64 decimal string"))?;

        // Validate byte slices
        if owner_pk.len() != 32 {
            return Err(JsValue::from_str("owner_pk must be 32 bytes"));
        }
        if blinding.len() != 32 {
            return Err(JsValue::from_str("blinding must be 32 bytes"));
        }
        if commitment.len() != 32 {
            return Err(JsValue::from_str("commitment must be 32 bytes"));
        }

        let mut owner_pk_bytes = [0u8; 32];
        let mut blinding_bytes = [0u8; 32];
        let mut commitment_bytes = [0u8; 32];
        owner_pk_bytes.copy_from_slice(&owner_pk);
        blinding_bytes.copy_from_slice(&blinding);
        commitment_bytes.copy_from_slice(&commitment);

        // Build domain types
        let memo = MemoData::new(value_u64, owner_pk_bytes, blinding_bytes, asset_id);
        let mask = DisclosureMask {
            disclose_value,
            disclose_owner,
            disclose_asset_id,
            disclose_blinding: false, // MUST always be false
        };

        // Build witness
        let w = create_disclosure_witness(&memo, &commitment_bytes, &mask)
            .map_err(|e| JsValue::from_str(&format!("{e}")))?;

        // Helper: bytes to "0x{hex}" string
        fn to_hex(b: &[u8; 32]) -> String {
            let mut s = String::with_capacity(66);
            s.push_str("0x");
            for byte in b {
                s.push_str(&format!("{byte:02x}"));
            }
            s
        }

        // Serialize to JS object
        let obj = js_sys::Object::new();
        macro_rules! set_hex {
            ($key:expr, $val:expr) => {
                js_sys::Reflect::set(&obj, &$key.into(), &to_hex($val).into())?;
            };
        }
        macro_rules! set_bool {
            ($key:expr, $val:expr) => {
                js_sys::Reflect::set(&obj, &$key.into(), &(if $val { "1" } else { "0" }).into())?;
            };
        }

        // Public inputs
        set_hex!("commitment", &w.commitment);
        set_hex!("revealed_value", &w.revealed_value);
        set_hex!("revealed_asset_id", &w.revealed_asset_id);
        set_hex!("revealed_owner_hash", &w.revealed_owner_hash);

        // Private inputs
        set_hex!("value", &w.value);
        set_hex!("asset_id", &w.asset_id);
        set_hex!("owner_pubkey", &w.owner_pubkey);
        set_hex!("blinding", &w.blinding);
        set_hex!("viewing_key", &w.viewing_key);
        set_bool!("disclose_value", w.disclose_value);
        set_bool!("disclose_asset_id", w.disclose_asset_id);
        set_bool!("disclose_owner", w.disclose_owner);

        Ok(obj.into())
    }
}

/// WASM bindings for encrypted memo operations
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct EncryptedMemo;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl EncryptedMemo {
    /// Encrypts memo data with automatic nonce generation (CSPRNG).
    #[wasm_bindgen(js_name = encryptMemo)]
    pub fn encrypt_memo(
        value: String,
        owner_pk: Vec<u8>,
        blinding: Vec<u8>,
        asset_id: u32,
        commitment: Vec<u8>,
        recipient_vk: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        // Validate value
        let value: u64 = value
            .parse()
            .map_err(|_| JsValue::from_str("Invalid value (must be u64)"))?;

        // Validate owner_pk
        if owner_pk.len() != 32 {
            return Err(JsValue::from_str("Owner public key must be 32 bytes"));
        }
        let mut owner_bytes = [0u8; 32];
        owner_bytes.copy_from_slice(&owner_pk);

        // Validate blinding
        if blinding.len() != 32 {
            return Err(JsValue::from_str("Blinding must be 32 bytes"));
        }
        let mut blinding_bytes = [0u8; 32];
        blinding_bytes.copy_from_slice(&blinding);

        // Validate commitment
        if commitment.len() != 32 {
            return Err(JsValue::from_str("Commitment must be 32 bytes"));
        }
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&commitment);

        // Validate recipient viewing key
        if recipient_vk.len() != 32 {
            return Err(JsValue::from_str("Recipient viewing key must be 32 bytes"));
        }
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&recipient_vk);

        // Encrypt memo with automatic random nonce generation
        use crate::application::memo_utils::create_encrypted_memo;
        create_encrypted_memo(
            value,
            owner_bytes,
            blinding_bytes,
            asset_id,
            &commitment_bytes,
            &vk_bytes,
        )
        .map_err(|e| JsValue::from_str(e))
    }

    /// Decrypts an encrypted memo.
    #[wasm_bindgen(js_name = decryptMemo)]
    pub fn decrypt_memo(
        encrypted: Vec<u8>,
        commitment: Vec<u8>,
        viewing_key: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        // Validate commitment
        if commitment.len() != 32 {
            return Err(JsValue::from_str("Commitment must be 32 bytes"));
        }
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&commitment);

        // Validate viewing key
        if viewing_key.len() != 32 {
            return Err(JsValue::from_str("Viewing key must be 32 bytes"));
        }
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&viewing_key);

        // Decrypt memo
        use crate::application::memo_utils::decrypt_encrypted_memo;
        let memo_data = decrypt_encrypted_memo(&encrypted, &commitment_bytes, &vk_bytes)
            .map_err(|e| JsValue::from_str(e))?;

        // Return as bytes array
        Ok(memo_data.to_bytes().to_vec())
    }

    /// Validates encrypted memo format (104-256 bytes).
    #[wasm_bindgen(js_name = validateEncryptedMemo)]
    pub fn validate_encrypted_memo(encrypted: &[u8]) -> bool {
        use crate::application::memo_utils::validate_encrypted_memo;
        validate_encrypted_memo(&encrypted)
    }

    /// Creates dummy 104-byte encrypted memo for testing.
    #[wasm_bindgen(js_name = createDummyMemo)]
    pub fn create_dummy_memo() -> Vec<u8> {
        use crate::application::memo_utils::create_dummy_encrypted_memo;
        create_dummy_encrypted_memo()
    }
}

/// WASM bindings for key management operations
#[cfg(all(target_arch = "wasm32", any(feature = "crypto-zk", feature = "crypto")))]
#[wasm_bindgen]
pub struct KeyManager;

#[cfg(all(target_arch = "wasm32", any(feature = "crypto-zk", feature = "crypto")))]
#[cfg(all(target_arch = "wasm32", feature = "crypto"))]
#[wasm_bindgen]
impl KeyManager {
    /// Derives viewing key from spending key.
    ///
    /// Viewing key allows reading all transactions but does not allow spending.
    /// Safe to share with auditors. Reveals complete transaction history.
    #[wasm_bindgen(js_name = deriveViewingKey)]
    pub fn derive_viewing_key(spending_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        // Validate input
        if spending_key.len() != 32 {
            return Err(JsValue::from_str("Spending key must be 32 bytes"));
        }

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&spending_key);

        // Derive viewing key
        use crate::application::key_manager::derive_viewing_key_from_spending;
        let viewing_key = derive_viewing_key_from_spending(&sk_bytes);

        Ok(viewing_key.to_vec())
    }

    /// Derives nullifier key from spending key.
    ///
    /// Used to compute nullifiers for spending notes. Must be kept secret.
    #[wasm_bindgen(js_name = deriveNullifierKey)]
    pub fn derive_nullifier_key(spending_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        if spending_key.len() != 32 {
            return Err(JsValue::from_str("Spending key must be 32 bytes"));
        }

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&spending_key);

        use crate::application::key_manager::derive_nullifier_key_from_spending;
        let nullifier_key = derive_nullifier_key_from_spending(&sk_bytes);

        Ok(nullifier_key.to_vec())
    }

    /// Derives EdDSA signing key from spending key for ZK circuit signatures.
    #[wasm_bindgen(js_name = deriveEddsaKey)]
    pub fn derive_eddsa_key(spending_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        if spending_key.len() != 32 {
            return Err(JsValue::from_str("Spending key must be 32 bytes"));
        }

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&spending_key);

        use crate::application::key_manager::derive_eddsa_key_from_spending;
        let eddsa_key = derive_eddsa_key_from_spending(&sk_bytes);

        Ok(eddsa_key.to_vec())
    }

    /// Derives all keys at once from spending key.
    ///
    /// Returns object with: viewing_key, nullifier_key, eddsa_key.
    #[wasm_bindgen(js_name = deriveAllKeys)]
    pub fn derive_all_keys(spending_key: Vec<u8>) -> Result<JsValue, JsValue> {
        if spending_key.len() != 32 {
            return Err(JsValue::from_str("Spending key must be 32 bytes"));
        }

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&spending_key);

        use crate::application::key_manager::derive_keyset_from_spending;
        let keyset = derive_keyset_from_spending(&sk_bytes);

        // Create JavaScript object
        let obj = js_sys::Object::new();

        let viewing_key = js_sys::Uint8Array::from(&keyset.viewing_key.as_bytes()[..]);
        js_sys::Reflect::set(&obj, &"viewing_key".into(), &viewing_key)?;

        let nullifier_key = js_sys::Uint8Array::from(&keyset.nullifier_key.as_bytes()[..]);
        js_sys::Reflect::set(&obj, &"nullifier_key".into(), &nullifier_key)?;

        let eddsa_key = js_sys::Uint8Array::from(&keyset.eddsa_key.as_bytes()[..]);
        js_sys::Reflect::set(&obj, &"eddsa_key".into(), &eddsa_key)?;

        Ok(obj.into())
    }

    /// Validates spending key format (32 bytes, non-zero).
    #[wasm_bindgen(js_name = validateSpendingKey)]
    pub fn validate_spending_key(key: Vec<u8>) -> bool {
        use crate::application::key_manager::validate_spending_key;
        validate_spending_key(&key)
    }

    /// Validates viewing key format (32 bytes).
    #[wasm_bindgen(js_name = validateViewingKey)]
    pub fn validate_viewing_key(key: Vec<u8>) -> bool {
        use crate::application::key_manager::validate_viewing_key;
        validate_viewing_key(&key)
    }
}
