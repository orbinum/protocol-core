//! Disclosure flow integration tests.
//!
//! Validates the full client-side selective disclosure pipeline:
//!
//! 1. `create_disclosure_witness` → `DisclosureWitness` (application layer)
//! 2. Packing `DisclosureWitness` fields into the 76-byte `public_signals`
//!    format expected by pallet-shielded-pool's `submit_disclosure` extrinsic:
//!    - bytes [0..32]  = commitment
//!    - bytes [32..40] = revealed_value  (LE u64, 8 bytes)
//!    - bytes [40..44] = revealed_asset_id (LE u32, 4 bytes)
//!    - bytes [44..76] = revealed_owner_hash (32 bytes)
//! 3. Building signed-ready `UnsignedTransaction` objects via the compliance builders.
//! 4. Compliance policy lifecycle: set_policy → request → approve / reject.
//! 5. Batch submit with multiple entries.

/// Extracts the 76-byte `public_signals` slice expected by pallet-shielded-pool
/// from a `DisclosureWitness`.
///
/// The pallet's `DisclosureValidationService::verify_disclosure_proof` parses:
/// - [0..32]  → commitment
/// - [32..40] → revealed_value  (u64 LE)
/// - [40..44] → revealed_asset_id (u32 LE)
/// - [44..76] → revealed_owner_hash
///
/// The witness stores value and asset_id as 32-byte field elements (BN254 scalar
/// field, little-endian canonical form), so the first 8 / 4 bytes are exactly the
/// LE u64 / u32 byte representation for values that fit in those widths.
#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
pub fn disclosure_witness_to_public_signals(
    witness: &crate::application::disclosure::DisclosureWitness,
) -> Vec<u8> {
    let mut signals = Vec::with_capacity(76);
    signals.extend_from_slice(&witness.commitment); // [0..32]
    signals.extend_from_slice(&witness.revealed_value[0..8]); // [32..40] LE u64
    signals.extend_from_slice(&witness.revealed_asset_id[0..4]); // [40..44] LE u32
    signals.extend_from_slice(&witness.revealed_owner_hash); // [44..76]
    signals
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::application::params::{
        ApproveDisclosureParams, AuditorInfo, BatchSubmitDisclosureParams, DisclosureConditionType,
        DisclosureSubmission, RejectDisclosureParams, RequestDisclosureParams,
        SetAuditPolicyParams, SubmitDisclosureParams,
    };
    use crate::domain::types::{Address, Commitment};
    use crate::infrastructure::serializers::SubstrateTransactionEncoder;
    use crate::presentation::config::{compliance_calls, PALLET_INDEX};

    use super::super::{
        ApproveDisclosureBuilder, BatchSubmitDisclosureBuilder, RejectDisclosureBuilder,
        RequestDisclosureBuilder, SetAuditPolicyBuilder, SubmitDisclosureBuilder,
    };

    // ── helpers ──────────────────────────────────────────────────────────────

    fn encoder() -> SubstrateTransactionEncoder {
        SubstrateTransactionEncoder::new()
    }

    fn commitment(byte: u8) -> Commitment {
        Commitment::from_bytes_unchecked([byte; 32])
    }

    fn address(byte: u8) -> Address {
        Address::from_slice_unchecked(&[byte; 32])
    }

    // ── builder call_index contracts ─────────────────────────────────────────

    #[test]
    fn test_all_compliance_builders_have_correct_pallet_and_call_indices() {
        let enc = encoder();

        let set_policy = SetAuditPolicyBuilder::build_unsigned(
            &enc,
            SetAuditPolicyParams {
                auditors: vec![AuditorInfo {
                    account: address(1),
                    public_key: None,
                    authorized_from: 0,
                }],
                conditions: vec![DisclosureConditionType::ManualApproval],
                max_frequency: Some(5),
            },
            0,
        );
        let request = RequestDisclosureBuilder::build_unsigned(
            &enc,
            RequestDisclosureParams {
                target: address(2),
                reason: b"audit".to_vec(),
                evidence: None,
            },
            1,
        );
        let approve = ApproveDisclosureBuilder::build_unsigned(
            &enc,
            ApproveDisclosureParams {
                auditor: address(3),
                commitment: commitment(4),
                zk_proof: vec![0u8; 64],
                disclosed_data: vec![0u8; 8],
            },
            2,
        );
        let reject = RejectDisclosureBuilder::build_unsigned(
            &enc,
            RejectDisclosureParams {
                auditor: address(5),
                reason: b"denied".to_vec(),
            },
            3,
        );
        let submit = SubmitDisclosureBuilder::build_unsigned(
            &enc,
            SubmitDisclosureParams {
                commitment: commitment(6),
                proof_bytes: vec![0u8; 256],
                public_signals: vec![0u8; 76],
                partial_data: vec![0u8; 8],
                auditor: None,
            },
            4,
        );
        let batch = BatchSubmitDisclosureBuilder::build_unsigned(
            &enc,
            BatchSubmitDisclosureParams {
                submissions: vec![DisclosureSubmission {
                    commitment: commitment(7),
                    proof: vec![0u8; 256],
                    public_signals: vec![0u8; 76],
                    disclosed_data: vec![0u8; 8],
                }],
            },
            5,
        );

        for (name, tx, expected_call) in [
            (
                "set_policy",
                &set_policy,
                compliance_calls::SET_AUDIT_POLICY,
            ),
            ("request", &request, compliance_calls::REQUEST_DISCLOSURE),
            ("approve", &approve, compliance_calls::APPROVE_DISCLOSURE),
            ("reject", &reject, compliance_calls::REJECT_DISCLOSURE),
            ("submit", &submit, compliance_calls::SUBMIT_DISCLOSURE),
            ("batch", &batch, compliance_calls::BATCH_SUBMIT_DISCLOSURE),
        ] {
            assert_eq!(
                tx.call_data()[0],
                PALLET_INDEX,
                "{name}: wrong pallet index"
            );
            assert_eq!(tx.call_data()[1], expected_call, "{name}: wrong call index");
            assert!(tx.call_data().len() > 2, "{name}: call_data too short");
        }
    }

    // ── nonce propagation ────────────────────────────────────────────────────

    #[test]
    fn test_nonce_is_propagated_into_unsigned_transaction() {
        let enc = encoder();

        for nonce in [0u32, 1, 42, u32::MAX] {
            let tx = SubmitDisclosureBuilder::build_unsigned(
                &enc,
                SubmitDisclosureParams {
                    commitment: commitment(0),
                    proof_bytes: vec![0u8; 8],
                    public_signals: vec![0u8; 8],
                    partial_data: vec![],
                    auditor: None,
                },
                nonce,
            );
            assert_eq!(tx.nonce(), nonce, "nonce must be forwarded unchanged");
        }
    }

    // ── public_signals packing format ─────────────────────────────────────────

    /// Constructs a 76-byte `public_signals` buffer directly from raw values.
    /// This mirrors what `disclosure_witness_to_public_signals` does internally
    /// and what pallet `DisclosureValidationService` decodes.
    fn pack_public_signals(
        commitment_bytes: &[u8; 32],
        revealed_value: u64,
        revealed_asset_id: u32,
        revealed_owner_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut signals = Vec::with_capacity(76);
        signals.extend_from_slice(commitment_bytes);
        signals.extend_from_slice(&revealed_value.to_le_bytes());
        signals.extend_from_slice(&revealed_asset_id.to_le_bytes());
        signals.extend_from_slice(revealed_owner_hash);
        signals
    }

    #[test]
    fn test_public_signals_length_is_76_bytes() {
        let signals = pack_public_signals(&[1u8; 32], 100, 7, &[2u8; 32]);
        assert_eq!(signals.len(), 76);
    }

    #[test]
    fn test_public_signals_commitment_occupies_first_32_bytes() {
        let commit = [0xABu8; 32];
        let signals = pack_public_signals(&commit, 0, 0, &[0u8; 32]);
        assert_eq!(&signals[0..32], &commit);
    }

    #[test]
    fn test_public_signals_value_occupies_bytes_32_to_40_as_le_u64() {
        let value: u64 = 1_000_000;
        let signals = pack_public_signals(&[0u8; 32], value, 0, &[0u8; 32]);
        let decoded = u64::from_le_bytes(signals[32..40].try_into().unwrap());
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_public_signals_max_u64_value_round_trips() {
        let signals = pack_public_signals(&[0u8; 32], u64::MAX, 0, &[0u8; 32]);
        let decoded = u64::from_le_bytes(signals[32..40].try_into().unwrap());
        assert_eq!(decoded, u64::MAX);
    }

    #[test]
    fn test_public_signals_asset_id_occupies_bytes_40_to_44_as_le_u32() {
        let asset_id: u32 = 42;
        let signals = pack_public_signals(&[0u8; 32], 0, asset_id, &[0u8; 32]);
        let decoded = u32::from_le_bytes(signals[40..44].try_into().unwrap());
        assert_eq!(decoded, asset_id);
    }

    #[test]
    fn test_public_signals_owner_hash_occupies_last_32_bytes() {
        let owner_hash = [0xCDu8; 32];
        let signals = pack_public_signals(&[0u8; 32], 0, 0, &owner_hash);
        assert_eq!(&signals[44..76], &owner_hash);
    }

    #[test]
    fn test_public_signals_zero_value_and_asset_produce_zero_bytes() {
        let signals = pack_public_signals(&[0u8; 32], 0, 0, &[0u8; 32]);
        assert_eq!(&signals[32..40], &[0u8; 8]);
        assert_eq!(&signals[40..44], &[0u8; 4]);
    }

    /// When a field is not disclosed the pallet expects zero bytes in its slot.
    #[test]
    fn test_undisclosed_fields_produce_zero_slots_in_signals() {
        // Not disclosing value → revealed_value = 0
        let signals = pack_public_signals(&[1u8; 32], 0, 5, &[0u8; 32]);
        assert_eq!(
            &signals[32..40],
            &[0u8; 8],
            "undisclosed value must be zero"
        );
        // Not disclosing owner → revealed_owner_hash = [0;32]
        assert_eq!(
            &signals[44..76],
            &[0u8; 32],
            "undisclosed owner must be zero"
        );
    }

    // ── submit_disclosure encoding ties to packing ────────────────────────────

    #[test]
    fn test_submit_disclosure_accepts_76_byte_public_signals() {
        let enc = encoder();
        let signals = pack_public_signals(&[1u8; 32], 500, 3, &[2u8; 32]);

        let tx = SubmitDisclosureBuilder::build_unsigned(
            &enc,
            SubmitDisclosureParams {
                commitment: commitment(1),
                proof_bytes: vec![0u8; 256],
                public_signals: signals,
                partial_data: vec![],
                auditor: None,
            },
            0,
        );

        assert_eq!(tx.call_data()[0], PALLET_INDEX);
        assert_eq!(tx.call_data()[1], compliance_calls::SUBMIT_DISCLOSURE);
    }

    #[test]
    fn test_submit_disclosure_encoding_changes_with_different_signal_values() {
        let enc = encoder();
        let commitment_bytes = [5u8; 32];
        let commit = Commitment::from_bytes_unchecked(commitment_bytes);

        let tx_a = SubmitDisclosureBuilder::build_unsigned(
            &enc,
            SubmitDisclosureParams {
                commitment: commit,
                proof_bytes: vec![0u8; 256],
                public_signals: pack_public_signals(&commitment_bytes, 100, 1, &[0u8; 32]),
                partial_data: vec![],
                auditor: None,
            },
            0,
        );

        let tx_b = SubmitDisclosureBuilder::build_unsigned(
            &enc,
            SubmitDisclosureParams {
                commitment: commit,
                proof_bytes: vec![0u8; 256],
                public_signals: pack_public_signals(&commitment_bytes, 200, 1, &[0u8; 32]),
                partial_data: vec![],
                auditor: None,
            },
            0,
        );

        assert_ne!(
            tx_a.call_data(),
            tx_b.call_data(),
            "different revealed values must produce different call_data"
        );
    }

    #[test]
    fn test_submit_disclosure_with_auditor_differs_from_without() {
        let enc = encoder();
        let signals = pack_public_signals(&[1u8; 32], 100, 0, &[0u8; 32]);

        let with_auditor = SubmitDisclosureBuilder::build_unsigned(
            &enc,
            SubmitDisclosureParams {
                commitment: commitment(1),
                proof_bytes: vec![0u8; 8],
                public_signals: signals.clone(),
                partial_data: vec![],
                auditor: Some(address(10)),
            },
            0,
        );

        let without_auditor = SubmitDisclosureBuilder::build_unsigned(
            &enc,
            SubmitDisclosureParams {
                commitment: commitment(1),
                proof_bytes: vec![0u8; 8],
                public_signals: signals,
                partial_data: vec![],
                auditor: None,
            },
            0,
        );

        assert_ne!(
            with_auditor.call_data(),
            without_auditor.call_data(),
            "auditor presence must change the encoding"
        );
    }

    // ── batch submit ─────────────────────────────────────────────────────────

    #[test]
    fn test_batch_submit_single_entry_is_longer_than_minimal_header() {
        let enc = encoder();

        let tx = BatchSubmitDisclosureBuilder::build_unsigned(
            &enc,
            BatchSubmitDisclosureParams {
                submissions: vec![DisclosureSubmission {
                    commitment: commitment(1),
                    proof: vec![0u8; 256],
                    public_signals: pack_public_signals(&[1u8; 32], 100, 1, &[0u8; 32]),
                    disclosed_data: vec![0u8; 8],
                }],
            },
            0,
        );

        assert_eq!(tx.call_data()[0], PALLET_INDEX);
        assert_eq!(tx.call_data()[1], compliance_calls::BATCH_SUBMIT_DISCLOSURE);
        // Must encode at least pallet_byte + call_byte + length_prefix + entry
        assert!(tx.call_data().len() > 10);
    }

    #[test]
    fn test_batch_submit_grows_with_each_submission() {
        let enc = encoder();

        let make_submission = |byte: u8| DisclosureSubmission {
            commitment: commitment(byte),
            proof: vec![byte; 64],
            public_signals: pack_public_signals(&[byte; 32], byte as u64, byte as u32, &[byte; 32]),
            disclosed_data: vec![byte; 8],
        };

        let tx_one = BatchSubmitDisclosureBuilder::build_unsigned(
            &enc,
            BatchSubmitDisclosureParams {
                submissions: vec![make_submission(1)],
            },
            0,
        );

        let tx_two = BatchSubmitDisclosureBuilder::build_unsigned(
            &enc,
            BatchSubmitDisclosureParams {
                submissions: vec![make_submission(1), make_submission(2)],
            },
            0,
        );

        let tx_three = BatchSubmitDisclosureBuilder::build_unsigned(
            &enc,
            BatchSubmitDisclosureParams {
                submissions: vec![make_submission(1), make_submission(2), make_submission(3)],
            },
            0,
        );

        assert!(
            tx_one.call_data().len() < tx_two.call_data().len(),
            "two submissions must be longer than one"
        );
        assert!(
            tx_two.call_data().len() < tx_three.call_data().len(),
            "three submissions must be longer than two"
        );
    }

    #[test]
    fn test_batch_submit_different_commitments_produce_different_call_data() {
        let enc = encoder();

        let tx_a = BatchSubmitDisclosureBuilder::build_unsigned(
            &enc,
            BatchSubmitDisclosureParams {
                submissions: vec![DisclosureSubmission {
                    commitment: commitment(0xAA),
                    proof: vec![1u8; 64],
                    public_signals: pack_public_signals(&[0xAAu8; 32], 100, 1, &[0u8; 32]),
                    disclosed_data: vec![0u8; 8],
                }],
            },
            0,
        );

        let tx_b = BatchSubmitDisclosureBuilder::build_unsigned(
            &enc,
            BatchSubmitDisclosureParams {
                submissions: vec![DisclosureSubmission {
                    commitment: commitment(0xBB),
                    proof: vec![1u8; 64],
                    public_signals: pack_public_signals(&[0xBBu8; 32], 100, 1, &[0u8; 32]),
                    disclosed_data: vec![0u8; 8],
                }],
            },
            0,
        );

        assert_ne!(tx_a.call_data(), tx_b.call_data());
    }

    // ── policy lifecycle builders ─────────────────────────────────────────────

    #[test]
    fn test_set_audit_policy_with_unlimited_frequency() {
        let enc = encoder();

        let tx = SetAuditPolicyBuilder::build_unsigned(
            &enc,
            SetAuditPolicyParams {
                auditors: vec![AuditorInfo {
                    account: address(1),
                    public_key: None,
                    authorized_from: 0,
                }],
                conditions: vec![DisclosureConditionType::ManualApproval],
                max_frequency: None, // unlimited
            },
            0,
        );

        assert_eq!(tx.call_data()[1], compliance_calls::SET_AUDIT_POLICY);
        assert!(tx.call_data().len() > 2);
    }

    #[test]
    fn test_set_audit_policy_limited_vs_unlimited_frequency_differ() {
        let enc = encoder();

        let build = |max_frequency| {
            SetAuditPolicyBuilder::build_unsigned(
                &enc,
                SetAuditPolicyParams {
                    auditors: vec![AuditorInfo {
                        account: address(1),
                        public_key: None,
                        authorized_from: 0,
                    }],
                    conditions: vec![DisclosureConditionType::ManualApproval],
                    max_frequency,
                },
                0,
            )
        };

        assert_ne!(
            build(Some(1)).call_data(),
            build(None).call_data(),
            "Some(n) vs None frequency must differ"
        );
    }

    #[test]
    fn test_set_audit_policy_with_multiple_auditors() {
        let enc = encoder();

        let single = SetAuditPolicyBuilder::build_unsigned(
            &enc,
            SetAuditPolicyParams {
                auditors: vec![AuditorInfo {
                    account: address(1),
                    public_key: None,
                    authorized_from: 0,
                }],
                conditions: vec![DisclosureConditionType::ManualApproval],
                max_frequency: None,
            },
            0,
        );

        let multiple = SetAuditPolicyBuilder::build_unsigned(
            &enc,
            SetAuditPolicyParams {
                auditors: vec![
                    AuditorInfo {
                        account: address(1),
                        public_key: None,
                        authorized_from: 0,
                    },
                    AuditorInfo {
                        account: address(2),
                        public_key: None,
                        authorized_from: 0,
                    },
                ],
                conditions: vec![DisclosureConditionType::ManualApproval],
                max_frequency: None,
            },
            0,
        );

        assert!(
            multiple.call_data().len() > single.call_data().len(),
            "more auditors must produce longer call_data"
        );
    }

    #[test]
    fn test_request_disclosure_with_and_without_evidence_differ() {
        let enc = encoder();

        let without = RequestDisclosureBuilder::build_unsigned(
            &enc,
            RequestDisclosureParams {
                target: address(1),
                reason: b"kyc check".to_vec(),
                evidence: None,
            },
            0,
        );

        let with_evidence = RequestDisclosureBuilder::build_unsigned(
            &enc,
            RequestDisclosureParams {
                target: address(1),
                reason: b"kyc check".to_vec(),
                evidence: Some(b"exhibit_a".to_vec()),
            },
            0,
        );

        assert_ne!(without.call_data(), with_evidence.call_data());
        assert!(with_evidence.call_data().len() > without.call_data().len());
    }

    #[test]
    fn test_approve_disclosure_payload_is_reflected_in_call_data() {
        let enc = encoder();

        let small_proof = ApproveDisclosureBuilder::build_unsigned(
            &enc,
            ApproveDisclosureParams {
                auditor: address(1),
                commitment: commitment(2),
                zk_proof: vec![0u8; 32],
                disclosed_data: vec![0u8; 8],
            },
            0,
        );

        let large_proof = ApproveDisclosureBuilder::build_unsigned(
            &enc,
            ApproveDisclosureParams {
                auditor: address(1),
                commitment: commitment(2),
                zk_proof: vec![0u8; 256],
                disclosed_data: vec![0u8; 8],
            },
            0,
        );

        assert!(
            large_proof.call_data().len() > small_proof.call_data().len(),
            "larger proof bytes must produce longer call_data"
        );
    }

    #[test]
    fn test_reject_disclosure_reason_affects_encoding() {
        let enc = encoder();

        let short = RejectDisclosureBuilder::build_unsigned(
            &enc,
            RejectDisclosureParams {
                auditor: address(1),
                reason: b"no".to_vec(),
            },
            0,
        );

        let long = RejectDisclosureBuilder::build_unsigned(
            &enc,
            RejectDisclosureParams {
                auditor: address(1),
                reason: b"insufficient documentation provided".to_vec(),
            },
            0,
        );

        assert!(
            long.call_data().len() > short.call_data().len(),
            "longer reason must produce longer call_data"
        );
    }

    #[test]
    fn test_reject_disclosure_different_auditors_differ() {
        let enc = encoder();

        let tx_a = RejectDisclosureBuilder::build_unsigned(
            &enc,
            RejectDisclosureParams {
                auditor: address(0xAA),
                reason: b"denied".to_vec(),
            },
            0,
        );
        let tx_b = RejectDisclosureBuilder::build_unsigned(
            &enc,
            RejectDisclosureParams {
                auditor: address(0xBB),
                reason: b"denied".to_vec(),
            },
            0,
        );

        assert_ne!(tx_a.call_data(), tx_b.call_data());
    }

    // ── lifecycle sequence: policy → request → approve → reject ──────────────

    #[test]
    fn test_compliance_lifecycle_sequence_produces_distinct_transactions() {
        let enc = encoder();

        let set_policy = SetAuditPolicyBuilder::build_unsigned(
            &enc,
            SetAuditPolicyParams {
                auditors: vec![AuditorInfo {
                    account: address(1),
                    public_key: None,
                    authorized_from: 100,
                }],
                conditions: vec![DisclosureConditionType::ManualApproval],
                max_frequency: Some(24),
            },
            10,
        );

        let request = RequestDisclosureBuilder::build_unsigned(
            &enc,
            RequestDisclosureParams {
                target: address(2),
                reason: b"compliance audit Q4".to_vec(),
                evidence: Some(b"txid:0xdeadbeef".to_vec()),
            },
            11,
        );

        let approve = ApproveDisclosureBuilder::build_unsigned(
            &enc,
            ApproveDisclosureParams {
                auditor: address(1),
                commitment: commitment(3),
                zk_proof: vec![0u8; 256],
                disclosed_data: vec![0u8; 32],
            },
            12,
        );

        let reject = RejectDisclosureBuilder::build_unsigned(
            &enc,
            RejectDisclosureParams {
                auditor: address(1),
                reason: b"duplicate request".to_vec(),
            },
            13,
        );

        // All four transactions are different
        let all_data = [
            set_policy.call_data(),
            request.call_data(),
            approve.call_data(),
            reject.call_data(),
        ];
        for i in 0..all_data.len() {
            for j in (i + 1)..all_data.len() {
                assert_ne!(
                    all_data[i], all_data[j],
                    "tx {i} and tx {j} should produce distinct call_data"
                );
            }
        }

        // Nonces increase monotonically
        assert_eq!(set_policy.nonce(), 10);
        assert_eq!(request.nonce(), 11);
        assert_eq!(approve.nonce(), 12);
        assert_eq!(reject.nonce(), 13);
    }

    // ── public_signals → SubmitDisclosureBuilder full round-trip ─────────────

    #[test]
    fn test_submit_disclosure_with_all_fields_disclosed() {
        let enc = encoder();
        let commitment_bytes = [0x11u8; 32];
        let value: u64 = 250_000_000;
        let asset_id: u32 = 1;
        let owner_hash = [0x22u8; 32];

        let signals = pack_public_signals(&commitment_bytes, value, asset_id, &owner_hash);
        assert_eq!(signals.len(), 76);

        // Verify round-trip parsing of each field
        assert_eq!(&signals[0..32], &commitment_bytes);
        assert_eq!(
            u64::from_le_bytes(signals[32..40].try_into().unwrap()),
            value
        );
        assert_eq!(
            u32::from_le_bytes(signals[40..44].try_into().unwrap()),
            asset_id
        );
        assert_eq!(&signals[44..76], &owner_hash);

        let tx = SubmitDisclosureBuilder::build_unsigned(
            &enc,
            SubmitDisclosureParams {
                commitment: Commitment::from_bytes_unchecked(commitment_bytes),
                proof_bytes: vec![0u8; 256],
                public_signals: signals,
                partial_data: vec![0u8; 32],
                auditor: None,
            },
            99,
        );

        assert_eq!(tx.call_data()[0], PALLET_INDEX);
        assert_eq!(tx.call_data()[1], compliance_calls::SUBMIT_DISCLOSURE);
        assert_eq!(tx.nonce(), 99);
    }

    #[test]
    fn test_submit_disclosure_value_only_mask_signals_format() {
        let enc = encoder();
        // Only value is disclosed; asset_id and owner_hash slots are zeros
        let commitment_bytes = [0x33u8; 32];
        let value: u64 = 1_234_567;
        let signals = pack_public_signals(&commitment_bytes, value, 0, &[0u8; 32]);

        assert_eq!(&signals[0..32], &commitment_bytes);
        assert_eq!(
            u64::from_le_bytes(signals[32..40].try_into().unwrap()),
            value
        );
        assert_eq!(&signals[40..44], &[0u8; 4]);
        assert_eq!(&signals[44..76], &[0u8; 32]);

        let tx = SubmitDisclosureBuilder::build_unsigned(
            &enc,
            SubmitDisclosureParams {
                commitment: Commitment::from_bytes_unchecked(commitment_bytes),
                proof_bytes: vec![0u8; 256],
                public_signals: signals,
                partial_data: vec![],
                auditor: None,
            },
            0,
        );
        assert_eq!(tx.call_data()[1], compliance_calls::SUBMIT_DISCLOSURE);
    }

    // ── witness → public_signals integration (requires crypto feature) ────────

    #[cfg(any(feature = "crypto-zk", feature = "crypto"))]
    mod crypto_flow {
        use crate::application::disclosure::create_disclosure_witness;
        use crate::application::params::SubmitDisclosureParams;
        use crate::domain::types::Commitment;
        use crate::infrastructure::serializers::SubstrateTransactionEncoder;
        use crate::presentation::config::{compliance_calls, PALLET_INDEX};
        use orbinum_encrypted_memo::{DisclosureMask, MemoData};

        // disclosure_witness_to_public_signals lives in the parent module (disclosure_flow.rs root)
        use super::super::disclosure_witness_to_public_signals;
        // builders live in the grandparent (compliance)
        use super::super::super::SubmitDisclosureBuilder;

        fn enc() -> SubstrateTransactionEncoder {
            SubstrateTransactionEncoder::new()
        }

        /// For BN254 scalar field, u64_to_field_bytes(v) stores v in LE order,
        /// so bytes [0..8] of the field element equal v.to_le_bytes().
        fn field_element_first_u64(fe: &[u8; 32]) -> u64 {
            u64::from_le_bytes(fe[0..8].try_into().unwrap())
        }

        fn field_element_first_u32(fe: &[u8; 32]) -> u32 {
            u32::from_le_bytes(fe[0..4].try_into().unwrap())
        }

        #[test]
        fn test_witness_to_public_signals_has_correct_length() {
            let memo = MemoData::new(100, [0u8; 32], [0u8; 32], 1);
            let commitment = [0xFFu8; 32];
            let mask = DisclosureMask {
                disclose_value: true,
                disclose_owner: false,
                disclose_asset_id: false,
                disclose_blinding: false,
            };
            let witness = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
            let signals = disclosure_witness_to_public_signals(&witness);
            assert_eq!(signals.len(), 76, "public_signals must be exactly 76 bytes");
        }

        #[test]
        fn test_witness_to_public_signals_commitment_slot_matches() {
            let commit_bytes = [0x55u8; 32];
            let memo = MemoData::new(50, [0u8; 32], [0u8; 32], 0);
            let mask = DisclosureMask {
                disclose_value: true,
                disclose_owner: false,
                disclose_asset_id: false,
                disclose_blinding: false,
            };
            let witness = create_disclosure_witness(&memo, &commit_bytes, &mask).unwrap();
            let signals = disclosure_witness_to_public_signals(&witness);
            assert_eq!(
                &signals[0..32],
                &commit_bytes,
                "commitment slot must equal the input commitment"
            );
        }

        #[test]
        fn test_witness_revealed_value_encodes_correctly_in_signals() {
            let value: u64 = 42_000;
            let memo = MemoData::new(value, [0u8; 32], [0u8; 32], 0);
            let commitment = [0u8; 32];
            let mask = DisclosureMask {
                disclose_value: true,
                disclose_owner: false,
                disclose_asset_id: false,
                disclose_blinding: false,
            };
            let witness = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

            // Field element stores LE value in first 8 bytes
            assert_eq!(
                field_element_first_u64(&witness.revealed_value),
                value,
                "field element first 8 bytes must equal the u64 value"
            );

            let signals = disclosure_witness_to_public_signals(&witness);
            let decoded = u64::from_le_bytes(signals[32..40].try_into().unwrap());
            assert_eq!(
                decoded, value,
                "signals[32..40] must decode to original value"
            );
        }

        #[test]
        fn test_witness_revealed_asset_id_encodes_correctly_in_signals() {
            let asset_id: u32 = 7;
            let memo = MemoData::new(100, [0u8; 32], [0u8; 32], asset_id);
            let commitment = [0u8; 32];
            let mask = DisclosureMask {
                disclose_value: false,
                disclose_owner: false,
                disclose_asset_id: true,
                disclose_blinding: false,
            };
            let witness = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

            assert_eq!(
                field_element_first_u32(&witness.revealed_asset_id),
                asset_id,
                "field element first 4 bytes must equal the u32 asset_id"
            );

            let signals = disclosure_witness_to_public_signals(&witness);
            let decoded = u32::from_le_bytes(signals[40..44].try_into().unwrap());
            assert_eq!(
                decoded, asset_id,
                "signals[40..44] must decode to original asset_id"
            );
        }

        #[test]
        fn test_witness_revealed_owner_hash_in_signals() {
            let owner_pk = [0x77u8; 32];
            let memo = MemoData::new(100, owner_pk, [0u8; 32], 0);
            let commitment = [0u8; 32];
            let mask = DisclosureMask {
                disclose_value: false,
                disclose_owner: true,
                disclose_asset_id: false,
                disclose_blinding: false,
            };
            let witness = create_disclosure_witness(&memo, &commitment, &mask).unwrap();

            assert_ne!(
                witness.revealed_owner_hash, [0u8; 32],
                "revealed_owner_hash must be non-zero when owner is disclosed"
            );

            let signals = disclosure_witness_to_public_signals(&witness);
            assert_eq!(
                &signals[44..76],
                &witness.revealed_owner_hash,
                "signals[44..76] must match revealed_owner_hash"
            );
        }

        #[test]
        fn test_witness_undisclosed_slots_are_zero_in_signals() {
            // Disclose only asset_id; value and owner should be zero
            let memo = MemoData::new(9_999, [0xAAu8; 32], [0u8; 32], 5);
            let commitment = [0u8; 32];
            let mask = DisclosureMask {
                disclose_value: false,
                disclose_owner: false,
                disclose_asset_id: true,
                disclose_blinding: false,
            };
            let witness = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
            let signals = disclosure_witness_to_public_signals(&witness);

            assert_eq!(
                &signals[32..40],
                &[0u8; 8],
                "undisclosed value slot must be zero"
            );
            assert_eq!(
                &signals[44..76],
                &[0u8; 32],
                "undisclosed owner slot must be zero"
            );
        }

        #[test]
        fn test_all_7_masks_produce_valid_submit_disclosure_transactions() {
            let enc = enc();
            let memo = MemoData::new(1_000, [0x11u8; 32], [0x22u8; 32], 3);
            let commitment_bytes = [0x33u8; 32];

            let masks = [
                (true, false, false),
                (false, true, false),
                (false, false, true),
                (true, true, false),
                (true, false, true),
                (false, true, true),
                (true, true, true),
            ];

            for (dv, do_, da) in masks {
                let mask = DisclosureMask {
                    disclose_value: dv,
                    disclose_owner: do_,
                    disclose_asset_id: da,
                    disclose_blinding: false,
                };

                let witness = create_disclosure_witness(&memo, &commitment_bytes, &mask)
                    .expect("witness must succeed for valid mask");

                let signals = disclosure_witness_to_public_signals(&witness);
                assert_eq!(signals.len(), 76);

                let tx = SubmitDisclosureBuilder::build_unsigned(
                    &enc,
                    SubmitDisclosureParams {
                        commitment: Commitment::from_bytes_unchecked(commitment_bytes),
                        proof_bytes: vec![0u8; 256],
                        public_signals: signals,
                        partial_data: vec![],
                        auditor: None,
                    },
                    0,
                );

                assert_eq!(
                    tx.call_data()[0],
                    PALLET_INDEX,
                    "mask (dv={dv},do={do_},da={da}): wrong pallet index"
                );
                assert_eq!(
                    tx.call_data()[1],
                    compliance_calls::SUBMIT_DISCLOSURE,
                    "mask (dv={dv},do={do_},da={da}): wrong call index"
                );
            }
        }

        #[test]
        fn test_max_u64_value_packs_correctly_into_signals() {
            let memo = MemoData::new(u64::MAX, [0u8; 32], [0u8; 32], 0);
            let commitment = [0u8; 32];
            let mask = DisclosureMask {
                disclose_value: true,
                disclose_owner: false,
                disclose_asset_id: false,
                disclose_blinding: false,
            };
            let witness = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
            let signals = disclosure_witness_to_public_signals(&witness);

            let decoded = u64::from_le_bytes(signals[32..40].try_into().unwrap());
            assert_eq!(
                decoded,
                u64::MAX,
                "max u64 must round-trip through public_signals"
            );
        }

        #[test]
        fn test_zero_asset_id_produces_zero_slot_in_signals() {
            // asset_id = 0 (ORB) → field element is [0; 32] → signals[40..44] = [0; 4]
            let memo = MemoData::new(100, [0u8; 32], [0u8; 32], 0);
            let commitment = [0u8; 32];
            let mask = DisclosureMask {
                disclose_value: false,
                disclose_owner: false,
                disclose_asset_id: true,
                disclose_blinding: false,
            };
            let witness = create_disclosure_witness(&memo, &commitment, &mask).unwrap();
            let signals = disclosure_witness_to_public_signals(&witness);

            assert_eq!(
                &signals[40..44],
                &[0u8; 4],
                "ORB asset_id=0 must produce zero bytes in the asset_id slot"
            );
        }
    }
}
