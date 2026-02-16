use crate::application::params::{
    AuditorInfo, DisclosureConditionType, DisclosureSubmission, ShieldOperation,
};
use crate::domain::entities::{SignedTransaction, UnsignedTransaction};
use crate::domain::types::{Address, Commitment, Hash, Nullifier};
use alloc::vec::Vec;
use codec::{Decode, Encode};

/// Address codec wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AddressCodec(pub [u8; 20]);

impl From<Address> for AddressCodec {
    fn from(addr: Address) -> Self {
        AddressCodec(*addr.as_bytes())
    }
}

impl From<AddressCodec> for Address {
    fn from(codec: AddressCodec) -> Self {
        Address::from_slice_unchecked(&codec.0)
    }
}

/// Hash codec wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct HashCodec(pub [u8; 32]);

impl From<Hash> for HashCodec {
    fn from(hash: Hash) -> Self {
        HashCodec(*hash.as_bytes())
    }
}

impl From<HashCodec> for Hash {
    fn from(codec: HashCodec) -> Self {
        Hash::from_slice(&codec.0)
    }
}

/// Commitment codec wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct CommitmentCodec(pub [u8; 32]);

impl From<Commitment> for CommitmentCodec {
    fn from(commitment: Commitment) -> Self {
        CommitmentCodec(*commitment.as_bytes())
    }
}

impl From<CommitmentCodec> for Commitment {
    fn from(codec: CommitmentCodec) -> Self {
        Commitment::from_bytes_unchecked(codec.0)
    }
}

/// Nullifier codec wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct NullifierCodec(pub [u8; 32]);

impl From<Nullifier> for NullifierCodec {
    fn from(nullifier: Nullifier) -> Self {
        NullifierCodec(*nullifier.as_bytes())
    }
}

impl From<NullifierCodec> for Nullifier {
    fn from(codec: NullifierCodec) -> Self {
        Nullifier::from_bytes_unchecked(codec.0)
    }
}

/// UnsignedTransaction codec wrapper.
#[derive(Debug, Clone, Encode, Decode)]
pub struct UnsignedTransactionCodec {
    pub call_data: Vec<u8>,
    pub nonce: u32,
    pub tip: u128,
}

impl From<UnsignedTransaction> for UnsignedTransactionCodec {
    fn from(tx: UnsignedTransaction) -> Self {
        Self {
            call_data: tx.call_data().to_vec(),
            nonce: tx.nonce(),
            tip: tx.tip(),
        }
    }
}

impl From<UnsignedTransactionCodec> for UnsignedTransaction {
    fn from(codec: UnsignedTransactionCodec) -> Self {
        UnsignedTransaction::new(codec.call_data, codec.nonce).with_tip(codec.tip)
    }
}

/// SignedTransaction codec wrapper.
#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedTransactionCodec {
    pub call_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub address: AddressCodec,
    pub nonce: u32,
}

impl From<SignedTransaction> for SignedTransactionCodec {
    fn from(tx: SignedTransaction) -> Self {
        Self {
            call_data: tx.call_data().to_vec(),
            signature: tx.signature().to_vec(),
            address: AddressCodec::from(*tx.address()),
            nonce: tx.nonce(),
        }
    }
}

impl From<SignedTransactionCodec> for SignedTransaction {
    fn from(codec: SignedTransactionCodec) -> Self {
        SignedTransaction::new(
            codec.call_data,
            codec.signature,
            codec.address.into(),
            codec.nonce,
        )
    }
}

/// ShieldOperation codec wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ShieldOperationCodec {
    pub asset_id: u32,
    pub amount: u128,
    pub commitment: CommitmentCodec,
    pub encrypted_memo: Vec<u8>,
}

impl From<ShieldOperation> for ShieldOperationCodec {
    fn from(op: ShieldOperation) -> Self {
        Self {
            asset_id: op.asset_id.as_u32(),
            amount: op.amount,
            commitment: CommitmentCodec::from(op.commitment),
            encrypted_memo: op.encrypted_memo,
        }
    }
}

/// AuditorInfo codec wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AuditorInfoCodec {
    pub account: AddressCodec,
    pub public_key: Option<[u8; 32]>,
    pub authorized_from: u32,
}

impl From<AuditorInfo> for AuditorInfoCodec {
    fn from(info: AuditorInfo) -> Self {
        Self {
            account: AddressCodec::from(info.account),
            public_key: info.public_key,
            authorized_from: info.authorized_from,
        }
    }
}

/// DisclosureConditionType codec wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum DisclosureConditionTypeCodec {
    AmountAbove(u128),
    TimeElapsed(u32),
    ManualApproval,
}

impl From<DisclosureConditionType> for DisclosureConditionTypeCodec {
    fn from(cond: DisclosureConditionType) -> Self {
        match cond {
            DisclosureConditionType::AmountAbove(v) => Self::AmountAbove(v),
            DisclosureConditionType::TimeElapsed(v) => Self::TimeElapsed(v),
            DisclosureConditionType::ManualApproval => Self::ManualApproval,
        }
    }
}

/// DisclosureSubmission codec wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DisclosureSubmissionCodec {
    pub commitment: CommitmentCodec,
    pub proof: Vec<u8>,
    pub public_signals: Vec<u8>,
    pub disclosed_data: Vec<u8>,
}

impl From<DisclosureSubmission> for DisclosureSubmissionCodec {
    fn from(sub: DisclosureSubmission) -> Self {
        Self {
            commitment: CommitmentCodec::from(sub.commitment),
            proof: sub.proof,
            public_signals: sub.public_signals,
            disclosed_data: sub.disclosed_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_codec_wrappers_roundtrip() {
        let address = Address::from_slice_unchecked(&[1u8; 20]);
        let hash = Hash::from_slice(&[2u8; 32]);
        let commitment = Commitment::from_bytes_unchecked([3u8; 32]);
        let nullifier = Nullifier::from_bytes_unchecked([4u8; 32]);

        let address_back: Address = AddressCodec::from(address).into();
        let hash_back: Hash = HashCodec::from(hash).into();
        let commitment_back: Commitment = CommitmentCodec::from(commitment).into();
        let nullifier_back: Nullifier = NullifierCodec::from(nullifier).into();

        assert_eq!(address_back.as_bytes(), &[1u8; 20]);
        assert_eq!(hash_back.as_bytes(), &[2u8; 32]);
        assert_eq!(commitment_back.as_bytes(), &[3u8; 32]);
        assert_eq!(nullifier_back.as_bytes(), &[4u8; 32]);
    }

    #[test]
    fn test_transaction_codecs_roundtrip() {
        let unsigned = UnsignedTransaction::new(vec![10u8, 11u8], 7).with_tip(3);
        let unsigned_codec = UnsignedTransactionCodec::from(unsigned);
        let unsigned_back: UnsignedTransaction = unsigned_codec.into();

        assert_eq!(unsigned_back.call_data(), &[10u8, 11u8]);
        assert_eq!(unsigned_back.nonce(), 7);
        assert_eq!(unsigned_back.tip(), 3);

        let signed = SignedTransaction::new(
            vec![12u8, 13u8],
            vec![14u8; 65],
            Address::from_slice_unchecked(&[15u8; 20]),
            8,
        );
        let signed_codec = SignedTransactionCodec::from(signed);
        let signed_back: SignedTransaction = signed_codec.into();

        assert_eq!(signed_back.call_data(), &[12u8, 13u8]);
        assert_eq!(signed_back.signature().len(), 65);
        assert_eq!(signed_back.address().as_bytes(), &[15u8; 20]);
        assert_eq!(signed_back.nonce(), 8);
    }

    #[test]
    fn test_application_param_codecs_conversion() {
        let shield_op = ShieldOperation {
            asset_id: crate::domain::types::AssetId::new(9),
            amount: 100,
            commitment: Commitment::from_bytes_unchecked([16u8; 32]),
            encrypted_memo: vec![17u8; 8],
        };
        let shield_codec = ShieldOperationCodec::from(shield_op);
        assert_eq!(shield_codec.asset_id, 9);
        assert_eq!(shield_codec.amount, 100);

        let auditor = AuditorInfo {
            account: Address::from_slice_unchecked(&[18u8; 20]),
            public_key: Some([19u8; 32]),
            authorized_from: 21,
        };
        let auditor_codec = AuditorInfoCodec::from(auditor);
        assert_eq!(auditor_codec.authorized_from, 21);
        assert_eq!(auditor_codec.account.0, [18u8; 20]);

        let cond_amount =
            DisclosureConditionTypeCodec::from(DisclosureConditionType::AmountAbove(500));
        let cond_elapsed =
            DisclosureConditionTypeCodec::from(DisclosureConditionType::TimeElapsed(42));
        let cond_manual =
            DisclosureConditionTypeCodec::from(DisclosureConditionType::ManualApproval);

        assert!(matches!(
            cond_amount,
            DisclosureConditionTypeCodec::AmountAbove(500)
        ));
        assert!(matches!(
            cond_elapsed,
            DisclosureConditionTypeCodec::TimeElapsed(42)
        ));
        assert!(matches!(
            cond_manual,
            DisclosureConditionTypeCodec::ManualApproval
        ));

        let submission = DisclosureSubmission {
            commitment: Commitment::from_bytes_unchecked([20u8; 32]),
            proof: vec![21u8; 16],
            public_signals: vec![22u8; 8],
            disclosed_data: vec![23u8; 4],
        };
        let submission_codec = DisclosureSubmissionCodec::from(submission);
        assert_eq!(submission_codec.proof, vec![21u8; 16]);
        assert_eq!(submission_codec.public_signals, vec![22u8; 8]);
        assert_eq!(submission_codec.disclosed_data, vec![23u8; 4]);
    }

    #[test]
    fn test_scale_encode_decode_for_codec_wrappers() {
        let address_codec = AddressCodec([24u8; 20]);
        let encoded = address_codec.encode();
        let decoded = AddressCodec::decode(&mut &encoded[..]).unwrap();
        assert_eq!(decoded.0, [24u8; 20]);

        let condition_codec = DisclosureConditionTypeCodec::ManualApproval;
        let encoded_cond = condition_codec.encode();
        let decoded_cond = DisclosureConditionTypeCodec::decode(&mut &encoded_cond[..]).unwrap();
        assert!(matches!(
            decoded_cond,
            DisclosureConditionTypeCodec::ManualApproval
        ));
    }
}
