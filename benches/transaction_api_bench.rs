use criterion::{black_box, criterion_group, criterion_main, Criterion};
use orbinum_protocol_core::TransactionApi;
use orbinum_protocol_core::domain::entities::SignedTransaction;
use orbinum_protocol_core::domain::types::{Address, Commitment, Hash, Nullifier};
use orbinum_protocol_core::infrastructure::codec::encoder::ScaleEncoder;
use orbinum_protocol_core::infrastructure::serializers::{
    serialize_signed_transaction, CallDataBuilder,
};

#[cfg(feature = "crypto")]
use orbinum_protocol_core::SigningApi;

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
use orbinum_protocol_core::presentation::crypto_api::CryptoApi;

fn bench_build_shield_unsigned(c: &mut Criterion) {
    c.bench_function("tx_api.build_shield_unsigned", |b| {
        b.iter(|| {
            let call_data = TransactionApi::build_shield_unsigned(
                black_box(1_000u128),
                black_box(1u32),
                black_box([1u8; 32]),
                black_box(vec![2u8; 32]),
                black_box(0u32),
            );
            black_box(call_data)
        })
    });
}

fn bench_build_unshield_unsigned(c: &mut Criterion) {
    c.bench_function("tx_api.build_unshield_unsigned", |b| {
        b.iter(|| {
            let call_data = TransactionApi::build_unshield_unsigned(
                black_box([3u8; 32]),
                black_box(500u128),
                black_box(1u32),
                black_box([4u8; 20]),
                black_box([5u8; 32]),
                black_box(vec![6u8; 192]),
                black_box(1u32),
            );
            black_box(call_data)
        })
    });
}

fn bench_build_transfer_unsigned(c: &mut Criterion) {
    c.bench_function("tx_api.build_transfer_unsigned", |b| {
        b.iter(|| {
            let call_data = TransactionApi::build_transfer_unsigned(
                black_box([[7u8; 32], [8u8; 32]]),
                black_box([[9u8; 32], [10u8; 32]]),
                black_box([11u8; 32]),
                black_box(vec![12u8; 192]),
                black_box([vec![13u8; 32], vec![14u8; 32]]),
                black_box(2u32),
            );
            black_box(call_data)
        })
    });
}

fn bench_call_data_builder_transfer(c: &mut Criterion) {
    let builder = CallDataBuilder::new(ScaleEncoder::new());
    let input_nullifiers = [
        Nullifier::from_bytes_unchecked([21u8; 32]),
        Nullifier::from_bytes_unchecked([22u8; 32]),
    ];
    let output_commitments = [
        Commitment::from_bytes_unchecked([23u8; 32]),
        Commitment::from_bytes_unchecked([24u8; 32]),
    ];
    let root = Hash::from_slice(&[25u8; 32]);
    let proof = vec![26u8; 192];
    let memos = [vec![27u8; 32], vec![28u8; 32]];

    c.bench_function("serializer.call_data_builder.transfer", |b| {
        b.iter(|| {
            let call_data = builder.build_transfer_call_data(
                black_box(&input_nullifiers),
                black_box(&output_commitments),
                black_box(&root),
                black_box(&proof),
                black_box(&memos),
            );
            black_box(call_data)
        })
    });
}

fn bench_serialize_signed_transaction(c: &mut Criterion) {
    let tx = SignedTransaction::new(
        vec![31u8; 128],
        vec![32u8; 65],
        Address::from_slice_unchecked(&[33u8; 20]),
        42,
    );

    c.bench_function("serializer.serialize_signed_transaction", |b| {
        b.iter(|| {
            let encoded = serialize_signed_transaction(black_box(&tx));
            black_box(encoded)
        })
    });
}

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
fn bench_crypto_api_compute_commitment(c: &mut Criterion) {
    let api = CryptoApi::new();

    c.bench_function("crypto_api.compute_commitment", |b| {
        b.iter(|| {
            let commitment = api
                .compute_commitment(
                    black_box(1_000u128),
                    black_box(0u32),
                    black_box([41u8; 32]),
                    black_box([42u8; 32]),
                )
                .expect("benchmark commitment should succeed");
            black_box(commitment)
        })
    });
}

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
fn bench_crypto_api_compute_nullifier(c: &mut Criterion) {
    let api = CryptoApi::new();

    c.bench_function("crypto_api.compute_nullifier", |b| {
        b.iter(|| {
            let nullifier = api
                .compute_nullifier(black_box([43u8; 32]), black_box([44u8; 32]))
                .expect("benchmark nullifier should succeed");
            black_box(nullifier)
        })
    });
}

#[cfg(any(feature = "crypto-zk", feature = "crypto"))]
fn bench_crypto_api_poseidon_hash_2(c: &mut Criterion) {
    let api = CryptoApi::new();

    c.bench_function("crypto_api.poseidon_hash_2", |b| {
        b.iter(|| {
            let hash = api
                .poseidon_hash_2(black_box([45u8; 32]), black_box([46u8; 32]))
                .expect("benchmark poseidon hash should succeed");
            black_box(hash)
        })
    });
}

#[cfg(feature = "crypto")]
fn bench_sign_and_build_shield(c: &mut Criterion) {
    const PRIVATE_KEY_HEX: &str =
        "0101010101010101010101010101010101010101010101010101010101010101";

    c.bench_function("signing_api.sign_and_build_shield", |b| {
        b.iter(|| {
            let signed = SigningApi::sign_and_build_shield(
                black_box(1_000u128),
                black_box(1u32),
                black_box([15u8; 32]),
                black_box(vec![16u8; 32]),
                black_box(0u32),
                black_box(PRIVATE_KEY_HEX),
            )
            .expect("benchmark signing should succeed");
            black_box(signed)
        })
    });
}

#[cfg(feature = "crypto")]
criterion_group!(
    benches,
    bench_build_shield_unsigned,
    bench_build_unshield_unsigned,
    bench_build_transfer_unsigned,
    bench_call_data_builder_transfer,
    bench_serialize_signed_transaction,
    bench_crypto_api_compute_commitment,
    bench_crypto_api_compute_nullifier,
    bench_crypto_api_poseidon_hash_2,
    bench_sign_and_build_shield
);

#[cfg(not(feature = "crypto"))]
criterion_group!(
    benches,
    bench_build_shield_unsigned,
    bench_build_unshield_unsigned,
    bench_build_transfer_unsigned,
    bench_call_data_builder_transfer,
    bench_serialize_signed_transaction
);

criterion_main!(benches);
