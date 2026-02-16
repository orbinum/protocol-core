# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-16

## [0.1.0] - 2026-02-16

### Added

- Initial public release of `orbinum-protocol-core` with Clean Architecture layering:
	- `domain` (types, entities, ports)
	- `application` (builders, validators, params, wallet utilities)
	- `infrastructure` (codec, serializers, crypto providers)
	- `presentation` (Rust API and WASM bindings)

- Core transaction construction API (`TransactionApi`) for unsigned flows:
	- Shield (`build_shield_unsigned`)
	- Unshield (`build_unshield_unsigned`)
	- Private transfer (`build_transfer_unsigned`)
	- Shield batch (`build_shield_batch_unsigned`)

- Compliance/disclosure transaction API for unsigned flows:
	- Set audit policy
	- Request disclosure
	- Approve disclosure
	- Reject disclosure
	- Submit disclosure
	- Batch submit disclosure

- Extrinsic composition API for externally signed payloads:
	- `build_signed_extrinsic`

- Native signing API (`SigningApi`, feature-gated):
	- Sign-and-build shield/unshield/transfer
	- Signer creation from hex private key
	- Address derivation from key

- ZK cryptography API (`CryptoApi`, feature-gated):
	- Note creation
	- Commitment computation
	- Nullifier computation
	- Poseidon hash (`hash_2`, `hash_4`)

- WASM bindings for JavaScript/TypeScript consumption (`target_arch = "wasm32"`):
	- `TransactionBuilder` methods for core, batch, and compliance calls
	- Input validation and type normalization for JS payloads
	- Optional crypto/signing exports via feature gates

- Full serializer/codec pipeline aligned to runtime call encoding:
	- SCALE encoder (`ScaleEncoder`)
	- Call-data builder (`CallDataBuilder`)
	- Substrate transaction encoder adapter
	- Signed transaction serializer

- Application/domain utilities:
	- Key management helpers
	- Encrypted memo helpers
	- Note scanning and selection utilities
	- Wallet balance and note-selection logic

- Validation layer:
	- Core transaction validation
	- Compliance/disclosure validation

- Feature matrix and build targets:
	- `std`
	- `crypto-zk`
	- `crypto-signing`
	- `crypto`
	- `subxt-native`
	- `subxt-web`

- Packaging and release readiness:
	- npm package template and npm README under `npm/`
	- GitHub Actions release workflow for build/tag/release/crates.io/npm publication

- Benchmarking baseline with Criterion:
	- Transaction API unsigned builders
	- Signing path benchmark
	- Serializer benchmarks (`CallDataBuilder`, signed transaction serialization)
	- ZK crypto benchmarks (`compute_commitment`, `compute_nullifier`, `poseidon_hash_2`)

- Initial project documentation set in `docs/`:
	- Protocol architecture
	- Complete API guide
	- 30/60/90 production roadmap
	- W3F budget proposal (EN/ES)