# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `Cargo.toml`: added `path` dependency on local `orbinum-zk-core` to access `poseidon_hash_1`

### Added
- **Universal NPM Package**: Support for both Node.js (CommonJS/fs) and Web (ESM/fetch) environments in a single package.
- **Hybrid CI Build**: `release.yml` now generates both `pkg/node` and `pkg/web` artifacts.
- **Conditional Exports**: `package.json` configured with `exports` field to automatically select the correct build based on the environment (`browser` vs `node`).
- **Documentation**: Updated README with instructions for JS/TS (Universal), Rust Native, and WASM Runtimes.
- **Selective Disclosure Witness API** (`src/application/disclosure.rs`):
  - `create_disclosure_witness()` — builds circuit inputs for `disclosure.circom` Groth16 proof
  - `DisclosureWitness` struct with 4 public inputs + 7 private inputs as `[u8; 32]` field elements and disclosure flags
  - `DisclosureError` enum (`InvalidMask`, `CryptoError`)
  - Support for all 7 valid mask combinations (value, asset_id, owner hash)
- **`poseidon_hash_1()`** added to `ZkCryptoProvider` (single-input Poseidon hash for viewing key)
- **WASM binding** `Crypto::buildDisclosureInputs()` exported to JavaScript/TypeScript
- **18 new tests** (11 unit + 7 integration) in `src/application/disclosure.rs` — all pass
- **Criterion benchmark** `bench_build_disclosure_witness` — ~12.7 µs (release profile)
- **E2E test** `tests/disclosure.test.ts`: full encrypt → decrypt → witness → proof → verify flow (1034ms)
- **E2E test** `tests/shield-and-disclose.test.ts`: Alice shields, generates ZK disclosure proof, Bob verifies (379ms)

### Changed
- Refactored `release.yml` to support multi-target WASM compilation.
- Updated `Cargo.toml` version to `0.2.0`.

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