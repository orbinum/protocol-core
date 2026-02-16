# Protocol Core API Reference

## Alcance

Este documento cubre la superficie pública expuesta por `orbinum-protocol-core` para consumo:

- Rust (API principal),
- features condicionales,
- y WASM (bindings para JS/TS).

Cuando una API depende de un feature, se indica explícitamente.

## 1. Exportaciones públicas en `lib.rs`

### Reexports principales

- `pub mod domain`
- `pub mod application`
- `pub mod infrastructure`
- `pub mod presentation`
- `pub use presentation::api::*`
- `pub use application::validators::TransactionValidator`
- `pub use infrastructure::crypto::*` (feature-gated por módulo)
- `pub type Result<T> = core::result::Result<T, Error>`
- `pub enum Error` (errores de validación, serialización, cryptography, etc.)

### Exportaciones WASM (solo `target_arch = "wasm32"`)

- `pub use presentation::wasm_bindings::*`

## 2. API Rust recomendada (`presentation::api`)

## `TransactionApi`

Constructor:

- `TransactionApi::new() -> Self`

### Core builders

- `build_shield_call_data(params: ShieldParams) -> Result<Vec<u8>>`
- `build_unshield_call_data(params: UnshieldParams) -> Result<Vec<u8>>`
- `build_transfer_call_data(params: TransferParams) -> Result<Vec<u8>>`

### Compliance builders

- `build_disclose_call_data(params: DiscloseParams) -> Result<Vec<u8>>`
- `build_register_vk_call_data(params: RegisterVkParams) -> Result<Vec<u8>>`
- `build_pause_call_data(params: PauseParams) -> Result<Vec<u8>>`
- `build_unpause_call_data(params: UnpauseParams) -> Result<Vec<u8>>`

### Extrinsics (unsigned)

- `build_extrinsic(call_data: &[u8]) -> Result<Vec<u8>>`
- `build_batch_extrinsic(call_datas: &[Vec<u8>], atomic: bool) -> Result<Vec<u8>>`
- `build_batch_calls(call_datas: &[Vec<u8>], atomic: bool) -> Result<Vec<u8>>`

### Utilidades

- `validate_transaction(tx: &UnsignedTransaction) -> Result<()>`

## `SigningApi` (requiere `feature = "crypto"`)

Constructor:

- `SigningApi::new() -> Self`

Métodos:

- `build_and_sign_shield(params: ShieldParams, private_key: &[u8; 32], nonce: u32) -> Result<Vec<u8>>`
- `build_and_sign_unshield(params: UnshieldParams, private_key: &[u8; 32], nonce: u32) -> Result<Vec<u8>>`
- `build_and_sign_transfer(params: TransferParams, private_key: &[u8; 32], nonce: u32) -> Result<Vec<u8>>`
- `sign_call_data(call_data: &[u8], private_key: &[u8; 32], nonce: u32) -> Result<Vec<u8>>`
- `derive_public_key(private_key: &[u8; 32]) -> Result<[u8; 33]>`

## `CryptoApi` (feature-gated)

La API criptográfica de alto nivel se expone en `presentation::crypto_api` y depende de features crypto.
Incluye utilidades para:

- generación de keypairs,
- commitments,
- nullifiers,
- hashing Poseidon,
- cifrado/descifrado de memo.

(Para consumidores de frontend, la vía recomendada es usar las clases WASM listadas más abajo.)

## 3. Parámetros de entrada (`application::params`)

Tipos de params usados por `TransactionApi`/`SigningApi`:

- `ShieldParams`
- `UnshieldParams`
- `TransferParams`
- `DiscloseParams`
- `RegisterVkParams`
- `PauseParams`
- `UnpauseParams`

Estos structs concentran el contrato de entrada para construcción de calls/extrinsics.

## 4. Modelos de salida y tipos comunes

Tipos comúnmente consumidos:

- `UnsignedTransaction`
- `SignedTransaction`
- `Address`, `Hash`, `Commitment`, `Nullifier`, `AssetId`
- modelos ZK de `presentation::zk_models` (según flujo y feature)

## 5. API WASM (JS/TS)

Disponible cuando se compila para `wasm32` y se consume desde el paquete npm generado.

## Clases principales

### `TransactionBuilder`

Operaciones de construcción de transacciones/calls para shield, unshield y transfer.
Devuelve bytes serializados para envío/firma según método.

### `Crypto`

Operaciones criptográficas para ZK:

- derivación/generación de claves,
- cálculo de commitment/nullifier,
- utilidades hash.

### `EncryptedMemo`

Manejo de memo encriptado:

- creación,
- serialización,
- parsing,
- cifrado/descifrado.

### `Proof`

Wrapper para datos de proof y serialización asociada.

### `KeyManager`

Utilidades para gestionar llaves en contexto WASM/JS.

## 6. Matriz de disponibilidad

- Core call builders (`TransactionApi`): sin feature crypto obligatorio.
- Signing (`SigningApi`): requiere `crypto`.
- Crypto ZK (`CryptoApi`/`Crypto`): requiere `crypto-zk` o `crypto`.
- WASM classes: requieren build target `wasm32`.

## 7. Ejemplos de uso

## Rust: construir call de shield

```rust
use orbinum_protocol_core::{TransactionApi, ShieldParams};

let api = TransactionApi::new();
let params = ShieldParams {
    amount: 1_000,
    asset_id: 0,
    owner_pubkey: [0u8; 32],
    blinding: [1u8; 32],
    memo: None,
};

let call_data = api.build_shield_call_data(params)?;
```

## Rust: construir y firmar (feature `crypto`)

```rust
use orbinum_protocol_core::{SigningApi, TransferParams};

let api = SigningApi::new();
let private_key = [7u8; 32];
let nonce = 1;

let params = TransferParams {
    root: [0u8; 32],
    input_nullifiers: vec![[0u8; 32]],
    output_commitments: vec![[0u8; 32]],
    proof: vec![0u8; 192],
    memo: None,
};

let signed_ext = api.build_and_sign_transfer(params, &private_key, nonce)?;
```

## TypeScript (WASM): inicialización y uso básico

```ts
import init, { TransactionBuilder, Crypto } from "orbinum-protocol-core";

await init();

const builder = new TransactionBuilder();
const crypto = new Crypto();

// ejemplo conceptual: construir call + operación crypto
// los nombres exactos de métodos dependen del binding generado en pkg/*.d.ts
```

## 8. Guía de adopción

- Si construyes backend Rust: empieza por `TransactionApi`.
- Si además firmas en servidor: habilita `crypto` y usa `SigningApi`.
- Si construyes frontend/web wallet: usa build WASM + bindings de `pkg/`.
- Evita acoplarte a módulos internos de infraestructura salvo necesidad real.

## 9. Estabilidad y versionado

- La API de `presentation::api` es la superficie de consumo prioritaria.
- Módulos internos (`application`/`infrastructure`) son públicos pero pueden evolucionar con menor estabilidad.
- Para integraciones externas, anclar versión semver del crate/paquete npm.
