# Protocol Core Architecture

## Objetivo

`orbinum-protocol-core` es el núcleo de construcción de transacciones y utilidades criptográficas para Orbinum, con soporte para Rust nativo y WASM.

Está organizado siguiendo Clean Architecture para separar:

- reglas de negocio,
- casos de uso,
- adaptadores técnicos,
- y superficie pública.

## Estructura por capas

```text
src/
├── domain/          # Tipos puros, entidades y puertos (sin infraestructura)
├── application/     # Builders, validadores, params y lógica de orquestación
├── infrastructure/  # Implementaciones técnicas (codec, serializers, crypto, adapters)
└── presentation/    # API pública Rust/WASM y modelos de salida
```

### 1) Domain (`src/domain`)

Responsabilidad:

- Modelo de dominio y contratos.
- No depende de detalles concretos de serialización ni del runtime.

Contenido principal:

- `types/`: `Address`, `Hash`, `Commitment`, `Nullifier`, `AssetId`, etc.
- `entities.rs`: `UnsignedTransaction`, `SignedTransaction`.
- `ports.rs` y `ports/encoder.rs`: contratos como `SignerPort`, `HashPort`, `EncoderPort`.

### 2) Application (`src/application`)

Responsabilidad:

- Casos de uso y validaciones de negocio.
- Usa puertos del dominio y params de entrada.

Contenido principal:

- `builders/`: shield, unshield, transfer, compliance, extrinsic.
- `validators/`: validación de transacciones core y compliance.
- `params.rs`: contratos de entrada para todos los builders/APIs.
- utilidades: `memo_utils`, `key_manager`, `note_manager`.

### 3) Infrastructure (`src/infrastructure`)

Responsabilidad:

- Implementaciones concretas de puertos.
- Serialización SCALE, adapters serde y crypto real.

Contenido principal:

- `codec/`: wrappers y encoder SCALE.
- `serializers/`: construcción de call data y serialización de extrinsics.
- `serde_adapters/`: serialización/deserialización de tipos de dominio.
- `crypto.rs`: provider ZK y signer ECDSA/Keccak (según features).

### 4) Presentation (`src/presentation`)

Responsabilidad:

- Superficie pública de consumo.
- API orientada a uso (Rust y WASM).

Contenido principal:

- `api/`: `TransactionApi`, `SigningApi`.
- `crypto_api.rs`: operaciones ZK de alto nivel.
- `zk_models.rs`: modelos públicos para note/nullifier/proofs.
- `wasm_bindings.rs`: bindings JS/TS cuando el target es wasm32.
- `config.rs`: constantes de índices de pallet/calls.

## Flujo principal de ejecución

```text
Cliente (Rust o WASM)
  -> presentation/api
  -> application/builders + validators
  -> infrastructure/serializers + codec
  -> bytes SCALE listos para firmar/enviar
```

Para flujos con firma integrada (nativo):

```text
presentation::api::SigningApi
  -> infrastructure::crypto::EcdsaSigner
  -> application::builders::{shield,unshield,transfer}::build_signed
  -> extrinsic serializado
```

## Feature gates y targets

- `crypto-zk`: habilita operaciones ZK (commitment/nullifier/poseidon).
- `crypto-signing`: habilita firma ECDSA/Keccak.
- `crypto`: habilita ambas (`crypto-zk` + `crypto-signing`).
- `target_arch = "wasm32"`: expone `presentation::wasm_bindings`.

Notas:

- `SigningApi` requiere `feature = "crypto"`.
- `wasm_bindings` solo existe para target WASM.

## Principios aplicados

- Separación estricta de responsabilidades por capa.
- Dependencias dirigidas hacia adentro (presentation -> application -> domain).
- Infraestructura implementa contratos definidos por domain/application.
- Surface API estable concentrada en `presentation` y reexports de `lib.rs`.

## Recomendación de uso

- Integraciones de producto: usar `presentation::api` (y WASM bindings en frontend).
- Integraciones avanzadas: usar capas inferiores solo si necesitas control fino.
- Mantener cambios de serialización/crypto en `infrastructure` para no contaminar dominio.
