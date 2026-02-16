# @orbinum/protocol-core

> Core protocol primitives and WASM bindings for interacting with Orbinum

[![npm version](https://img.shields.io/npm/v/@orbinum/protocol-core.svg)](https://www.npmjs.com/package/@orbinum/protocol-core)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20GPL--3.0-blue)](https://github.com/orbinum/protocol-core/blob/main/LICENSE-APACHE2)

`@orbinum/protocol-core` exposes WASM bindings for:

- Building Orbinum transaction call data (`TransactionBuilder`)
- ZK cryptographic operations (`Crypto`)
- Encrypted memo utilities (`EncryptedMemo`)

## Installation

```bash
npm install @orbinum/protocol-core
```

## Usage

### 1) Initialize WASM module

```ts
import * as protocolCore from '@orbinum/protocol-core';

await protocolCore.default();
```

### 2) Build unsigned transactions

```ts
import { TransactionBuilder } from '@orbinum/protocol-core';

const callData = TransactionBuilder.buildShieldUnsigned(
  '1000',
  1,
  new Uint8Array(32),
  new Uint8Array(104),
  0
);
```

### 3) Build signed extrinsic with external signature

```ts
import { TransactionBuilder } from '@orbinum/protocol-core';

const signedExtrinsic = TransactionBuilder.buildSignedExtrinsic(
  callData,
  signatureBytes,   // Uint8Array(65)
  addressBytes,     // Uint8Array(20)
  nonce
);
```

### 4) ZK crypto operations

```ts
import { Crypto } from '@orbinum/protocol-core';

const commitment = Crypto.computeCommitment(
  '1000',
  1,
  ownerPubKey,
  blinding
);

const nullifier = Crypto.computeNullifier(commitment, spendingKey);
```

### 5) Encrypted memos

```ts
import { EncryptedMemo } from '@orbinum/protocol-core';

const encrypted = EncryptedMemo.encryptMemo(
  '1000',
  ownerPk,
  blinding,
  1,
  commitment,
  recipientViewingKey
);

const ok = EncryptedMemo.validateEncryptedMemo(encrypted);
```

## Exported API (WASM)

### TransactionBuilder

- `buildShieldUnsigned(amount, asset_id, commitment, encrypted_memo, nonce)`
- `buildShieldBatchUnsigned(operations_js, nonce)`
- `buildTransferUnsigned(input_nullifiers, output_commitments, root, proof, encrypted_memos_js, nonce)`
- `buildUnshieldUnsigned(nullifier, amount, asset_id, recipient, root, proof, nonce)`
- `buildSetAuditPolicyUnsigned(auditors_js, conditions_js, max_frequency, nonce)`
- `buildRequestDisclosureUnsigned(target, reason, evidence, nonce)`
- `buildApproveDisclosureUnsigned(auditor, commitment, zk_proof, disclosed_data, nonce)`
- `buildRejectDisclosureUnsigned(auditor, reason, nonce)`
- `buildSubmitDisclosureUnsigned(commitment, proof_bytes, public_signals, partial_data, auditor, nonce)`
- `buildBatchSubmitDisclosureUnsigned(submissions_js, nonce)`
- `buildSignedExtrinsic(call_data, signature, address, nonce)`

### Crypto

- `createNote(value, asset_id, owner_pubkey, blinding)`
- `computeCommitment(value, asset_id, owner_pubkey, blinding)`
- `computeNullifier(commitment, spending_key)`
- `poseidonHash2(left, right)`
- `poseidonHash4(inputs)`

### EncryptedMemo

- `createDummyMemo()`
- `encryptMemo(value, owner_pk, blinding, asset_id, commitment, recipient_vk)`
- `decryptMemo(encrypted, commitment, viewing_key)`
- `validateEncryptedMemo(encrypted)`

## Node.js

If your environment requires manual WASM loading:

```ts
import * as protocolCore from '@orbinum/protocol-core';
import { readFileSync } from 'node:fs';

const wasm = readFileSync('node_modules/@orbinum/protocol-core/orbinum_protocol_core_bg.wasm');
await protocolCore.default({ module: wasm });
```

## Notes

- This package is focused on transaction building and crypto helpers.
- Transaction signing strategy depends on your integration flow.
- For browser wallets, it is common to build unsigned call data and sign externally.

## License

Dual-licensed under Apache-2.0 OR GPL-3.0-or-later.

## Repository

https://github.com/orbinum/protocol-core
