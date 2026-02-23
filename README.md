# orbinum-protocol-core

Core Rust/WASM protocol library for building and encoding Orbinum shielded-pool transactions.

**Universal Package**: Works seamlessly in **Node.js**, **Browsers**, **Rust Native**, and **WASM Runtimes** (Polkadot, Near, etc.).

## Features

- **Universal WASM**: Single package supports `require('fs')` in Node and `fetch()` in Web.
- **Native Rust**: Full support for `no_std` environments and native binary compilation.
- **Type-safe**: Generated from runtime metadata using Subxt.
- **Zero-Knowledge Primitives**: Poseidon hashing, commitment generation, nullifier computation.
- **Transaction Building**: Create unsigned transactions for Note Transfer, Shielding, and Unshielding.
- **Clean Architecture**: Domain-driven design with clear separation of concerns.

## Installation

### JavaScript / TypeScript (npm)

```bash
npm install @orbinum/protocol-core
```

### Rust (Cargo)

```toml
[dependencies]
orbinum-protocol-core = "0.2.0"
```

## Usage

### Web / Browser (React, Next.js)

The npm package automatically uses `fetch` to load the WASM binary.

```typescript
import { Crypto, TransactionBuilder } from '@orbinum/protocol-core';

async function main() {
  // Initialize WASM (downloads from CDN or local asset)
  await Crypto.init(); 

  // Create a Note Commitment
  const commitment = Crypto.computeCommitment("100", 1, ownerPubkey, blinding);
  console.log("Commitment:", commitment);
}
```

### Node.js (Backend)

The npm package automatically uses `fs` to load the WASM binary.

```javascript
const { Crypto } = require('@orbinum/protocol-core');

async function main() {
  // Initialize WASM (loads from disk)
  await Crypto.init();
  
  const hash = Crypto.poseidonHash2(left, right);
  console.log("Hash:", hash);
}
```

### Rust (Native / WASM Runtime)

Ideal for CLI tools, Substrate pallets, or generic WASM actors.

```rust
use orbinum_protocol_core::{CryptoApi, TransactionBuilder};

fn main() {
    // Native Rust code (no WASM initialization needed)
    let commitment = CryptoApi::compute_commitment(
        "100", 
        1, 
        &owner_pubkey, 
        &blinding
    ).unwrap();
    
    println!("Commitment: {:?}", commitment);
}
```

## Build from Source

To build the universal package locally (requires `rust`, `wasm-pack`, and `node`):

```bash
# Build both targets (pkg/web and pkg/node)
make wasm-all
```

## Documentation

This README is intentionally brief. Full documentation is in `docs/`:

- [Architecture](docs/PROTOCOL_CORE_ARCHITECTURE.md)
- [API Reference](docs/PROTOCOL_CORE_API.md)

## License

Apache-2.0 OR GPL-3.0-or-later

