# orbinum-protocol-core

Core Rust/WASM protocol library for building and encoding Orbinum shielded-pool transactions.

`orbinum-protocol-core` provides a clean, feature-gated API for:
- unsigned call-data construction,
- signed extrinsic building,
- compliance/disclosure transaction flows,
- ZK helper operations (commitment, nullifier, Poseidon hashing),
- JavaScript/TypeScript consumption through WASM bindings.

## Status

- Version: `0.1.0` (initial release)
- Maturity: active development (MVP hardening phase)
- Runtime scope: Substrate/Frontier-compatible transaction payloads

## Features

- `std` (default)
- `crypto-zk`
- `crypto-signing`
- `crypto` (enables both `crypto-zk` and `crypto-signing`)
- `subxt-native`
- `subxt-web`

## Build

```bash
cargo build --release --features crypto
```

## WASM

```bash
wasm-pack build --target web --out-dir pkg --release --features crypto-zk
wasm-pack build --target nodejs --out-dir pkg-node --release --features crypto-zk
```

## Validate

```bash
make fmt
make test
make bench
```

## Documentation

This README is intentionally brief. Full documentation is in `docs/`:

- [Architecture](docs/PROTOCOL_CORE_ARCHITECTURE.md)
- [API Reference](docs/PROTOCOL_CORE_API.md)

## License

Apache-2.0 OR GPL-3.0-or-later
