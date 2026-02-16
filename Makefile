.PHONY: all build test check clean wasm wasm-node examples doc help

# Default target
all: check test

# Build all targets
build:
	@echo "🔨 Building wallet-core-wasm..."
	@cargo build --release --features crypto
	@echo "✅ Build complete"

# Run tests
test:
	@echo "🧪 Running tests..."
	@cargo test --features crypto
	@cargo test --features "crypto-zk,subxt-native"
	@echo "✅ Tests passed"

# Check compilation
check:
	@echo "🔍 Checking code..."
	@cargo check --features "crypto,subxt-native"
	@cargo clippy --features "crypto,subxt-native" -- -D warnings
	@echo "✅ Check complete"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning..."
	@cargo clean
	@rm -rf pkg pkg-node
	@echo "✅ Clean complete"

# Build WASM for web (with ZK crypto, no signing)
wasm:
	@echo "🌐 Building WASM for web (with crypto-zk)..."
	@wasm-pack build --target web --out-dir pkg --release --features crypto-zk
	@echo "✅ WASM build complete: pkg/"
	@echo "   ✅ Poseidon hash available"
	@echo "   ✅ Commitments/Nullifiers available"
	@echo "   ❌ Signing NOT available (use @polkadot/keyring)"

# Build WASM for Node.js (with ZK crypto, no signing)
wasm-node:
	@echo "📦 Building WASM for Node.js (with crypto-zk)..."
	@wasm-pack build --target nodejs --out-dir pkg-node --release --features crypto-zk
	@echo "✅ WASM Node build complete: pkg-node/"

# Build all WASM targets
wasm-all: wasm wasm-node

# Format code
fmt:
	@echo "✨ Formatting code..."
	@cargo fmt
	@echo "✅ Format complete"

# Run benchmarks (if any)
bench:
	@echo "⚡ Running benchmarks..."
	@cargo bench --features crypto

# Show help
help:
	@echo "Wallet Core WASM - Makefile targets:"
	@echo ""
	@echo "  make all         - Check and test everything"
	@echo "  make build       - Build release version with crypto"
	@echo "  make test        - Run all tests"
	@echo "  make check       - Check code and run clippy"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make wasm        - Build WASM for web"
	@echo "  make wasm-node   - Build WASM for Node.js"
	@echo "  make wasm-all    - Build all WASM targets"
	@echo "  make fmt         - Format code"
	@echo "  make help        - Show this help"
	@echo ""
