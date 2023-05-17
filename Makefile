setup:
	rustup update
	rustup component add clippy
	cargo install cargo-audit

build:
	cargo build --release

build-wasm:
	cargo build --target wasm32-unknown-unknown --release

fmt:
	cargo fmt --all

test:
	cargo test --all-features --release

lint:
	cargo clippy --all-targets --all-features -- -D warnings

doc:
	cargo doc --no-deps --document-private-items --all-features --examples

bench:
	cargo bench --features benchmarking

audit:
	cargo audit
