#!/bin/bash

cargo test --workspace && cargo build --workspace --release && cargo clippy --workspace && cargo fmt -- --check && cargo doc --no-deps --workspace --document-private-items
