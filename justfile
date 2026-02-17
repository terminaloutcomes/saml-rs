check:
    cargo clippy --workspace --all-targets --all-features
    cargo test

live-e2e:
    ./scripts/live_e2e.py run

live-e2e-up:
    ./scripts/live_e2e.py up

live-e2e-down:
    ./scripts/live_e2e.py down

docs:
    cargo doc --no-deps --workspace --document-private-items
