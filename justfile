[private]
default:
    just --list

check:
    cargo clippy --workspace --all-targets --all-features
    cargo test

live-e2e:
    uv run scripts/live_e2e.py run

live-e2e-test:
    uv run scripts/live_e2e.py run

live-e2e-up:
    uv run scripts/live_e2e.py up

live-e2e-down:
    uv run scripts/live_e2e.py down

docs:
    cargo doc --no-deps --workspace --document-private-items
