check:
    cargo clippy --workspace --all-targets --all-features

live-e2e:
    ./scripts/live_e2e.sh run

live-e2e-up:
    ./scripts/live_e2e.sh up

live-e2e-down:
    ./scripts/live_e2e.sh down
