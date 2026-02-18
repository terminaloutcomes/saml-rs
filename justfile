[private]
default:
    just --list

check: clippy test

clippy:
    cargo clippy --workspace --all-targets --all-features

test:
    cargo test --all-targets --workspace
    cargo test --all-targets --workspace --features danger_i_want_to_risk_it_all

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


set positional-arguments

@coverage_inner *args='':
    cargo tarpaulin --workspace \
        --exclude-files=src/main.rs \
        --exclude-files=src/logging/mod.rs \
        --exclude-files=src/logging/consoleexporter.rs \
        $@

# run coverage checks
coverage:
    just coverage_inner --out=Html
    @echo "Coverage report should be at file://$(pwd)/tarpaulin-report.html"

coveralls:
    just coverage_inner --out=Html --coveralls $COVERALLS_REPO_TOKEN
    @echo "Coverage report should be at https://coveralls.io/github/terminaloutcomes/saml-rs?branch=$(git branch --show-current)"
