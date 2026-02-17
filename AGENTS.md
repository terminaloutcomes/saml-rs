# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains the core `saml-rs` library modules (`metadata`, `response`, `assertion`, `xml`, etc.).
- `tests/` holds Rust integration tests (`test_metadata.rs`, `test_response.rs`).
- `saml_test_server/` is a workspace member binary for local IdP/SP flow testing.
- `examples/` stores sample SAML XML payloads and config fixtures used by tests and manual validation.
- Top-level Python files (`test_examples.py`, `test_c14n.py`) support XML/signature validation workflows.
- Utility scripts live at repo root: `pre-commit.sh`, `builddocs.sh`, `docker_build.sh`, `run_docker_example.sh`.

## Build, Test, and Development Commands
- `cargo build --workspace`: build the library and test server.
- `cargo test --workspace`: run Rust unit/integration tests.
- `./pre-commit.sh`: full local gate (`test`, `build --release`, `clippy`, `fmt --check`, `doc`).
- `cargo doc --no-deps --workspace --document-private-items`: generate local API docs.
- `uv sync --all-groups`: install Python tooling used by CI.
- `uv run pytest`, `uv run mypy test*.py`, `uv run pylint test*.py`: run Python checks.
- A task is not complete until `just check` runs with zero errors and zero warnings.

## Coding Style & Naming Conventions
- Rust edition is 2018; crate-level policy forbids unsafe code (`#![forbid(unsafe_code)]`).
- Always run `cargo fmt` and `cargo clippy --workspace` before opening a PR.
- Rust naming: modules/files `snake_case`, structs/enums `UpperCamelCase`, functions/tests `snake_case`.
- Python code follows Black/Pylint/Mypy expectations (see `pyproject.toml`; Pylint max line length is 200).

## Testing Guidelines
- Prefer deterministic tests in `tests/test_*.rs`; keep reusable fixtures in `examples/` or `src/test_samples.rs`.
- Run focused Rust tests with `cargo test <test_name>` while iterating.
- Use `uv run pytest -k <pattern>` for targeted Python runs.
- Avoid adding network-dependent tests; if unavoidable, make failure modes explicit and easy to skip.

## Commit & Pull Request Guidelines
- Follow the repository’s existing style: concise, Conventional-Commit-like messages such as `build(deps): bump ...`.
- Recommended format: `<type>(<scope>): imperative summary` (e.g., `fix(response): validate destination URL`).
- PRs should include: purpose, behavior changes, test evidence (commands run), and linked issues.
- For protocol/XML changes, include a minimal sample payload or fixture update in `examples/`.

## Security & Configuration Tips
- Do not commit certificates, private keys, or environment-specific secrets.
- Use environment variables for runtime key/cert paths in container/server workflows.
- Follow `SECURITY.MD` for vulnerability reporting.
