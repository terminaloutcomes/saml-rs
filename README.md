# saml-rs

If you want to help - please log PRs/Issues against [terminaloutcomes/saml-rs](https://github.com/terminaloutcomes/saml-rs).

## Please help

I can't work out how to get signed assertions to validate in any publicly-available SP implementation :(

This library's in a lot of flux right now, if you're using it from Github then... sorry? Once it's published as a crate you'll have a relatively stable target, as much as that'll help?

## Documentation

The automatically-generated documentation based on the `main` branch is here: <https://terminaloutcomes.github.io/saml-rs/saml_rs/>

Project documentation sources for GitHub Pages live in this repository under `docs/`:

- Book entry: `docs/src/index.md`
- Getting started: `docs/src/getting-started.md`
- Publishing/deployment: `docs/src/publishing.md`

## Current implementation state

- `saml_test_server` currently handles the browser SSO path of:
  - SP Redirect AuthnRequest -> IdP `/SAML/Redirect`
  - IdP generates a POST form containing `SAMLResponse` back to the SP ACS
- Assertions are signed in the default test-server response path.
- Response-level message signing is currently disabled in the test-server flow.
- Assertion encryption (`EncryptedAssertion`) is not currently implemented.
- The local `live-e2e` harness uses HTTP endpoints for local-only automation.

## Security defaults

This crate now defaults to strict parsing and strict cryptographic policy:

- XML payloads reject `DOCTYPE`/DTD/entity-expansion, processing instructions, and XInclude-style include attempts.
- SHA-1 digest/signature use is rejected by default.
- `saml_test_server` defaults to requiring signed AuthnRequests and signed response messages.
- Unknown SP fallback is disabled by default.

Dangerous compatibility behavior is only available when both conditions are met:

1. compile with `--features danger_i_want_to_risk_it_all`
2. explicitly unlock runtime danger toggles via `saml_rs::security::danger::*`

## Live local interoperability test (no browser automation)

You can run a fully local SAML round-trip with:

- `saml_test_server` as the IdP (from this repo)
- Keycloak as a real SAML peer (as SP via identity brokering)
- a headless verifier script that drives the protocol and asserts success

### Prerequisites

- Docker (daemon running)
- `openssl` for some minor features
- `uv` (for running Python harness dependencies)

### Run

```shell
uv sync --all-groups
just live-e2e
```

This command will:

1. Generate temporary signing material in `.tmp/live-e2e/`
2. Start Keycloak (Docker) on `http://localhost:18080`
3. Start `saml_test_server` directly on your host via `cargo run` at `http://localhost:18081`
4. Run a headless end-to-end verifier (`scripts/live_e2e_verify.py`)
5. Tear everything down automatically (unless `KEEP_UP=1` is set)

`just live-e2e-test` is also available as an explicit test alias.

### Helper commands

```shell
just live-e2e-up
just live-e2e-down
```

If you want to keep the stack running after a test:

```shell
KEEP_UP=1 ./scripts/live_e2e.py run
```

You can tune startup waits for slower machines:

```shell
LIVE_E2E_KEYCLOAK_WAIT_TIMEOUT_SECONDS=300 \
LIVE_E2E_SAML_SERVER_WAIT_TIMEOUT_SECONDS=180 \
just live-e2e
```

The verifier drives the complete flow without a browser, including Keycloak's first-broker-login profile form.

## `saml_test_server` runtime config (current)

`saml_test_server` reads config from:

- `SAML_CONFIG_PATH` file (optional, default `~/.config/saml_test_server`)
- environment variables with `SAML_` prefix (override file values)

Key fields used by current code:

- `bind_address` / `SAML_BIND_ADDRESS`
- `bind_port` / `SAML_BIND_PORT`
- `listen_scheme` / `SAML_LISTEN_SCHEME` (`http` or `https`)
- `public_hostname` / `SAML_PUBLIC_HOSTNAME`
- `public_base_url` / `SAML_PUBLIC_BASE_URL` (used for metadata URLs)
- `entity_id` / `SAML_ENTITY_ID`
- `allow_unknown_sp` / `SAML_ALLOW_UNKNOWN_SP`
- `require_signed_authn_requests` / `SAML_REQUIRE_SIGNED_AUTHN_REQUESTS` (default `true`)
- `sign_assertion` / `SAML_SIGN_ASSERTION` (default `true`)
- `sign_message` / `SAML_SIGN_MESSAGE` (default `true`)
- `sp_metadata_files` / `SAML_SP_METADATA_FILES`
- `saml_cert_path` / `SAML_SAML_CERT_PATH` (IdP signing cert)
- `saml_key_path` / `SAML_SAML_KEY_PATH` (IdP signing key)
- `tls_cert_path` / `SAML_TLS_CERT_PATH` and `tls_key_path` / `SAML_TLS_KEY_PATH` when `listen_scheme=https`

## Generating the SAML keys for the test server

You'll need cloudflare's SSL toolkit [cloudflare/ssl](https://github.com/cloudflare/cfssl).

This assumes you're running it from `~/certs`

### Create a config.json

```json
{
    "hosts": [
        "example.com"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C":  "AU",
            "L":  "The Internet",
            "O":  "Example Org",
            "OU": "SAML",
            "ST": "Somewhere"
        }
    ]
}
```

### Running commands

This generates a CA cert, then signs a certificate for it with the same name. It's janky but it works.

```shell
$ cfssl genkey -initca config.json | cfssljson -bare ca
2021/07/30 23:58:29 [INFO] generate received request
2021/07/30 23:58:29 [INFO] received CSR
2021/07/30 23:58:29 [INFO] generating key: rsa-2048
2021/07/30 23:58:29 [INFO] encoded CSR
2021/07/30 23:58:29 [INFO] signed certificate with serial number 486163044885311370117893514213005435517027358051

$ cfssl gencert -ca ca.pem -ca-key ca-key.pem -hostname=example.com config.json | cfssljson -bare
2021/07/31 00:04:29 [INFO] generate received request
2021/07/31 00:04:29 [INFO] received CSR
2021/07/31 00:04:29 [INFO] generating key: rsa-2048
2021/07/31 00:04:29 [INFO] encoded CSR
2021/07/31 00:04:29 [INFO] signed certificate with serial number 31731242146728568970438012635101523767577144558

```

You end up with files you can specify in the config here:

```json
"saml_cert_path" : "~/certs/cert.pem",
"saml_key_path" : "~/certs/cert-key.pem"
```
