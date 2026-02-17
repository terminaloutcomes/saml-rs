# Security Policy

## Supported Versions

Only the latest released version is supported - if a major issue appears, old ones will be considered for patching, or yanked.

## Reporting a Vulnerability

Please contact me via email at james+saml-rs@terminaloutcomes.com

## Runtime Safety Notes

- Strict parsing and cryptographic defaults are enabled by default.
- The `danger_i_want_to_risk_it_all` feature intentionally exposes unsafe compatibility toggles.
- Do not enable the danger feature in production unless you have a documented exception and compensating controls.
