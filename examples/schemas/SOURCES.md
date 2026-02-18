# Vendored Schema Sources

These schema files are vendored for offline, reproducible SAML validation in local tooling and tests.

## Source of truth

The canonical download + verification process is:

```bash
uv run python scripts/fetch_saml_schemas.py
```

Verification-only mode (no network):

```bash
uv run python scripts/fetch_saml_schemas.py --verify-only
```

## Pinned files

| File | Source URL | SHA256 |
| --- | --- | --- |
| `saml-schema-protocol-2.0.xsd` | `https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd` | `554250583cd5eacc6ce5f094f6ff50fc2547972c436dc96e2e7eb41abf2c817e` |
| `saml-schema-assertion-2.0.xsd` | `https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd` | `006eb7553843cb7baa9b08da2a9d444346c0e982fb9d9293babe08ede680924b` |
| `xmldsig-core-schema.xsd` | `https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd` | `35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c` |
| `xenc-schema.xsd` | `https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd` | `5dd57f074870e1d91f7eb814aa92967cefcce9011a86adf5e12a769fcf2a237e` |
