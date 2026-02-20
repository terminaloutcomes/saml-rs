# SAML-RS Safe SAML Implementation To-Do List

## Summary

This list identifies remaining work for robust, secure SAML 2.0 support in the saml-rs library, focusing on assertion signing, encryption, proper XML security, and comprehensive validation. The library currently supports basic unsigned assertion generation and signed assertions, but lacks encrypted assertions and some critical validation/verification capabilities.

**Library Design Principles:**

- Third-party consumable API with clear, minimal dependencies
- Runtime-configurable keys (rotation is up to the consumer)
- Encrypt-assertions-by-default with configurable override
- Use rustcrypto crates exclusively (no openssl)
- Strong security defaults with opt-in relaxed settings

---

## ✅ Current State (Implemented)

- **Basic unsigned assertions**: Generated and serialized
- **Assertion signing**: SHA-1/SHA-256/SHA-384/SHA-512 with RSA (via openssl)
- **Response/message signing**: Implemented in `response.rs`
- **XML hardening**: XML security policy with limits on depth, attributes, text size, DTD/PI/CDATA rejection
- **Service Provider metadata parsing**: Full parsing of SP metadata including signing/want-assertions-signed flags
- **IdP metadata support**: Basic metadata handling
- **Live e2e test harness**: Uses Keycloak as SP peer
- **Security defaults**: Strict parsing by default, danger feature for relaxed settings

**Current Limitations:**

- Uses `openssl` for cryptographic operations (needs migration to rustcrypto later)
- No encrypted assertion support
- No signature verification (only signing)
- No response parsing (IdP-only)

---

## 📋 To-Do List

### 1. Assertion Encryption (High Priority)

- [x] Implement `EncryptedAssertion` XML structure parsing and generation
- [x] Implement A256CBC-HS512 (AES-256-CBC + HMAC-SHA-512) for content encryption
- [x] Implement RSA-OAEP-256 for key encryption (default)
- [ ] Add `EncryptionAlgorithm` enum with support for:
  - [ ] A128CBC-HS256, A256CBC-HS512 (AES-CBC + HMAC)
  - [ ] A128GCM, A256GCM (AES-GCM)
  - [ ] RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512
  - [ ] ECDH-ES with AES-KW key wrap
- [ ] Support `xenc:EncryptedKey` for key transport
- [ ] Add encrypted assertion decryption in response parsing
- [ ] Add validation: ensure encrypted assertions are signed (SAML 2.0 spec requirement)

### 2. Key Management (High Priority)

- [ ] Add `struct KeyProvider` trait for runtime key configuration
- [ ] Support RSA key generation and loading (PEM/RSA private keys)
- [ ] Support EC key generation and loading (P-256, P-384, secp256k1)
- [ ] Support Ed25519 key generation and loading
- [ ] Add `KeyInfo` structure for embedding public keys in assertions
- [ ] Add `KeyProvider::get_signing_key(&self, key_id: Option<&str>) -> Result<&PrivateKey>`
- [ ] Add `KeyProvider::get_encryption_key(&self, key_id: Option<&str>) -> Result<&PublicKey>`

### 3. Enhanced Signature Verification (High Priority)

- [ ] Implement signature verification for assertions (currently only signing implemented)
- [ ] Implement signature verification for responses (currently only signing implemented)
- [ ] Verify `ds:SignedInfo` references match actual XML content (URI verification)
- [ ] Implement `ds:Reference#Transforms` validation (C14N, XPath, etc.)
- [ ] Verify certificate chains or public key matching from metadata
- [ ] Add `Response::verify_signature(&self, key_provider: &impl KeyProvider) -> Result<bool>`
- [ ] Add `Assertion::verify_signature(&self, key_provider: &impl KeyProvider) -> Result<bool>`

### 4. Response Parsing & Validation (High Priority)

- [ ] Implement `Response` XML parsing from base64-decoded, inflated bytes
- [ ] Parse `Response` elements: `InResponseTo`, `Destination`, `Issuer`, `Status`, `Signature`
- [ ] Parse `Assertion` elements from inside response (encrypted or plaintext)
- [ ] Validate `InResponseTo` matches original request ID
- [ ] Validate `Destination` matches expected SP ACS URL
- [ ] Validate `Issuer` matches expected IdP entity ID
- [ ] Handle both signed and unsigned responses/assertions

### 5. AuthnRequest Validation (Medium Priority)

- [ ] Implement AuthnRequest parsing (currently only request generation)
- [ ] Verify AuthnRequest signature (when signed)
- [ ] Validate `Destination` matches IdP endpoint
- [ ] Validate `IssueInstant` is not in the past (configurable clock skew)
- [ ] Store signed AuthnRequest for replay protection

### 6. Replay Protection (Medium Priority)

- [ ] Implement `ReplayCache` trait for storing processed `InResponseTo` values
- [ ] Reject duplicate `InResponseTo` values within TTL window
- [ ] Add configurable replay window (default: 5 minutes)
- [ ] Implement persistence interface for distributed deployments

### 7. NameID Format Handling (Low Priority)

- [ ] Implement all SAML 2.0 NameID formats from spec
- [ ] Support NameID encryption (transient vs persistent)
- [ ] Add `NameIDPolicy` parsing for SP requests

### 8. Conditions & AttributeStatement Validation (Medium Priority)

- [ ] Validate `Conditions` `NotBefore` and `NotOnOrAfter` timestamps
- [ ] Validate `Audience` restrictions match SP entity ID
- [ ] Validate `AuthnContext` class references
- [ ] Implement attribute filtering based on SP requirements

### 9. Binding & Protocol Support (Medium Priority)

- [ ] Implement HTTP-POST binding (response handling at SP)
- [ ] Implement HTTP-Redirect binding (request handling at IdP)
- [ ] Add `SAMLResponse` query parameter encoding
- [ ] Add `RelayState` validation and round-trip preservation

### 10. XML Canonicalization & Digest (Medium Priority)

- [ ] Verify canonicalization produces deterministic output
- [ ] Implement `ds:DigestMethod` validation (SHA-256, SHA-384, SHA-512)
- [ ] Add unit tests for C14N edge cases

### 11. Security Policy Enhancements (Medium Priority)

- [ ] Add `SecurityPolicy` field: `require_encrypted_assertions` (default: false)
- [ ] Add `SecurityPolicy` field: `allowed_encryption_algorithms` (whitelist)
- [ ] Add `SecurityPolicy` field: `require_response_signature` (default: true)
- [ ] Add `SecurityPolicy` field: `require_assertion_signature` (default: true)
- [ ] Implement signature algorithm whitelisting per security policy
- [ ] Add runtime check: reject SHA-1 when not in danger mode
- [ ] Add runtime check: reject RSA-OAEP with <256-bit hash

### 12. Test Coverage & Examples (Medium Priority)

- [ ] Add signed assertion validation test vectors
- [ ] Add encrypted assertion test vectors (interop with Keycloak)
- [ ] Add attack fixture tests for signature manipulation
- [ ] Add benchmark tests for parsing/signing/encryption performance
- [ ] Document example flows: IdP-initiated vs SP-initiated

### 13. Migration from openssl to rustcrypto (Medium Priority)

- [ ] Replace `openssl` with `rsa`, `ecdsa`, `ed25519`, `p256`, `k256` crates
- [ ] Replace `openssl::x509` with `x509-cert`, `pkcs8`, `pem-rfc7468`
- [ ] Replace `openssl::hash` with `sha2`, `sha3`, `blake2`
- [ ] Replace `openssl::sign` with `rsa`, `ecdsa`, `ed25519` signature APIs
- [ ] Replace `openssl::pkey` with `rsa::Rsa`, `p256::ecdsa::SigningKey`, `ed25519_dalek::SigningKey`

### 14. Documentation & API Refinement (Medium Priority)

- [ ] Document security guarantees and assumptions
- [ ] Add example code for common patterns (signing, encryption, verification)
- [ ] Add API documentation for all public methods
- [ ] Document threat model and mitigation strategies

### 15. Performance & Optimization (Low Priority)

- [ ] Add response caching for repeated assertions
- [ ] Implement streaming XML parsing for large payloads
- [ ] Optimize canonicalization for large assertions
- [ ] Add memory usage benchmarks

---

## 🔐 Cryptographic Configuration (High Priority)

### Default Encryption (A256CBC-HS512 + RSA-OAEP-256)

```rust
pub struct EncryptionConfig {
    pub content_algorithm: ContentEncryptionAlgorithm,
    pub key_encryption_algorithm: KeyEncryptionAlgorithm,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            content_algorithm: ContentEncryptionAlgorithm::A256CBC_HS512,
            key_encryption_algorithm: KeyEncryptionAlgorithm::RSA_OAEP_256,
        }
    }
}
```

### Runtime Key Configuration

```rust
pub trait KeyProvider {
    fn get_signing_key(&self, key_id: Option<&str>) -> Result<&dyn Signer>;
    fn get_encryption_key(&self, key_id: Option<&str>) -> Result<&dyn KeyEncipher>;
    fn get_verification_key(&self, key_id: Option<&str>) -> Result<&dyn Verifier>;
    fn get_decryption_key(&self, key_id: Option<&str>) -> Result<&dyn KeyDecipher>;
}
```

---

## 🎯 Priority Implementation Order

1. **Migration to rustcrypto** (remove openssl dependency)
2. **Assertion Encryption** (required for production SAML)
3. **Signature Verification** (security requirement)
4. **Response Parsing** (completes the protocol flow)
5. **Key Management** (runtime configuration)
6. **Security Policy Enhancements** (enables strict mode)
7. **Replay Protection** (security requirement)
8. **AuthnRequest Validation** (completes IdP flow)

---

## 📦 Dependency Changes (Cargo.toml)

### Remove (Once no longer required)

- `openssl`

### Add (already present or add)

- `rsa` (0.9) - RSA signing/encryption
- `p256` (0.13) - ECDSA P-256
- `p384` - ECDSA P-384
- `k256` (0.13) - ECDSA secp256k1
- `ed25519-dalek` (1.6) - Ed25519 signing
- `x509-cert` (0.3) - X.509 certificate handling
- `pkcs8` (0.10) - PKCS#8 key formatting
- `pem-rfc7468` (1.0) - PEM encoding
- `der` (0.7) - DER encoding
- `const-oid` (0.8) - OID constants
- `aes-gcm` (0.11) - AES-GCM encryption
- `chacha20poly1305` (0.10) - ChaCha20-Poly1305
- `sha2` (0.10) - SHA-256/384/512
- `sha3` (0.10) - SHA-3
- `blake2` (0.10) - BLAKE2
- `hmac` (0.12) - HMAC
- `hkdf` (0.6) - HKDF key derivation

---

## 📝 Notes

- **No openssl**: The library will use pure Rust cryptography via rustcrypto crates
- **Runtime key configuration**: Keys are provided by the consumer
- **Encrypt by default**: Encrypted assertions are the default, but can be disabled per-assertion
- **Configurable algorithms**: All cryptographic algorithms are configurable but have secure defaults
- **Third-party library**: API designed for consumption, not just internal use
- **SAML 2.0 compliance**: Focus on Web Browser SSO profile, but design for extensibility
