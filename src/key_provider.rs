//! Runtime key provider abstractions.

use std::collections::HashMap;

use crate::{error::SamlError, sign::SigningKey};

/// Public-key material supported for assertion encryption.
#[derive(Clone, Debug)]
pub enum EncryptionPublicKey {
    /// RSA public key used for key transport (for example RSA-OAEP variants).
    Rsa(rsa::RsaPublicKey),
    // TODO - Add support for EC keys (for example ECDH-ES variants).
}

/// Provides signing and encryption keys at runtime.
pub trait KeyProvider {
    /// Returns a signing key by id, or the provider default when id is omitted.
    fn get_signing_key(&self, key_id: Option<&str>) -> Result<&SigningKey, SamlError>;

    /// Returns an encryption key by id, or the provider default when id is omitted.
    fn get_encryption_key(&self, key_id: Option<&str>) -> Result<&EncryptionPublicKey, SamlError>;
}

/// In-memory key provider for straightforward embedding/injection.
#[derive(Debug, Default)]
pub struct InMemoryKeyProvider {
    signing_keys: HashMap<String, SigningKey>,
    encryption_keys: HashMap<String, EncryptionPublicKey>,
    default_signing_key_id: Option<String>,
    default_encryption_key_id: Option<String>,
}

impl InMemoryKeyProvider {
    /// Create an empty key provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a signing key.
    pub fn insert_signing_key(&mut self, key_id: impl Into<String>, signing_key: SigningKey) {
        self.signing_keys.insert(key_id.into(), signing_key);
    }

    /// Insert an encryption key.
    pub fn insert_encryption_key(
        &mut self,
        key_id: impl Into<String>,
        encryption_key: EncryptionPublicKey,
    ) {
        self.encryption_keys.insert(key_id.into(), encryption_key);
    }

    /// Set default signing key id.
    pub fn set_default_signing_key_id(&mut self, key_id: impl Into<String>) {
        self.default_signing_key_id = Some(key_id.into());
    }

    /// Set default encryption key id.
    pub fn set_default_encryption_key_id(&mut self, key_id: impl Into<String>) {
        self.default_encryption_key_id = Some(key_id.into());
    }

    fn resolve_key_id<'a>(
        requested_key_id: Option<&'a str>,
        default_key_id: &'a Option<String>,
    ) -> Result<&'a str, SamlError> {
        match requested_key_id {
            Some(value) => Ok(value),
            None => default_key_id.as_deref().ok_or(SamlError::NoKeyAvailable),
        }
    }
}

impl KeyProvider for InMemoryKeyProvider {
    fn get_signing_key(&self, key_id: Option<&str>) -> Result<&SigningKey, SamlError> {
        let resolved_key_id = Self::resolve_key_id(key_id, &self.default_signing_key_id)?;
        self.signing_keys
            .get(resolved_key_id)
            .ok_or(SamlError::NoKeyAvailable)
    }

    fn get_encryption_key(&self, key_id: Option<&str>) -> Result<&EncryptionPublicKey, SamlError> {
        let resolved_key_id = Self::resolve_key_id(key_id, &self.default_encryption_key_id)?;
        self.encryption_keys
            .get(resolved_key_id)
            .ok_or(SamlError::NoKeyAvailable)
    }
}
