//! Runtime key provider abstractions.

use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    error::SamlError,
    sign::{SamlSigningKey, SigningAlgorithm, VerificationKey},
};

/// Public-key material supported for assertion encryption.
#[derive(Clone, Debug)]
pub enum EncryptionPublicKey {
    /// RSA public key used for key transport (for example RSA-OAEP variants).
    Rsa(rsa::RsaPublicKey),
    // TODO - Add support for EC keys (for example ECDH-ES variants).
}

/// Builder for constructing immutable [`KeyService`] instances.
#[derive(Debug, Default)]
pub struct KeyServiceBuilder {
    signing_keys: HashMap<String, SamlSigningKey>,
    verification_keys: HashMap<String, VerificationKey>,
    encryption_keys: HashMap<String, EncryptionPublicKey>,
    default_signing_key_id: Option<String>,
    default_encryption_key_id: Option<String>,
}

impl KeyServiceBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a signing key; corresponding verification key material is derived and stored.
    pub fn with_signing_key(mut self, key_id: &impl ToString, signing_key: SamlSigningKey) -> Self {
        let key_id = key_id.to_string();
        let verification_key = signing_key
            .to_verification_key()
            .unwrap_or(VerificationKey::None);
        self.signing_keys.insert(key_id.clone(), signing_key);
        self.verification_keys.insert(key_id, verification_key);
        self
    }

    /// Register an encryption public key.
    pub fn with_encryption_key(
        mut self,
        key_id: &impl ToString,
        encryption_key: EncryptionPublicKey,
    ) -> Self {
        self.encryption_keys
            .insert(key_id.to_string(), encryption_key);
        // if the default encryption key id is not set, use the first added key as the default
        if self.default_encryption_key_id.is_none() {
            self.default_encryption_key_id = Some(key_id.to_string());
        }
        self
    }

    /// Set default key id used for signing and verification requests.
    pub fn default_signing_key_id(mut self, key_id: &impl ToString) -> Self {
        self.default_signing_key_id = Some(key_id.to_string());
        self
    }

    /// Set default encryption key id.
    pub fn default_encryption_key_id(mut self, key_id: &impl ToString) -> Self {
        self.default_encryption_key_id = Some(key_id.to_string());
        self
    }

    /// Build an immutable [`KeyService`].
    pub fn build(self) -> Result<KeyService, SamlError> {
        if let Some(default_signing_key_id) = self.default_signing_key_id.as_deref()
            && !self.signing_keys.contains_key(default_signing_key_id)
        {
            return Err(SamlError::NoKeyAvailable);
        }
        if let Some(default_encryption_key_id) = self.default_encryption_key_id.as_deref()
            && !self.encryption_keys.contains_key(default_encryption_key_id)
        {
            return Err(SamlError::NoKeyAvailable);
        }

        Ok(KeyService {
            signing_keys: self.signing_keys,
            verification_keys: self.verification_keys,
            encryption_keys: self.encryption_keys,
            default_signing_key_id: self.default_signing_key_id,
            default_encryption_key_id: self.default_encryption_key_id,
        })
    }
}

/// Immutable key service used for signing, verification, and encryption-key lookup.
#[derive(Debug, Default)]
pub struct KeyService {
    signing_keys: HashMap<String, SamlSigningKey>,
    verification_keys: HashMap<String, VerificationKey>,
    encryption_keys: HashMap<String, EncryptionPublicKey>,
    default_signing_key_id: Option<String>,
    default_encryption_key_id: Option<String>,
}

impl KeyService {
    /// Start building a new [`KeyService`].
    pub fn builder() -> KeyServiceBuilder {
        KeyServiceBuilder::new()
    }

    fn resolve_key_id(
        requested_key_id: Option<&str>,
        default_key_id: Option<&str>,
    ) -> Result<String, SamlError> {
        Ok(requested_key_id
            .map(|s| s.to_string())
            .unwrap_or(default_key_id.ok_or(SamlError::NoKeyAvailable)?.to_string()))
    }

    /// Sign bytes with configured private key material.
    pub fn sign(
        &self,
        key_id: Option<&str>,
        signing_algorithm: SigningAlgorithm,
        bytes_to_sign: &[u8],
    ) -> Result<Vec<u8>, SamlError> {
        let resolved_key_id = Self::resolve_key_id(key_id, self.default_signing_key_id.as_deref())?;
        let signing_key = self
            .signing_keys
            .get(&resolved_key_id)
            .ok_or(SamlError::NoKeyAvailable)?
            .clone();
        crate::sign::sign_data(signing_algorithm, &Arc::new(signing_key), bytes_to_sign)
    }

    /// Verify bytes with configured public verification material.
    pub fn verify(
        &self,
        key_id: Option<&str>,
        signing_algorithm: SigningAlgorithm,
        bytes_to_verify: &[u8],
        signature: &[u8],
    ) -> Result<bool, SamlError> {
        let verification_key = self.resolve_verification_key(key_id)?;
        crate::sign::verify_data_with_verification_key(
            signing_algorithm,
            verification_key,
            bytes_to_verify,
            signature,
        )
    }

    fn resolve_verification_key(
        &self,
        key_id: Option<&str>,
    ) -> Result<&VerificationKey, SamlError> {
        let resolved_key_id = Self::resolve_key_id(key_id, self.default_signing_key_id.as_deref())?;
        self.verification_keys
            .get(&resolved_key_id)
            .ok_or(SamlError::NoKeyAvailable)
    }

    /// Returns configured encryption key material.
    pub fn get_encryption_key(
        &self,
        key_id: Option<&str>,
    ) -> Result<&EncryptionPublicKey, SamlError> {
        let resolved_key_id =
            Self::resolve_key_id(key_id, self.default_encryption_key_id.as_deref())?;
        self.encryption_keys
            .get(&resolved_key_id)
            .ok_or(SamlError::NoKeyAvailable)
    }

    /// List the keys available for signing (for example, to include in metadata).
    pub fn key_ids(&self) -> Vec<String> {
        self.signing_keys.keys().cloned().collect()
    }
}
