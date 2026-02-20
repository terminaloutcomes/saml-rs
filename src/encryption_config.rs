//!  Configuration for encryption algorithms

use crate::sign::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm};

/// Configuration for encryption algorithms
#[derive(Debug, Copy, Clone)]
pub struct EncryptionConfig {
    /// The content encryption algorithm to use (e.g., AES-256-CBC + HMAC-SHA-512)
    pub content_algorithm: Option<ContentEncryptionAlgorithm>,
    /// The key encryption algorithm to use (e.g., RSA-OAEP-256)
    pub key_encryption_algorithm: Option<KeyEncryptionAlgorithm>,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            content_algorithm: Some(ContentEncryptionAlgorithm::A256CBC_HS512),
            key_encryption_algorithm: Some(KeyEncryptionAlgorithm::RSA_OAEP_256),
        }
    }
}

/// Trait for providing keys for encryption and signing operations
pub trait KeyProvider {
    /// Get the signing key for the given key ID (if any)
    fn get_signing_key(&self, key_id: Option<&str>) -> Option<Vec<u8>>;
    /// Get the verification key for the given key ID (if any)
    fn get_encryption_key(&self, key_id: Option<&str>) -> Option<Vec<u8>>;
    /// Get the decryption key for the given key ID (if any)
    fn get_verification_key(&self, key_id: Option<&str>) -> Option<Vec<u8>>;
    /// Get the decryption key for the given key ID (if any)
    fn get_decryption_key(&self, key_id: Option<&str>) -> Option<Vec<u8>>;
}
