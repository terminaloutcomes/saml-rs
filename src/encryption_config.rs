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

// Key management is provided centrally by `crate::key_provider::KeyService`.
