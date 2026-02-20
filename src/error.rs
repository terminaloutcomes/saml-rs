//! This module defines the error types used in the SAML library.

use std::{str::Utf8Error, string::FromUtf8Error};

use aes::cipher::block_padding::UnpadError;
use hmac::digest::MacError;

use crate::security::SecurityError;

#[allow(missing_docs)]
/// Custom error type for SAML operations
#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    #[error("Invalid length for key")]
    InvalidKeyLength(String),

    #[error("Invalid length for initialization vector, expected {0} bytes")]
    InvalidIvLength(usize),

    #[error("Invalid length for input data: {0}")]
    InvalidInputLength(String),

    #[error("AES-CBC encryption error: {0}")]
    AesCbcEncryption(String),

    #[error("AES-CBS encryption error: {0}")]
    AesCbsEncryptionError(String),

    #[error("AES-GCM encryption error: {0}")]
    AesGcmEncryptionError(String),

    #[error("Weak algorithm: {0}")]
    WeakAlgorithm(String),

    #[error("RSA encryption error: {0}")]
    RsaEncryption(#[from] rsa::Error),

    #[error("No encryption key available")]
    NoKeyAvailable,

    #[error("No encryption certificate available")]
    NoCertAvailable,

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Decoding error: {0}")]
    Decoding(String),

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Key error: {0}")]
    Key(String),

    #[error("Other error: {0}")]
    Other(String),

    #[error("XML parsing error: {0}")]
    XmlParsing(String),

    #[error("XML encoding error: {0}")]
    XmlEncoding(String),

    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Security error: {0}")]
    Security(SecurityError),
}

impl SamlError {
    /// Generic message for errors that don't fit into other categories
    pub fn other(message: impl Into<String>) -> Self {
        SamlError::Other(message.into())
    }
}

impl From<hmac::digest::InvalidLength> for SamlError {
    fn from(_: hmac::digest::InvalidLength) -> Self {
        SamlError::InvalidKeyLength("Invalid HMAC key length".to_string())
    }
}

impl From<aes::cipher::inout::PadError> for SamlError {
    fn from(e: aes::cipher::inout::PadError) -> Self {
        SamlError::AesCbcEncryption(e.to_string())
    }
}

impl From<FromUtf8Error> for SamlError {
    fn from(e: FromUtf8Error) -> Self {
        SamlError::Encoding(format!("UTF-8 conversion error: {}", e))
    }
}

impl From<xml_c14n::CanonicalizationErrorCode> for SamlError {
    fn from(e: xml_c14n::CanonicalizationErrorCode) -> Self {
        SamlError::Encoding(format!("XML canonicalization error: {}", e))
    }
}

impl From<x509_cert::spki::Error> for SamlError {
    fn from(e: x509_cert::spki::Error) -> Self {
        SamlError::Key(format!("SPKI handling error: {}", e))
    }
}

impl From<MacError> for SamlError {
    fn from(err: MacError) -> Self {
        SamlError::Other(format!("HMAC digest failed: {err}"))
    }
}

impl From<UnpadError> for SamlError {
    fn from(err: UnpadError) -> Self {
        SamlError::AesCbcEncryption(format!("Padding error: {err}"))
    }
}

impl From<SecurityError> for SamlError {
    fn from(err: SecurityError) -> Self {
        SamlError::Security(err)
    }
}

impl From<xml::reader::Error> for SamlError {
    fn from(err: xml::reader::Error) -> Self {
        SamlError::XmlParsing(format!("XML parsing error: {err}"))
    }
}

impl From<base64::DecodeError> for SamlError {
    fn from(err: base64::DecodeError) -> Self {
        SamlError::Decoding(format!("Base64 decoding error: {err}"))
    }
}

impl From<x509_cert::der::Error> for SamlError {
    fn from(err: x509_cert::der::Error) -> Self {
        SamlError::Certificate(format!("DER Certificate parsing error: {err}"))
    }
}

impl From<Utf8Error> for SamlError {
    fn from(err: Utf8Error) -> Self {
        SamlError::Encoding(format!("UTF-8 decoding error: {err}"))
    }
}
