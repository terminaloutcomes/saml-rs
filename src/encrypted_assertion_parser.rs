//! XML parsing for EncryptedAssertion elements
//!
//! Provides deserialization of xenc:EncryptedAssertion XML structures

use crate::encrypted_assertion::{
    EncryptedAssertion, EncryptedData, EncryptionKeyInfo, EncryptionMethod,
};
use crate::sign::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm};
use std::io::Cursor;
use xml::reader::{EventReader, XmlEvent};

/// Parses an EncryptedAssertion from XML bytes
pub fn parse_encrypted_assertion(xml_bytes: &[u8]) -> Result<EncryptedAssertion, String> {
    let cursor = Cursor::new(xml_bytes);
    let reader = EventReader::new(cursor);

    let mut state = ParserState::default();

    for event in reader {
        let event = event.map_err(|e| format!("XML parse error: {}", e))?;

        match event {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                match name.local_name.as_str() {
                    "EncryptedAssertion" => {
                        // Start of EncryptedAssertion - ensure EncryptionMethod is captured
                        if state.encryption_method.is_none() {
                            for attr in attributes {
                                if attr.name.local_name == "xmlns:xenc"
                                    && attr.value == "http://www.w3.org/2001/04/xmlenc#"
                                {
                                    state.xenc_ns = Some(attr.value.clone());
                                    break;
                                }
                            }
                        }
                    }
                    "EncryptionMethod" => {
                        if state.encryption_method.is_none() {
                            for attr in attributes {
                                if attr.name.local_name == "Algorithm" {
                                    state.encryption_method = Some(attr.value.clone());
                                    break;
                                }
                            }
                        }
                    }
                    "KeyInfo" => {
                        for attr in attributes {
                            if attr.name.local_name == "xmlns:ds"
                                && attr.value == "http://www.w3.org/2000/09/xmldsig#"
                            {
                                state.ds_ns = Some(attr.value.clone());
                                break;
                            }
                        }
                    }
                    "EncryptedKey" => {
                        state.in_encrypted_key = true;
                    }
                    "CipherValue" => {
                        state.expecting_cipher_value = true;
                    }
                    _ => {}
                }
            }
            XmlEvent::EndElement { name, .. } => match name.local_name.as_str() {
                "EncryptedAssertion" => {
                    return build_encrypted_assertion(state);
                }
                "EncryptedKey" => {
                    state.in_encrypted_key = false;
                }
                "CipherValue" => {
                    state.expecting_cipher_value = false;
                }
                _ => {}
            },
            XmlEvent::Characters(text) => {
                if state.expecting_cipher_value && !text.trim().is_empty() {
                    state.cipher_value = Some(text.trim().to_string());
                    state.expecting_cipher_value = false;
                }
            }
            _ => {}
        }
    }

    Err("Failed to parse EncryptedAssertion: incomplete XML structure".to_string())
}

/// Internal parser state
#[derive(Debug, Default)]
struct ParserState {
    encryption_method: Option<String>,
    key_enc_algorithm: Option<String>,
    cipher_value: Option<String>,
    xenc_ns: Option<String>,
    ds_ns: Option<String>,
    in_encrypted_key: bool,
    expecting_cipher_value: bool,
}

/// Builds EncryptedAssertion from parser state
fn build_encrypted_assertion(state: ParserState) -> Result<EncryptedAssertion, String> {
    let encryption_method = EncryptionMethod {
        algorithm: state
            .encryption_method
            .clone()
            .ok_or("Missing EncryptionMethod algorithm")?,
    };

    let encrypted_data = EncryptedData {
        content_algorithm: parse_content_encryption_algorithm(
            state
                .encryption_method
                .as_deref()
                .ok_or("Missing algorithm")?,
        )?,
        cipher_value: state.cipher_value.clone().ok_or("Missing CipherValue")?,
    };

    let key_info = if state.in_encrypted_key {
        let key_enc = EncryptionKeyInfo {
            key_encryption_algorithm: parse_key_encryption_algorithm(
                state
                    .key_enc_algorithm
                    .as_deref()
                    .ok_or("Missing key encryption algorithm")?,
            )?,
            encrypted_key: state.cipher_value.ok_or("Missing encrypted key data")?,
            recipient: None,
        };
        Some(key_enc)
    } else {
        None
    };

    let mut assertion = EncryptedAssertion::new(encryption_method);
    if let Some(ki) = key_info {
        assertion = assertion.with_key_info(ki);
    }
    Ok(assertion.with_encrypted_data(encrypted_data))
}

/// Parses content encryption algorithm URI to enum
fn parse_content_encryption_algorithm(uri: &str) -> Result<ContentEncryptionAlgorithm, String> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => {
            Ok(ContentEncryptionAlgorithm::A128CBC_HS256)
        }
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => {
            Ok(ContentEncryptionAlgorithm::A256CBC_HS512)
        }
        "http://www.w3.org/2001/04/xmlenc#aes128-gcm" => Ok(ContentEncryptionAlgorithm::A128GCM),
        "http://www.w3.org/2001/04/xmlenc#aes256-gcm" => Ok(ContentEncryptionAlgorithm::A256GCM),
        _ => Err(format!("Unsupported content encryption algorithm: {}", uri)),
    }
}

/// Parses key encryption algorithm URI to enum
fn parse_key_encryption_algorithm(uri: &str) -> Result<KeyEncryptionAlgorithm, String> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" => Ok(KeyEncryptionAlgorithm::RSA_OAEP),
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p#sha256" => {
            Ok(KeyEncryptionAlgorithm::RSA_OAEP_256)
        }
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p#sha384" => {
            Ok(KeyEncryptionAlgorithm::RSA_OAEP_384)
        }
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p#sha512" => {
            Ok(KeyEncryptionAlgorithm::RSA_OAEP_512)
        }
        _ => Err(format!("Unsupported key encryption algorithm: {}", uri)),
    }
}
