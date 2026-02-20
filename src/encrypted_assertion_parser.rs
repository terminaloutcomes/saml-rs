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
            } => match name.local_name.as_str() {
                "EncryptionMethod" => {
                    for attr in attributes {
                        if attr.name.local_name == "Algorithm" {
                            let algorithm = attr.value;
                            if state.in_encrypted_key {
                                state.key_enc_algorithm = Some(algorithm);
                            } else if state.assertion_encryption_method.is_none() {
                                state.assertion_encryption_method = Some(algorithm);
                            } else {
                                state.content_encryption_method = Some(algorithm);
                            }
                            break;
                        }
                    }
                }
                "EncryptedKey" => {
                    state.in_encrypted_key = true;
                }
                "EncryptedData" => {
                    state.in_encrypted_data = true;
                }
                "CipherValue" => {
                    state.expecting_cipher_value = true;
                }
                _ => {}
            },
            XmlEvent::EndElement { name, .. } => match name.local_name.as_str() {
                "EncryptedAssertion" => {
                    return build_encrypted_assertion(state);
                }
                "EncryptedKey" => {
                    state.in_encrypted_key = false;
                }
                "EncryptedData" => {
                    state.in_encrypted_data = false;
                }
                "CipherValue" => {
                    state.expecting_cipher_value = false;
                }
                _ => {}
            },
            XmlEvent::Characters(text) => {
                if state.expecting_cipher_value && !text.trim().is_empty() {
                    let value = text.trim().to_string();
                    if state.in_encrypted_key {
                        state.key_cipher_value = Some(value);
                    } else if state.in_encrypted_data {
                        state.data_cipher_value = Some(value);
                    }
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
    assertion_encryption_method: Option<String>,
    content_encryption_method: Option<String>,
    key_enc_algorithm: Option<String>,
    key_cipher_value: Option<String>,
    data_cipher_value: Option<String>,
    in_encrypted_key: bool,
    in_encrypted_data: bool,
    expecting_cipher_value: bool,
}

/// Builds EncryptedAssertion from parser state
fn build_encrypted_assertion(state: ParserState) -> Result<EncryptedAssertion, String> {
    let encryption_method = EncryptionMethod {
        algorithm: state
            .assertion_encryption_method
            .clone()
            .ok_or("Missing EncryptionMethod algorithm")?,
    };

    let encrypted_data = match (state.content_encryption_method, state.data_cipher_value) {
        (Some(algorithm), Some(cipher_value)) => Some(EncryptedData {
            content_algorithm: parse_content_encryption_algorithm(&algorithm)?,
            cipher_value,
        }),
        (None, None) => None,
        _ => return Err("Missing EncryptedData fields".to_string()),
    };

    let key_info = match (state.key_enc_algorithm, state.key_cipher_value) {
        (Some(algorithm), Some(encrypted_key)) => Some(EncryptionKeyInfo {
            key_encryption_algorithm: parse_key_encryption_algorithm(&algorithm)?,
            encrypted_key,
            recipient: None,
        }),
        (None, None) => None,
        _ => return Err("Missing EncryptedKey fields".to_string()),
    };

    let mut assertion = EncryptedAssertion::new(encryption_method);
    if let Some(ki) = key_info {
        assertion = assertion.with_key_info(ki);
    }
    if let Some(ed) = encrypted_data {
        assertion = assertion.with_encrypted_data(ed);
    }
    Ok(assertion)
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
