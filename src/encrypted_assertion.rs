//! Encrypted Assertion support for SAML
use crate::content_encryption;
use crate::encrypted_assertion_parser;
use crate::error::SamlError;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::Rng;

/// SAML 2.0 EncryptedAssertion as per section 2.3.3.1 of the spec
use crate::sign::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm};
use std::io::Write;
use xml::writer::{EventWriter, XmlEvent};

/// The encryption key information
#[derive(Clone, Debug)]
pub struct EncryptionKeyInfo {
    /// The key encryption algorithm used
    pub key_encryption_algorithm: KeyEncryptionAlgorithm,
    /// The encrypted key value (base64 encoded)
    pub encrypted_key: String,
    /// The recipient's public key identifier
    pub recipient: Option<String>,
}

/// The encrypted data content
#[derive(Clone, Debug)]
pub struct EncryptedData {
    /// The content encryption algorithm
    pub content_algorithm: ContentEncryptionAlgorithm,
    /// The base64-encoded encrypted content
    pub cipher_value: String,
}

/// An EncryptedAssertion element
#[derive(Clone, Debug)]
pub struct EncryptedAssertion {
    /// The encryption method used
    pub encryption_method: EncryptionMethod,
    /// The key information
    pub key_info: Option<EncryptionKeyInfo>,
    /// The encrypted data
    pub encrypted_data: Option<EncryptedData>,
}

/// The encryption method element
#[derive(Clone, Debug)]
pub struct EncryptionMethod {
    /// The algorithm URI
    pub algorithm: String,
}

impl EncryptedAssertion {
    /// Create a new EncryptedAssertion
    pub fn new(encryption_method: EncryptionMethod) -> Self {
        EncryptedAssertion {
            encryption_method,
            key_info: None,
            encrypted_data: None,
        }
    }

    /// Set the key info
    pub fn with_key_info(mut self, key_info: EncryptionKeyInfo) -> Self {
        self.key_info = Some(key_info);
        self
    }

    /// Set the encrypted data
    pub fn with_encrypted_data(mut self, encrypted_data: EncryptedData) -> Self {
        self.encrypted_data = Some(encrypted_data);
        self
    }

    /// Serialize to XML bytes
    pub fn to_xml_bytes(&self) -> Result<Vec<u8>, SamlError> {
        let mut buf = Vec::new();
        let mut writer: EventWriter<&mut Vec<u8>> = EventWriter::new(&mut buf);

        // Start EncryptedAssertion element
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptedAssertion"))
                    .attr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
                    .attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"),
            )
            .map_err(|_| SamlError::XmlParsing("Failed to write start element".to_string()))?;

        // Write EncryptionMethod
        self.write_encryption_method(&mut writer)?;

        // Write KeyInfo if present
        // TODO work out what happens here
        if let Some(ref key_info) = self.key_info {
            self.write_key_info(key_info, &mut writer)?;
        }

        // Write EncryptedData if present
        if let Some(ref encrypted_data) = self.encrypted_data {
            self.write_encrypted_data(encrypted_data, &mut writer)?;
        }

        // End EncryptedAssertion element
        writer.write(XmlEvent::end_element()).map_err(|err| {
            SamlError::XmlEncoding(format!("Failed to write end element: {}", err))
        })?;

        Ok(buf)
    }

    fn write_encryption_method<W: Write>(
        &self,
        writer: &mut EventWriter<W>,
    ) -> Result<(), SamlError> {
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", &self.encryption_method.algorithm),
            )
            .map_err(|_| {
                SamlError::XmlEncoding("Failed to write EncryptionMethod start".to_string())
            })?;

        writer.write(XmlEvent::end_element()).map_err(|_| {
            SamlError::XmlEncoding("Failed to write EncryptionMethod end".to_string())
        })?;
        Ok(())
    }

    fn write_key_info<W: Write>(
        &self,
        key_info: &EncryptionKeyInfo,
        writer: &mut EventWriter<W>,
    ) -> Result<(), SamlError> {
        writer
            .write(
                XmlEvent::start_element(("ds", "KeyInfo"))
                    .attr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"),
            )
            .map_err(|_| SamlError::XmlEncoding("Failed to write KeyInfo start".to_string()))?;

        // Write EncryptedKey element
        writer
            .write(XmlEvent::start_element(("xenc", "EncryptedKey")))
            .map_err(|_| {
                SamlError::XmlEncoding("Failed to write EncryptedKey start".to_string())
            })?;

        // Write EncryptionMethod
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", key_info.key_encryption_algorithm.as_uri()),
            )
            .map_err(|_| {
                SamlError::XmlEncoding("Failed to write Key EncryptionMethod start".to_string())
            })?;

        writer.write(XmlEvent::end_element()).map_err(|_| {
            SamlError::XmlEncoding("Failed to write Key EncryptionMethod end".to_string())
        })?;

        // Write CipherData
        writer
            .write(XmlEvent::start_element(("xenc", "CipherData")))
            .map_err(|_| SamlError::XmlEncoding("Failed to write CipherData start".to_string()))?;

        writer
            .write(XmlEvent::start_element(("xenc", "CipherValue")))
            .map_err(|_| SamlError::XmlEncoding("Failed to write CipherValue start".to_string()))?;

        writer
            .write(XmlEvent::characters(&key_info.encrypted_key))
            .map_err(|_| {
                SamlError::XmlEncoding("Failed to write CipherValue content".to_string())
            })?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| SamlError::XmlEncoding("Failed to write CipherValue end".to_string()))?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| SamlError::XmlEncoding("Failed to write CipherData end".to_string()))?;

        // End EncryptedKey
        writer
            .write(XmlEvent::end_element())
            .map_err(|_| SamlError::XmlEncoding("Failed to write EncryptedKey end".to_string()))?;

        // End KeyInfo
        writer
            .write(XmlEvent::end_element())
            .map_err(|_| SamlError::XmlEncoding("Failed to write KeyInfo end".to_string()))?;
        Ok(())
    }

    fn write_encrypted_data<W: Write>(
        &self,
        encrypted_data: &EncryptedData,
        writer: &mut EventWriter<W>,
    ) -> Result<(), SamlError> {
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptedData"))
                    .attr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#"),
            )
            .map_err(|_| {
                SamlError::XmlEncoding("Failed to write EncryptedData start".to_string())
            })?;

        // Write EncryptionMethod
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", encrypted_data.content_algorithm.as_uri()),
            )
            .map_err(|_| {
                SamlError::XmlEncoding("Failed to write Data EncryptionMethod start".to_string())
            })?;

        writer.write(XmlEvent::end_element()).map_err(|_| {
            SamlError::XmlEncoding("Failed to write Data EncryptionMethod end".to_string())
        })?;

        // Write CipherData
        writer
            .write(XmlEvent::start_element(("xenc", "CipherData")))
            .map_err(|_| SamlError::XmlEncoding("Failed to write CipherData start".to_string()))?;

        writer
            .write(XmlEvent::start_element(("xenc", "CipherValue")))
            .map_err(|_| SamlError::XmlEncoding("Failed to write CipherValue start".to_string()))?;

        writer
            .write(XmlEvent::characters(&encrypted_data.cipher_value))
            .map_err(|_| {
                SamlError::XmlEncoding("Failed to write CipherValue content".to_string())
            })?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| SamlError::XmlEncoding("Failed to write CipherValue end".to_string()))?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| SamlError::XmlEncoding("Failed to write CipherData end".to_string()))?;

        // End EncryptedData
        writer
            .write(XmlEvent::end_element())
            .map_err(|_| SamlError::XmlEncoding("Failed to write EncryptedData end".to_string()))?;
        Ok(())
    }
}

impl Default for EncryptedAssertion {
    fn default() -> Self {
        EncryptedAssertion::new(EncryptionMethod {
            algorithm: KeyEncryptionAlgorithm::RSA_OAEP_256.as_uri().to_string(),
        })
        .with_key_info(EncryptionKeyInfo {
            key_encryption_algorithm: KeyEncryptionAlgorithm::RSA_OAEP_256,
            encrypted_key: "placeholder".to_string(),
            recipient: None,
        })
        .with_encrypted_data(EncryptedData {
            content_algorithm: ContentEncryptionAlgorithm::A256CBC_HS512,
            cipher_value: "placeholder".to_string(),
        })
    }
}

/// Encrypts an assertion and creates an EncryptedAssertion structure
///
/// Steps:
/// 1. Generate random 32-byte content encryption key (AES-256)
/// 2. Generate random 16-byte IV
/// 3. Encrypt assertion with AES-256-CBC-HMAC-SHA-512
/// 4. Encrypt content key with RSA-OAEP
/// 5. Build EncryptedAssertion with encrypted data and key info
pub fn encrypt_assertion(
    assertion_bytes: &[u8],
    public_key: &rsa::RsaPublicKey,
    key_enc_algo: KeyEncryptionAlgorithm,
    content_enc_algo: ContentEncryptionAlgorithm,
) -> Result<EncryptedAssertion, SamlError> {
    if key_enc_algo == KeyEncryptionAlgorithm::RSA_OAEP
        && !crate::security::weak_algorithms_allowed()
    {
        return Err(SamlError::WeakAlgorithm(
            "RSA-OAEP with SHA-1 is disabled by security policy".to_string(),
        ));
    }

    let (key, encrypted_content): (Vec<u8>, Vec<u8>) = match content_enc_algo {
        ContentEncryptionAlgorithm::A128CBC_HS256 => {
            let mut key = vec![0u8; 32];
            let mut rng = rand::rng();
            rng.fill_bytes(&mut key);
            let iv = content_encryption::generate_iv();
            let encrypted = content_encryption::encrypt_a128cbs_hs256(assertion_bytes, &key, &iv)?;
            (key, encrypted)
        }
        ContentEncryptionAlgorithm::A256CBC_HS512 => {
            let mut key = vec![0u8; 64];
            let mut rng = rand::rng();
            rng.fill_bytes(&mut key);
            let iv = content_encryption::generate_iv();
            let encrypted = content_encryption::encrypt_a256cbs_hs512(assertion_bytes, &key, &iv)?;
            (key, encrypted)
        }
        ContentEncryptionAlgorithm::A128GCM => {
            let mut key = vec![0u8; 16];
            let mut rng = rand::rng();
            rng.fill_bytes(&mut key);
            let nonce = content_encryption::generate_gcm_nonce();
            let encrypted = content_encryption::encrypt_a128gcm(assertion_bytes, &key, &nonce)?;
            (key, encrypted)
        }
        ContentEncryptionAlgorithm::A256GCM => {
            let mut key = vec![0u8; 32];
            let mut rng = rand::rng();
            rng.fill_bytes(&mut key);
            let nonce = content_encryption::generate_gcm_nonce();
            let encrypted = content_encryption::encrypt_a256gcm(assertion_bytes, &key, &nonce)?;
            (key, encrypted)
        }
    };

    // Base64 encode the encrypted content
    let cipher_value = STANDARD.encode(&encrypted_content);

    // Encrypt the content key using RSA-OAEP
    let encrypted_key = key_enc_algo.encrypt_rsa(key.as_slice(), public_key)?;

    // Base64 encode the encrypted key
    let encrypted_key_b64 = STANDARD.encode(&encrypted_key);

    // Create the EncryptedData structure
    let encrypted_data = EncryptedData {
        content_algorithm: content_enc_algo,
        cipher_value,
    };

    // Create the EncryptionKeyInfo structure
    let key_info = EncryptionKeyInfo {
        key_encryption_algorithm: key_enc_algo,
        encrypted_key: encrypted_key_b64,
        recipient: None,
    };

    // Create the EncryptionMethod
    let encryption_method = EncryptionMethod {
        algorithm: key_enc_algo.as_uri().to_string(),
    };

    // Build and return EncryptedAssertion
    Ok(EncryptedAssertion::new(encryption_method)
        .with_key_info(key_info)
        .with_encrypted_data(encrypted_data))
}

/// Decrypts an encrypted assertion
///
/// Steps:
/// 1. Parse EncryptedAssertion from XML
/// 2. Extract encrypted content and encrypted key
/// 3. Decrypt the encrypted key using RSA-OAEP
/// 4. Extract IV and ciphertext from encrypted content
/// 5. Decrypt the assertion using AES-256-CBC-HMAC-SHA-512
/// 6. Return the decrypted assertion bytes
pub fn decrypt_assertion(
    encrypted_assertion_xml: &[u8],
    private_key: &rsa::RsaPrivateKey,
) -> Result<Vec<u8>, SamlError> {
    // Parse the EncryptedAssertion
    let encrypted_assertion =
        encrypted_assertion_parser::parse_encrypted_assertion(encrypted_assertion_xml)?;

    // Get the encrypted data
    let encrypted_data = encrypted_assertion.encrypted_data.ok_or(SamlError::Other(
        "No EncryptedData found in assertion".to_string(),
    ))?;

    let encrypted_key = encrypted_assertion
        .key_info
        .as_ref()
        .ok_or(SamlError::Key("No KeyInfo found in assertion".to_string()))?
        .encrypted_key
        .clone();

    let key_enc_algo = encrypted_assertion
        .key_info
        .ok_or(SamlError::other("No KeyInfo found in assertion"))?
        .key_encryption_algorithm;

    // Decode the encrypted content
    let encrypted_content_bytes = STANDARD.decode(&encrypted_data.cipher_value)?;

    let encrypted_key_bytes = STANDARD.decode(encrypted_key)?;
    let content_key = key_enc_algo.decrypt_rsa(&encrypted_key_bytes, private_key)?;

    match encrypted_data.content_algorithm {
        ContentEncryptionAlgorithm::A128CBC_HS256 => {
            if encrypted_content_bytes.len() < 16 + 32 {
                return Err(SamlError::InvalidInputLength(
                    "Encrypted content too short to contain IV and HMAC".to_string(),
                ));
            }
            let iv = &encrypted_content_bytes[..16];
            let payload = &encrypted_content_bytes[16..];
            content_encryption::decrypt_a128cbs_hs256(payload, &content_key, iv)
        }
        ContentEncryptionAlgorithm::A256CBC_HS512 => {
            if encrypted_content_bytes.len() < 16 + 64 {
                return Err(SamlError::InvalidInputLength(
                    "Encrypted content too short to contain IV and HMAC".to_string(),
                ));
            }
            let iv = &encrypted_content_bytes[..16];
            let payload = &encrypted_content_bytes[16..];
            content_encryption::decrypt_a256cbs_hs512(payload, &content_key, iv)
        }
        ContentEncryptionAlgorithm::A128GCM => {
            if encrypted_content_bytes.len() < 12 + 16 {
                return Err(SamlError::InvalidInputLength(
                    "Encrypted content too short to contain GCM nonce+tag".to_string(),
                ));
            }
            let nonce = &encrypted_content_bytes[..12];
            let payload = &encrypted_content_bytes[12..];
            content_encryption::decrypt_a128gcm(payload, &content_key, nonce)
        }
        ContentEncryptionAlgorithm::A256GCM => {
            if encrypted_content_bytes.len() < 12 + 16 {
                return Err(SamlError::InvalidInputLength(
                    "Encrypted content too short to contain GCM nonce+tag".to_string(),
                ));
            }
            let nonce = &encrypted_content_bytes[..12];
            let payload = &encrypted_content_bytes[12..];
            content_encryption::decrypt_a256gcm(payload, &content_key, nonce)
        }
    }
}
