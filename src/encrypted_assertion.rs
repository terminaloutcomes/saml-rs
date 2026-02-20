//! Encrypted Assertion support for SAML
//!
//! SAML 2.0 EncryptedAssertion as per section 2.3.3.1 of the spec

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
    pub fn to_xml_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer: EventWriter<&mut Vec<u8>> = EventWriter::new(&mut buf);

        // Start EncryptedAssertion element
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptedAssertion"))
                    .attr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
                    .attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"),
            )
            .expect("Failed to write start element");

        // Write EncryptionMethod
        self.write_encryption_method(&mut writer);

        // Write KeyInfo if present
        if let Some(ref key_info) = self.key_info {
            self.write_key_info(key_info, &mut writer);
        }

        // Write EncryptedData if present
        if let Some(ref encrypted_data) = self.encrypted_data {
            self.write_encrypted_data(encrypted_data, &mut writer);
        }

        // End EncryptedAssertion element
        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write end element");

        buf
    }

    fn write_encryption_method<W: Write>(&self, writer: &mut EventWriter<W>) {
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", &self.encryption_method.algorithm),
            )
            .expect("Failed to write EncryptionMethod start");

        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write EncryptionMethod end");
    }

    fn write_key_info<W: Write>(&self, key_info: &EncryptionKeyInfo, writer: &mut EventWriter<W>) {
        writer
            .write(
                XmlEvent::start_element(("ds", "KeyInfo"))
                    .attr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"),
            )
            .expect("Failed to write KeyInfo start");

        // Write EncryptedKey element
        writer
            .write(XmlEvent::start_element(("xenc", "EncryptedKey")))
            .expect("Failed to write EncryptedKey start");

        // Write EncryptionMethod
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", key_info.key_encryption_algorithm.as_uri()),
            )
            .expect("Failed to write Key EncryptionMethod start");

        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write Key EncryptionMethod end");

        // Write CipherData
        writer
            .write(XmlEvent::start_element(("xenc", "CipherData")))
            .expect("Failed to write CipherData start");

        writer
            .write(XmlEvent::start_element(("xenc", "CipherValue")))
            .expect("Failed to write CipherValue start");

        writer
            .write(XmlEvent::characters(&key_info.encrypted_key))
            .expect("Failed to write CipherValue content");

        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write CipherValue end");

        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write CipherData end");

        // End EncryptedKey
        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write EncryptedKey end");

        // End KeyInfo
        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write KeyInfo end");
    }

    fn write_encrypted_data<W: Write>(
        &self,
        encrypted_data: &EncryptedData,
        writer: &mut EventWriter<W>,
    ) {
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptedData"))
                    .attr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#"),
            )
            .expect("Failed to write EncryptedData start");

        // Write EncryptionMethod
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", encrypted_data.content_algorithm.as_uri()),
            )
            .expect("Failed to write Data EncryptionMethod start");

        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write Data EncryptionMethod end");

        // Write CipherData
        writer
            .write(XmlEvent::start_element(("xenc", "CipherData")))
            .expect("Failed to write CipherData start");

        writer
            .write(XmlEvent::start_element(("xenc", "CipherValue")))
            .expect("Failed to write CipherValue start");

        writer
            .write(XmlEvent::characters(&encrypted_data.cipher_value))
            .expect("Failed to write CipherValue content");

        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write CipherValue end");

        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write CipherData end");

        // End EncryptedData
        writer
            .write(XmlEvent::end_element())
            .expect("Failed to write EncryptedData end");
    }
}

impl Default for EncryptedAssertion {
    fn default() -> Self {
        EncryptedAssertion::new(EncryptionMethod {
            algorithm: KeyEncryptionAlgorithm::RSA_OAEP_256.as_uri().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_assertion_basic() {
        let assertion = EncryptedAssertion::default();
        let xml = assertion.to_xml_bytes();
        let xml_str = String::from_utf8_lossy(&xml);

        assert!(xml_str.contains("EncryptedAssertion"));
        assert!(xml_str.contains("rsa-oaep"));
    }

    #[test]
    fn test_encrypted_assertion_with_key_info() {
        let key_info = EncryptionKeyInfo {
            key_encryption_algorithm: KeyEncryptionAlgorithm::RSA_OAEP_256,
            encrypted_key: "base64encryptedkeydata".to_string(),
            recipient: Some("recipient@example.com".to_string()),
        };

        let assertion = EncryptedAssertion::default().with_key_info(key_info);

        let xml = assertion.to_xml_bytes();
        let xml_str = String::from_utf8_lossy(&xml);

        assert!(xml_str.contains("EncryptedKey"));
        assert!(xml_str.contains("base64encryptedkeydata"));
    }
}
