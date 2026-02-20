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
    pub fn to_xml_bytes(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        let mut writer: EventWriter<&mut Vec<u8>> = EventWriter::new(&mut buf);

        // Start EncryptedAssertion element
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptedAssertion"))
                    .attr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
                    .attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"),
            )
            .map_err(|_| "Failed to write start element".to_string())?;

        // Write EncryptionMethod
        self.write_encryption_method(&mut writer)?;

        // Write KeyInfo if present
        if let Some(ref key_info) = self.key_info {
            self.write_key_info(key_info, &mut writer)?;
        }

        // Write EncryptedData if present
        if let Some(ref encrypted_data) = self.encrypted_data {
            self.write_encrypted_data(encrypted_data, &mut writer)?;
        }

        // End EncryptedAssertion element
        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write end element".to_string())?;

        Ok(buf)
    }

    fn write_encryption_method<W: Write>(&self, writer: &mut EventWriter<W>) -> Result<(), String> {
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", &self.encryption_method.algorithm),
            )
            .map_err(|_| "Failed to write EncryptionMethod start".to_string())?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write EncryptionMethod end".to_string())?;
        Ok(())
    }

    fn write_key_info<W: Write>(
        &self,
        key_info: &EncryptionKeyInfo,
        writer: &mut EventWriter<W>,
    ) -> Result<(), String> {
        writer
            .write(
                XmlEvent::start_element(("ds", "KeyInfo"))
                    .attr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#"),
            )
            .map_err(|_| "Failed to write KeyInfo start".to_string())?;

        // Write EncryptedKey element
        writer
            .write(XmlEvent::start_element(("xenc", "EncryptedKey")))
            .map_err(|_| "Failed to write EncryptedKey start".to_string())?;

        // Write EncryptionMethod
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", key_info.key_encryption_algorithm.as_uri()),
            )
            .map_err(|_| "Failed to write Key EncryptionMethod start".to_string())?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write Key EncryptionMethod end".to_string())?;

        // Write CipherData
        writer
            .write(XmlEvent::start_element(("xenc", "CipherData")))
            .map_err(|_| "Failed to write CipherData start".to_string())?;

        writer
            .write(XmlEvent::start_element(("xenc", "CipherValue")))
            .map_err(|_| "Failed to write CipherValue start".to_string())?;

        writer
            .write(XmlEvent::characters(&key_info.encrypted_key))
            .map_err(|_| "Failed to write CipherValue content".to_string())?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write CipherValue end".to_string())?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write CipherData end".to_string())?;

        // End EncryptedKey
        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write EncryptedKey end".to_string())?;

        // End KeyInfo
        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write KeyInfo end".to_string())?;
        Ok(())
    }

    fn write_encrypted_data<W: Write>(
        &self,
        encrypted_data: &EncryptedData,
        writer: &mut EventWriter<W>,
    ) -> Result<(), String> {
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptedData"))
                    .attr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#"),
            )
            .map_err(|_| "Failed to write EncryptedData start".to_string())?;

        // Write EncryptionMethod
        writer
            .write(
                XmlEvent::start_element(("xenc", "EncryptionMethod"))
                    .attr("Algorithm", encrypted_data.content_algorithm.as_uri()),
            )
            .map_err(|_| "Failed to write Data EncryptionMethod start".to_string())?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write Data EncryptionMethod end".to_string())?;

        // Write CipherData
        writer
            .write(XmlEvent::start_element(("xenc", "CipherData")))
            .map_err(|_| "Failed to write CipherData start".to_string())?;

        writer
            .write(XmlEvent::start_element(("xenc", "CipherValue")))
            .map_err(|_| "Failed to write CipherValue start".to_string())?;

        writer
            .write(XmlEvent::characters(&encrypted_data.cipher_value))
            .map_err(|_| "Failed to write CipherValue content".to_string())?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write CipherValue end".to_string())?;

        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write CipherData end".to_string())?;

        // End EncryptedData
        writer
            .write(XmlEvent::end_element())
            .map_err(|_| "Failed to write EncryptedData end".to_string())?;
        Ok(())
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
        let xml = assertion.to_xml_bytes().expect("Failed to convert to XML");
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

        let xml = assertion.to_xml_bytes().expect("Failed to convert to XML");
        let xml_str = String::from_utf8_lossy(&xml);

        assert!(xml_str.contains("EncryptedKey"));
        assert!(xml_str.contains("base64encryptedkeydata"));
    }
}
