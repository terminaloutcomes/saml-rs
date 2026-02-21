use aes_gcm::aead::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use saml_rs::{
    content_encryption,
    encrypted_assertion::*,
    encrypted_assertion_parser::parse_encrypted_assertion,
    sign::{ContentEncryptionAlgorithm, KeyEncryptionAlgorithm},
};

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

#[test]
fn test_encrypt_decrypt_roundtrip() {
    // Generate RSA key pair using cryptographically secure RNG
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);

    // Create a simple SAML assertion
    let original_assertion = r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="test-id" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">test@example.com</saml:NameID>
            </saml:Subject>
        </saml:Assertion>"#;

    // Encrypt the assertion
    let encrypted_assertion = encrypt_assertion(
        original_assertion.as_bytes(),
        &public_key,
        KeyEncryptionAlgorithm::RSA_OAEP_256,
        ContentEncryptionAlgorithm::A256CBC_HS512,
    )
    .expect("Failed to encrypt assertion");

    // Verify encryption created structure
    let xml = encrypted_assertion
        .to_xml_bytes()
        .expect("Failed to convert to XML");
    let xml_str = String::from_utf8_lossy(&xml);
    assert!(xml_str.contains("EncryptedAssertion"));
    assert!(xml_str.contains("EncryptedData"));
    assert!(xml_str.contains("EncryptedKey"));

    // Decrypt the assertion
    let decrypted_assertion =
        decrypt_assertion(&xml, &private_key).expect("Failed to decrypt assertion");

    // Verify the decrypted assertion matches the original
    let decrypted_str = String::from_utf8_lossy(&decrypted_assertion);
    assert!(decrypted_str.contains("saml:Assertion"));
    assert!(decrypted_str.contains("test@example.com"));
}

#[test]
fn test_encrypted_assertion_canonicalization() {
    let assertion = EncryptedAssertion::default();
    let xml = assertion.to_xml_bytes().expect("Failed to convert to XML");

    // Verify XML can be parsed and serialized consistently
    let parsed = parse_encrypted_assertion(&xml).expect("Failed to parse encrypted assertion");

    // Re-serialize and verify structure is preserved
    let serialized = parsed.to_xml_bytes().expect("Failed to re-serialize");
    assert_eq!(xml.len(), serialized.len());
}

#[test]
fn test_parse_encrypted_assertion_rejects_dtd_payloads() {
    let xml = br#"<?xml version="1.0"?>
<!DOCTYPE x [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<xenc:EncryptedAssertion xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p#sha256"/>
</xenc:EncryptedAssertion>"#;

    let error = parse_encrypted_assertion(xml)
        .expect_err("expected parser preflight to reject DTD declarations");
    assert!(error.to_string().to_lowercase().contains("doctype"));
}

#[test]
fn test_a256cbc_hs512_rejects_tag_tampering() {
    let key = [7u8; 64];
    let iv = [9u8; 16];
    let plaintext = b"saml-cbc-hmac-payload";

    let mut packed = content_encryption::encrypt_a256cbs_hs512(plaintext, &key, &iv)
        .expect("encryption should succeed");

    let tag_start = packed.len() - 32;
    packed[tag_start] ^= 0x01;

    let payload_without_iv = &packed[16..];
    let result = content_encryption::decrypt_a256cbs_hs512(payload_without_iv, &key, &iv);
    assert!(result.is_err(), "tampered tag must be rejected");
}
