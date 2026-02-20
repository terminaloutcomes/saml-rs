use saml_rs::key_provider::{EncryptionPublicKey, InMemoryKeyProvider, KeyProvider};
use saml_rs::sign::SigningKey;

#[test]
fn in_memory_key_provider_resolves_defaults_and_named_keys() {
    let mut provider = InMemoryKeyProvider::new();

    let signing_key = SigningKey::from(saml_rs::sign::generate_private_key());
    provider.insert_signing_key("sig-default", signing_key.clone());
    provider.set_default_signing_key_id("sig-default");

    let encryption_key = EncryptionPublicKey::Rsa(rsa::RsaPublicKey::from(
        &saml_rs::sign::generate_private_key(),
    ));
    provider.insert_encryption_key("enc-default", encryption_key);
    provider.set_default_encryption_key_id("enc-default");

    let resolved_signing = provider
        .get_signing_key(None)
        .expect("default signing key should resolve");
    assert!(!resolved_signing.is_none());

    let resolved_encryption = provider
        .get_encryption_key(None)
        .expect("default encryption key should resolve");
    assert!(matches!(resolved_encryption, EncryptionPublicKey::Rsa(_)));

    let named_signing = provider
        .get_signing_key(Some("sig-default"))
        .expect("named signing key should resolve");
    assert!(!named_signing.is_none());

    let named_encryption = provider
        .get_encryption_key(Some("enc-default"))
        .expect("named encryption key should resolve");
    assert!(matches!(named_encryption, EncryptionPublicKey::Rsa(_)));
}

#[test]
fn in_memory_key_provider_reports_missing_defaults_and_ids() {
    let provider = InMemoryKeyProvider::new();

    assert!(
        provider.get_signing_key(None).is_err(),
        "missing default signing key should error"
    );
    assert!(
        provider.get_encryption_key(None).is_err(),
        "missing default encryption key should error"
    );

    assert!(
        provider.get_signing_key(Some("unknown")).is_err(),
        "unknown signing key id should error"
    );
    assert!(
        provider.get_encryption_key(Some("unknown")).is_err(),
        "unknown encryption key id should error"
    );
}
