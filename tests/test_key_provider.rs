use saml_rs::key_provider::{EncryptionPublicKey, KeyService};
use saml_rs::sign::{SamlSigningKey, SigningAlgorithm};

#[test]
fn in_memory_key_provider_resolves_defaults_and_named_keys() {
    let signing_key = SamlSigningKey::from(saml_rs::sign::generate_private_key());

    let encryption_key = EncryptionPublicKey::Rsa(rsa::RsaPublicKey::from(
        &saml_rs::sign::generate_private_key(),
    ));

    let provider = KeyService::builder()
        .with_signing_key(&"sig-default", signing_key.clone())
        .with_encryption_key(&"enc-default", encryption_key)
        .default_signing_key_id(&"sig-default")
        .default_encryption_key_id(&"enc-default")
        .build()
        .expect("key service should build");

    let payload = b"default signing payload";
    let signature = provider
        .sign(None, SigningAlgorithm::RsaSha256, payload)
        .expect("default signing key should sign");
    assert!(
        provider
            .verify(None, SigningAlgorithm::RsaSha256, payload, &signature)
            .expect("default key should verify signature"),
        "signature should verify with default key"
    );

    let resolved_encryption = provider
        .get_encryption_key(None)
        .expect("default encryption key should resolve");
    assert!(matches!(resolved_encryption, EncryptionPublicKey::Rsa(_)));

    let named_payload = b"named signing payload";
    let named_signature = provider
        .sign(
            Some("sig-default"),
            SigningAlgorithm::RsaSha256,
            named_payload,
        )
        .expect("named signing key should sign");
    assert!(
        provider
            .verify(
                Some("sig-default"),
                SigningAlgorithm::RsaSha256,
                named_payload,
                &named_signature,
            )
            .expect("named key should verify signature"),
        "signature should verify with named key"
    );

    let named_encryption = provider
        .get_encryption_key(Some("enc-default"))
        .expect("named encryption key should resolve");
    assert!(matches!(named_encryption, EncryptionPublicKey::Rsa(_)));
}

#[test]
fn in_memory_key_provider_reports_missing_defaults_and_ids() {
    let provider = KeyService::builder()
        .build()
        .expect("empty key service should build");

    assert!(
        provider
            .sign(None, SigningAlgorithm::RsaSha256, b"payload")
            .is_err(),
        "missing default signing key should error"
    );
    assert!(
        provider
            .verify(None, SigningAlgorithm::RsaSha256, b"payload", b"sig")
            .is_err(),
        "missing default verification material should error"
    );
    assert!(
        provider.get_encryption_key(None).is_err(),
        "missing default encryption key should error"
    );

    assert!(
        provider
            .sign(Some("unknown"), SigningAlgorithm::RsaSha256, b"payload")
            .is_err(),
        "unknown signing key id should error"
    );
    assert!(
        provider
            .verify(
                Some("unknown"),
                SigningAlgorithm::RsaSha256,
                b"payload",
                b"sig",
            )
            .is_err(),
        "unknown verification key id should error"
    );
    assert!(
        provider.get_encryption_key(Some("unknown")).is_err(),
        "unknown encryption key id should error"
    );
}
