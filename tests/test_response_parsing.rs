use chrono::{DateTime, NaiveDate, Utc};
use saml_rs::assertion::AssertionAttribute;
use saml_rs::key_provider::InMemoryKeyProvider;
use saml_rs::response::{AuthNStatement, ResponseElementsBuilder};
use saml_rs::sign::{
    CanonicalizationMethod, DigestAlgorithm, SigningAlgorithm, SigningKey, generate_private_key,
};

fn build_response_xml(
    sign_message: bool,
) -> (String, std::sync::Arc<SigningKey>, x509_cert::Certificate) {
    let authnstatement = AuthNStatement {
        instant: DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2014, 7, 17)
                .expect("Failed to create NaiveDate for authn_instant in test response parsing")
                .and_hms_opt(1, 1, 48)
                .expect("Failed to create NaiveTime for authn_instant in test response parsing"),
            Utc,
        ),
        session_index: String::from("_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"),
        classref: String::from("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"),
        expiry: None,
    };

    let responseattributes = [
        AssertionAttribute::basic("uid", ["test"].to_vec()),
        AssertionAttribute::basic("mail", ["test@example.com"].to_vec()),
    ]
    .to_vec();

    let signing_key: std::sync::Arc<SigningKey> = SigningKey::from(generate_private_key()).into();
    let signing_cert = saml_rs::cert::gen_self_signed_certificate("idp.example.com")
        .expect("failed to generate self-signed certificate for test response parsing");

    let response = ResponseElementsBuilder::new()
        .issuer("http://idp.example.com/metadata.php")
        .response_id(String::from("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"))
        .issue_instant(DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2014, 7, 17)
                .expect("Failed to create NaiveDate for issue_instant in test response parsing")
                .and_hms_opt(1, 1, 48)
                .expect("Failed to create NaiveTime for issue_instant in test response parsing"),
            Utc,
        ))
        .in_response_to(String::from(
            "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685",
        ))
        .attributes(responseattributes)
        .destination(String::from("http://sp.example.com/demo1/index.php?acs"))
        .authnstatement(authnstatement)
        .assertion_id(String::from("_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"))
        .service_provider(saml_rs::sp::ServiceProvider::test_generic("sp.example.com"))
        .nameid_value("test-user".to_string())
        .assertion_consumer_service(Some(String::from(
            "http://sp.example.com/demo1/index.php?acs",
        )))
        .session_length_seconds(1)
        .status(saml_rs::constants::StatusCode::Success)
        .sign_assertion(false)
        .sign_message(sign_message)
        .signing_key(signing_key.clone())
        .signing_cert(Some(signing_cert.clone()))
        .signing_algorithm(SigningAlgorithm::RsaSha256)
        .digest_algorithm(DigestAlgorithm::Sha256)
        .canonicalization_method(CanonicalizationMethod::ExclusiveCanonical10)
        .build()
        .expect("Failed to build ResponseElements for test response parsing");

    (
        String::from_utf8(response.into()).expect("Failed to convert response to UTF-8 string"),
        signing_key,
        signing_cert,
    )
}

fn build_unsigned_response_xml() -> String {
    build_response_xml(false).0
}

#[test]
fn parse_response_xml_extracts_required_fields() {
    let xml = build_unsigned_response_xml();
    let parsed = saml_rs::response::parse_response_xml(&xml)
        .expect("expected response parser to extract required fields");

    assert_eq!(
        parsed.response_id,
        "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"
    );
    assert_eq!(
        parsed.in_response_to,
        "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
    );
    assert_eq!(
        parsed.destination,
        "http://sp.example.com/demo1/index.php?acs"
    );
    assert_eq!(parsed.issuer, "http://idp.example.com/metadata.php");
    assert_eq!(
        parsed.status_code,
        "urn:oasis:names:tc:SAML:2.0:status:Success"
    );
}

#[test]
fn parse_response_xml_rejects_missing_required_field() {
    let xml = build_unsigned_response_xml().replacen(
        "InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"",
        "",
        1,
    );
    let error = saml_rs::response::parse_response_xml(&xml)
        .expect_err("expected response parser to reject missing InResponseTo");
    assert!(error.to_string().contains("InResponseTo"));
}

#[test]
fn parse_and_verify_response_xml_with_key_provider_roundtrip() {
    let (xml, signing_key, _cert) = build_response_xml(true);
    let mut provider = InMemoryKeyProvider::new();
    provider.insert_signing_key("idp-signing", signing_key.as_ref().clone());
    provider.set_default_signing_key_id("idp-signing");

    let parsed =
        saml_rs::response::parse_and_verify_response_xml_with_key_provider(&xml, &provider, None)
            .expect("expected parse+verify helper to succeed");
    assert_eq!(
        parsed.response_id,
        "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"
    );
}

#[test]
fn parse_and_verify_response_xml_with_key_provider_rejects_tamper() {
    let (xml, signing_key, _cert) = build_response_xml(true);
    let mut provider = InMemoryKeyProvider::new();
    provider.insert_signing_key("idp-signing", signing_key.as_ref().clone());
    provider.set_default_signing_key_id("idp-signing");

    let tampered = xml.replacen("test-user", "evil-user", 1);
    let error = saml_rs::response::parse_and_verify_response_xml_with_key_provider(
        &tampered, &provider, None,
    )
    .expect_err("expected parse+verify helper to reject tampered payload");
    assert!(error.to_string().contains("verification failed"));
}
