use chrono::{DateTime, NaiveDate, Utc};
use saml_rs::assertion::AssertionAttribute;
use saml_rs::key_provider::InMemoryKeyProvider;
use saml_rs::response::{AuthNStatement, ResponseElementsBuilder};
use saml_rs::sign::{
    CanonicalizationMethod, DigestAlgorithm, SigningAlgorithm, SigningKey, generate_private_key,
};

fn build_response_with_cert(
    sign_assertion: bool,
    sign_message: bool,
    canonicalization_method: CanonicalizationMethod,
) -> (String, std::sync::Arc<SigningKey>, x509_cert::Certificate) {
    let signing_cert = saml_rs::cert::gen_self_signed_certificate("idp.example.com")
        .expect("failed to generate self-signed certificate for test response");
    let signing_key: std::sync::Arc<SigningKey> = SigningKey::from(generate_private_key()).into();

    let authnstatement = AuthNStatement {
        instant: DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2014, 7, 17)
                .expect("Failed to create NaiveDate for authn_instant in test_full_response_something_something")
                .and_hms_opt(1, 1, 48)
                .expect("Failed to create NaiveTime for authn_instant in test_full_response_something_something"),
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

    let response = ResponseElementsBuilder::new()
        .issuer("http://idp.example.com/metadata.php")
        .response_id("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6")
        .issue_instant(DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2014, 7, 17)
                .expect("Failed to create NaiveDate for issue_instant in test_full_response_something_something")
                .and_hms_opt(1, 1, 48)
                .expect("Failed to create NaiveTime for issue_instant in test_full_response_something_something"),
            Utc,
        ))
        .in_response_to(String::from("ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"))
        .attributes(responseattributes)
        .destination(String::from("http://sp.example.com/demo1/index.php?acs"))
        .authnstatement(authnstatement)
        .assertion_id(String::from("_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"))
        .service_provider(saml_rs::sp::ServiceProvider::test_generic("sp.example.com"))
        .nameid_value("test-user".to_string())
        .assertion_consumer_service(Some(String::from("http://sp.example.com/demo1/index.php?acs")))
        .session_length_seconds(1)
        .status(saml_rs::constants::StatusCode::Success)
        .sign_assertion(sign_assertion)
        .sign_message(sign_message)
        .signing_key(signing_key.clone())
        .signing_cert(Some(signing_cert.clone()))
        .signing_algorithm(SigningAlgorithm::RsaSha256)
        .digest_algorithm(DigestAlgorithm::Sha256)
        .canonicalization_method(canonicalization_method)
        .build()
        .expect("Failed to build ResponseElements for test response parsing");

    (
        String::from_utf8(response.into()).expect("Failed to convert response to UTF-8 string"),
        signing_key,
        signing_cert,
    )
}

fn build_response(
    sign_assertion: bool,
    sign_message: bool,
    canonicalization_method: CanonicalizationMethod,
) -> String {
    build_response_with_cert(sign_assertion, sign_message, canonicalization_method).0
}

fn extract_assertion_xml(response_xml: &str) -> String {
    let start = response_xml
        .find("<saml:Assertion")
        .expect("expected signed assertion element in response xml");
    let end_relative = response_xml[start..]
        .find("</saml:Assertion>")
        .expect("expected end of assertion element in response xml");
    let end = start + end_relative + "</saml:Assertion>".len();
    response_xml[start..end].to_string()
}

#[test]
fn assertion_only_signs_assertion() {
    let xml = build_response(true, false, CanonicalizationMethod::ExclusiveCanonical10);
    let assertion_start = xml
        .find("<saml:Assertion")
        .expect("Failed to find start of Assertion element in test assertion_only_signs_assertion");
    let response_segment = &xml[..assertion_start];
    let assertion_segment = &xml[assertion_start..];
    assert!(!response_segment.contains("<ds:Signature"));
    assert!(assertion_segment.contains("<ds:Signature"));
}

#[test]
fn message_only_signs_response_message() {
    let xml = build_response(false, true, CanonicalizationMethod::ExclusiveCanonical10);
    let assertion_start = xml.find("<saml:Assertion").expect(
        "Failed to find start of Assertion element in test message_only_signs_response_message",
    );
    let response_segment = &xml[..assertion_start];
    let assertion_segment = &xml[assertion_start..];
    assert!(response_segment.contains("<ds:Signature"));
    assert!(!assertion_segment.contains("<ds:Signature"));
}

#[test]
fn inclusive_c14n_is_emitted_in_signedinfo() {
    let xml = build_response(true, true, CanonicalizationMethod::InclusiveCanonical10);
    let expected = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    assert!(xml.contains(expected));
    assert_eq!(xml.matches(expected).count(), 4);
}

#[test]
fn response_signature_and_reference_verify_roundtrip() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(false, true, CanonicalizationMethod::ExclusiveCanonical10);
    let result =
        saml_rs::response::verify_response_signature_and_references_with_key(&xml, &signing_key)
            .expect("verification should complete without parser errors");
    assert!(result);
}

#[test]
fn response_signature_verification_rejects_tampered_payload() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(false, true, CanonicalizationMethod::ExclusiveCanonical10);
    let tampered = xml.replacen("test-user", "evil-user", 1);
    let result = saml_rs::response::verify_response_signature_and_references_with_key(
        &tampered,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(!result);
}

#[test]
fn response_signature_verification_rejects_reference_uri_mismatch() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(false, true, CanonicalizationMethod::ExclusiveCanonical10);
    let tampered = xml.replacen(
        "URI=\"#_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\"",
        "URI=\"#_different\"",
        1,
    );
    let result = saml_rs::response::verify_response_signature_and_references_with_key(
        &tampered,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(!result);
}

#[test]
fn response_signature_verification_rejects_unexpected_transform() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(false, true, CanonicalizationMethod::ExclusiveCanonical10);
    let tampered = xml.replacen(
        "</ds:Transforms>",
        "<ds:Transform Algorithm=\"http://example.invalid/transform\"/></ds:Transforms>",
        1,
    );
    let result = saml_rs::response::verify_response_signature_and_references_with_key(
        &tampered,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(!result);
}

#[test]
fn assertion_signature_and_reference_verify_roundtrip() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(true, false, CanonicalizationMethod::ExclusiveCanonical10);
    let assertion_xml = extract_assertion_xml(&xml);
    let result = saml_rs::assertion::verify_assertion_signature_and_references_with_key(
        &assertion_xml,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(result);
}

#[test]
fn assertion_signature_verification_rejects_tampered_payload() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(true, false, CanonicalizationMethod::ExclusiveCanonical10);
    let assertion_xml = extract_assertion_xml(&xml);
    let tampered = assertion_xml.replacen("test-user", "evil-user", 1);
    let result = saml_rs::assertion::verify_assertion_signature_and_references_with_key(
        &tampered,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(!result);
}

#[test]
fn assertion_signature_verification_rejects_reference_uri_mismatch() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(true, false, CanonicalizationMethod::ExclusiveCanonical10);
    let assertion_xml = extract_assertion_xml(&xml);
    let tampered = assertion_xml.replacen(
        "URI=\"#_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"",
        "URI=\"#_different\"",
        1,
    );
    let result = saml_rs::assertion::verify_assertion_signature_and_references_with_key(
        &tampered,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(!result);
}

#[test]
fn assertion_signature_verification_rejects_unexpected_transform() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(true, false, CanonicalizationMethod::ExclusiveCanonical10);
    let assertion_xml = extract_assertion_xml(&xml);
    let tampered = assertion_xml.replacen(
        "</ds:Transforms>",
        "<ds:Transform Algorithm=\"http://example.invalid/transform\"/></ds:Transforms>",
        1,
    );
    let result = saml_rs::assertion::verify_assertion_signature_and_references_with_key(
        &tampered,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(!result);
}

#[test]
fn response_signature_verifies_via_key_provider() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(false, true, CanonicalizationMethod::ExclusiveCanonical10);
    let mut provider = InMemoryKeyProvider::new();
    provider.insert_signing_key("idp-signing", signing_key.as_ref().clone());
    provider.set_default_signing_key_id("idp-signing");

    let result = saml_rs::response::verify_response_signature_and_references_with_key_provider(
        &xml, &provider, None,
    )
    .expect("key provider verification should complete without parser errors");
    assert!(result);
}

#[test]
fn response_signature_verification_rejects_multiple_references() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(false, true, CanonicalizationMethod::ExclusiveCanonical10);
    let tampered = xml.replacen(
        "</ds:SignedInfo>",
        "<ds:Reference URI=\"#_another\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        1,
    );
    let result = saml_rs::response::verify_response_signature_and_references_with_key(
        &tampered,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(!result);
}

#[test]
fn assertion_signature_verifies_via_key_provider() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(true, false, CanonicalizationMethod::ExclusiveCanonical10);
    let assertion_xml = extract_assertion_xml(&xml);
    let mut provider = InMemoryKeyProvider::new();
    provider.insert_signing_key("idp-signing", signing_key.as_ref().clone());
    provider.set_default_signing_key_id("idp-signing");

    let result = saml_rs::assertion::verify_assertion_signature_and_references_with_key_provider(
        &assertion_xml,
        &provider,
        None,
    )
    .expect("key provider verification should complete without parser errors");
    assert!(result);
}

#[test]
fn assertion_signature_verification_rejects_multiple_references() {
    let (xml, signing_key, _cert) =
        build_response_with_cert(true, false, CanonicalizationMethod::ExclusiveCanonical10);
    let assertion_xml = extract_assertion_xml(&xml);
    let tampered = assertion_xml.replacen(
        "</ds:SignedInfo>",
        "<ds:Reference URI=\"#_another\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        1,
    );
    let result = saml_rs::assertion::verify_assertion_signature_and_references_with_key(
        &tampered,
        &signing_key,
    )
    .expect("verification should complete without parser errors");
    assert!(!result);
}
