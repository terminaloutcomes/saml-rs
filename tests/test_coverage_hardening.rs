//! Coverage-focused tests for strict defaults and edge-path behavior.
//!
//! The adversarial test cases in this file use an explicit attack contract:
//! - Attack: what malformed/malicious condition is attempted.
//! - Intent: why an attacker would attempt it.
//! - Expected response: exact strict-mode rejection category.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, NaiveDate, Utc};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509, X509NameBuilder};
use saml_rs::assertion::AssertionAttribute;
use saml_rs::response::{AuthNStatement, ResponseElements};
use saml_rs::security::{SecurityError, XmlSecurityLimits, inspect_xml_payload};
use saml_rs::sign::{CanonicalizationMethod, DigestAlgorithm, SigningAlgorithm};
use saml_rs::sp::{BindingMethod, NameIdFormat, SamlBindingType, ServiceBinding};
use saml_rs::utils::{DateTimeUtils, to_hex_string};

fn fixed_datetime() -> DateTime<Utc> {
    DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2024, 7, 17)
            .and_then(|value| value.and_hms_opt(9, 1, 48))
            .expect("failed to construct fixed datetime for tests"),
        Utc,
    )
}

fn generate_private_key() -> PKey<openssl::pkey::Private> {
    let rsa = match Rsa::generate(2048) {
        Ok(value) => value,
        Err(error) => panic!("failed to generate rsa key: {:?}", error),
    };
    match PKey::from_rsa(rsa) {
        Ok(value) => value,
        Err(error) => panic!("failed to convert rsa into pkey: {:?}", error),
    }
}

fn generate_valid_signing_material(common_name: &str) -> (PKey<openssl::pkey::Private>, X509) {
    let private_key = generate_private_key();

    let mut name_builder = match X509NameBuilder::new() {
        Ok(value) => value,
        Err(error) => panic!("failed to create X509 name builder: {:?}", error),
    };
    if let Err(error) = name_builder.append_entry_by_text("CN", common_name) {
        panic!("failed to set certificate CN: {:?}", error);
    }
    let name = name_builder.build();

    let mut builder = match X509::builder() {
        Ok(value) => value,
        Err(error) => panic!("failed to create X509 builder: {:?}", error),
    };
    if let Err(error) = builder.set_version(2) {
        panic!("failed to set certificate version: {:?}", error);
    }
    if let Err(error) = builder.set_subject_name(&name) {
        panic!("failed to set certificate subject name: {:?}", error);
    }
    if let Err(error) = builder.set_issuer_name(&name) {
        panic!("failed to set certificate issuer name: {:?}", error);
    }
    if let Err(error) = builder.set_pubkey(&private_key) {
        panic!("failed to set certificate public key: {:?}", error);
    }
    let not_before = match Asn1Time::days_from_now(0) {
        Ok(value) => value,
        Err(error) => panic!("failed to build not_before: {:?}", error),
    };
    if let Err(error) = builder.set_not_before(&not_before) {
        panic!("failed to set not_before: {:?}", error);
    }
    let not_after = match Asn1Time::days_from_now(365) {
        Ok(value) => value,
        Err(error) => panic!("failed to build not_after: {:?}", error),
    };
    if let Err(error) = builder.set_not_after(&not_after) {
        panic!("failed to set not_after: {:?}", error);
    }
    if let Err(error) = builder.sign(&private_key, MessageDigest::sha256()) {
        panic!("failed to sign certificate: {:?}", error);
    }

    (private_key, builder.build())
}

fn unique_temp_file(name: &str, extension: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value.as_nanos(),
        Err(error) => panic!("system clock error while creating temp path: {:?}", error),
    };
    path.push(format!(
        "saml-rs-{}-{}-{}.{}",
        name,
        std::process::id(),
        nanos,
        extension
    ));
    path
}

fn sample_response_builder(
    sign_assertion: bool,
    sign_message: bool,
    signing_cert: Option<openssl::x509::X509>,
) -> saml_rs::response::ResponseElementsBuilder {
    let authnstatement = AuthNStatement {
        instant: fixed_datetime(),
        session_index: "_session_idx".to_string(),
        classref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
        expiry: None,
    };

    let attributes = vec![
        AssertionAttribute::basic("uid", vec!["alice"]),
        AssertionAttribute::basic("mail", vec!["alice@example.com"]),
    ];

    ResponseElements::builder()
        .issuer("https://idp.example.com/metadata")
        .destination("https://sp.example.com/acs")
        .in_response_to("_relay")
        .nameid_value("alice")
        .authnstatement(authnstatement)
        .service_provider(saml_rs::sp::ServiceProvider::test_generic(
            "https://sp.example.com/metadata",
        ))
        .issue_instant(fixed_datetime())
        .attributes(attributes)
        .assertion_consumer_service(Some("https://sp.example.com/acs".to_string()))
        .sign_assertion(sign_assertion)
        .sign_message(sign_message)
        .signing_key(Some(generate_private_key()))
        .signing_cert(signing_cert)
        .signing_algorithm(SigningAlgorithm::Sha256)
        .digest_algorithm(DigestAlgorithm::Sha256)
        .canonicalization_method(CanonicalizationMethod::ExclusiveCanonical10)
}

#[test]
fn utils_hex_and_datetime_formatting_are_stable() {
    let rendered = to_hex_string(&[0x01, 0xAB, 0xFF], None);
    assert_eq!(rendered, "01abff");

    let rendered_joined = to_hex_string(&[0x01, 0xAB, 0xFF], Some(":"));
    assert_eq!(rendered_joined, "01:ab:ff");

    let ts = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2024, 1, 2)
            .and_then(|value| value.and_hms_opt(3, 4, 5))
            .unwrap_or_else(|| panic!("failed to construct datetime for formatting test")),
        Utc,
    );
    assert_eq!(ts.to_saml_datetime_string(), "2024-01-02T03:04:05Z");
}

#[test]
fn cert_helpers_parse_base64_and_strip_headers() {
    let (_private_key, cert) = generate_valid_signing_material("example.com");
    let cert_der = match cert.to_der() {
        Ok(value) => value,
        Err(error) => panic!("failed to render cert DER: {:?}", error),
    };
    let cert_der_base64 = BASE64_STANDARD.encode(cert_der);
    let cert_der_base64_with_ws = format!("\n  {}\n", cert_der_base64);

    let parsed = saml_rs::cert::init_cert_from_base64(&cert_der_base64_with_ws);
    assert!(parsed.is_ok(), "base64 DER cert should parse successfully");

    let invalid = saml_rs::cert::init_cert_from_base64("not-a-cert");
    assert!(invalid.is_err(), "invalid base64 cert input should fail");

    let cert_pem = match cert.to_pem() {
        Ok(value) => value,
        Err(error) => panic!("failed to render cert PEM: {:?}", error),
    };
    let cert_pem_string = match String::from_utf8(cert_pem) {
        Ok(value) => value,
        Err(error) => panic!("failed to convert cert PEM to utf8: {:?}", error),
    };
    let stripped = saml_rs::cert::strip_cert_headers(&cert_pem_string);
    assert!(!stripped.contains("BEGIN CERTIFICATE"));
    assert!(!stripped.contains("END CERTIFICATE"));
}

#[test]
fn decode_helpers_cover_plaintext_and_error_paths() {
    let xml = "<samlp:AuthnRequest ID=\"_abc\"></samlp:AuthnRequest>";
    let encoded = BASE64_STANDARD.encode(xml.as_bytes());

    let decoded = match saml_rs::decode_authn_request_base64_encoded(encoded) {
        Ok(value) => value,
        Err(error) => panic!("expected plaintext decode path to succeed: {:?}", error),
    };
    assert_eq!(decoded, xml);

    let invalid = saml_rs::decode_authn_request_base64_encoded("%%%".to_string());
    assert!(invalid.is_err(), "invalid base64 input should fail");

    let passthrough = saml_rs::decode_authn_request_signature("abc123".to_string());
    assert_eq!(passthrough, "abc123");
}

#[test]
fn authn_request_try_from_reports_missing_required_fields() {
    fn complete_parser() -> saml_rs::AuthnRequestParser {
        saml_rs::AuthnRequestParser {
            request_id: Some("_relay".to_string()),
            issue_instant: Some(fixed_datetime()),
            consumer_service_url: Some("https://sp.example.com/acs".to_string()),
            issuer: Some("https://sp.example.com/metadata".to_string()),
            version: "2.0".to_string(),
            issuer_state: -1,
            destination: Some("https://idp.example.com/SAML/Redirect".to_string()),
            sigalg: Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string()),
            signature: Some("sig-value".to_string()),
        }
    }

    let mut missing_relay = complete_parser();
    missing_relay.request_id = None;
    let relay_result = saml_rs::AuthnRequest::try_from(missing_relay);
    match relay_result {
        Ok(_) => panic!("missing request_id should fail"),
        Err(error) => assert!(error.message.contains("request_id")),
    }

    let mut missing_issue = complete_parser();
    missing_issue.issue_instant = None;
    let issue_result = saml_rs::AuthnRequest::try_from(missing_issue);
    match issue_result {
        Ok(_) => panic!("missing issue_instant should fail"),
        Err(error) => assert!(error.message.contains("issue_instant")),
    }

    let mut missing_acs = complete_parser();
    missing_acs.consumer_service_url = None;
    let acs_result = saml_rs::AuthnRequest::try_from(missing_acs);
    match acs_result {
        Ok(_) => panic!("missing consumer_service_url should fail"),
        Err(error) => assert!(error.message.contains("consumer_service_url")),
    }

    let mut missing_issuer = complete_parser();
    missing_issuer.issuer = None;
    let issuer_result = saml_rs::AuthnRequest::try_from(missing_issuer);
    match issuer_result {
        Ok(_) => panic!("missing issuer should fail"),
        Err(error) => assert!(error.message.contains("issuer")),
    }

    let mut missing_destination = complete_parser();
    missing_destination.destination = None;
    let destination_result = saml_rs::AuthnRequest::try_from(missing_destination);
    match destination_result {
        Ok(_) => panic!("missing destination should fail"),
        Err(error) => assert!(error.message.contains("destination")),
    }

    let ok = match saml_rs::AuthnRequest::try_from(complete_parser()) {
        Ok(value) => value,
        Err(error) => panic!(
            "complete parser should convert to AuthnRequest: {:?}",
            error
        ),
    };
    assert_eq!(ok.issue_instant_string(), "2024-07-17T09:01:48Z");
}

#[test]
fn response_builder_rejects_bad_inputs_and_builds_unsigned_responses() {
    let missing_issuer = saml_rs::response::ResponseElementsBuilder::new().build();
    match missing_issuer {
        Ok(_) => panic!("builder without issuer should fail"),
        Err(error) => assert_eq!(error, "issuer"),
    }

    let zero_session = sample_response_builder(false, false, None)
        .session_length_seconds(0)
        .build();
    match zero_session {
        Ok(_) => panic!("builder with zero session length should fail"),
        Err(error) => assert_eq!(error, "session_length_seconds must be greater than 0"),
    }

    let signing_without_cert = sample_response_builder(true, true, None).build();
    match signing_without_cert {
        Ok(_) => panic!("builder should require signing_cert when signing is enabled"),
        Err(error) => assert_eq!(error, "signing_cert must be set when signing is enabled"),
    }

    let bad_assertion_id = sample_response_builder(false, false, None)
        .assertion_id("abc")
        .build();
    match bad_assertion_id {
        Ok(_) => panic!("builder should reject non-SAML-safe assertion ids"),
        Err(error) => assert_eq!(
            error,
            "assertion_id must begin with '_' and contain only [A-Za-z0-9_.-]"
        ),
    }

    let bad_response_id = sample_response_builder(false, false, None)
        .response_id("abc")
        .build();
    match bad_response_id {
        Ok(_) => panic!("builder should reject non-SAML-safe response ids"),
        Err(error) => assert_eq!(
            error,
            "response_id must begin with '_' and contain only [A-Za-z0-9_.-]"
        ),
    }

    let unsigned = match sample_response_builder(false, false, None).build() {
        Ok(value) => value,
        Err(error) => panic!("unsigned response should build successfully: {}", error),
    };

    let xml_bytes = match unsigned.try_into_xml_bytes() {
        Ok(value) => value,
        Err(error) => panic!("unsigned response should render to xml: {}", error),
    };
    let xml = match String::from_utf8(xml_bytes) {
        Ok(value) => value,
        Err(error) => panic!("response xml should be utf8: {:?}", error),
    };
    assert!(!xml.contains("<ds:Signature"));
    assert_eq!(xml.matches("InResponseTo=\"_relay\"").count(), 2);
    assert!(xml.contains(">alice</saml:NameID>"));
    assert!(xml.contains("NotOnOrAfter=\"2024-07-17T09:02:48"));

    let regenerated = match sample_response_builder(false, false, None).build() {
        Ok(value) => value.regenerate_response_id(),
        Err(error) => panic!("response should build before id regeneration: {}", error),
    };
    assert!(regenerated.response_id.starts_with('_'));
}

#[test]
fn signing_roundtrip_sha256_detects_tamper_and_conversion_fallbacks() {
    let rsa = match Rsa::generate(2048) {
        Ok(value) => value,
        Err(error) => panic!("failed to generate rsa: {:?}", error),
    };
    let signing_key = match PKey::from_rsa(rsa) {
        Ok(value) => value,
        Err(error) => panic!("failed to create private key: {:?}", error),
    };
    let public_pem = match signing_key.public_key_to_pem() {
        Ok(value) => value,
        Err(error) => panic!("failed to export public key: {:?}", error),
    };
    let verify_key = match PKey::public_key_from_pem(&public_pem) {
        Ok(value) => value,
        Err(error) => panic!("failed to parse public key: {:?}", error),
    };

    let signed = saml_rs::sign::sign_data(SigningAlgorithm::Sha256, &signing_key, b"integrity");
    assert!(!signed.is_empty(), "SHA-256 signing should produce bytes");

    let ok =
        saml_rs::sign::verify_data(SigningAlgorithm::Sha256, &verify_key, b"integrity", &signed);
    match ok {
        Ok(value) => assert!(value, "signature must verify over original payload"),
        Err(error) => panic!("verification should not error: {}", error),
    }

    let tampered = saml_rs::sign::verify_data(
        SigningAlgorithm::Sha256,
        &verify_key,
        b"integrity-tampered",
        &signed,
    );
    match tampered {
        Ok(value) => assert!(
            !value,
            "signature verification must fail for tampered payload"
        ),
        Err(error) => panic!("tampered verify should return false, not error: {}", error),
    }

    let invalid_signing = SigningAlgorithm::from("urn:invalid".to_string());
    assert!(matches!(
        invalid_signing,
        SigningAlgorithm::InvalidAlgorithm
    ));

    let invalid_digest = DigestAlgorithm::from("urn:invalid".to_string());
    assert!(matches!(invalid_digest, DigestAlgorithm::InvalidAlgorithm));

    let invalid_signing_uri = String::from(SigningAlgorithm::InvalidAlgorithm);
    assert!(invalid_signing_uri.contains("Invalid Algorithm specified"));

    let invalid_digest_uri = String::from(DigestAlgorithm::InvalidAlgorithm);
    assert!(invalid_digest_uri.contains("Invalid Algorithm specified"));

    let inclusive =
        CanonicalizationMethod::from("http://www.w3.org/TR/2001/REC-xml-c14n-20010315".to_string());
    assert!(matches!(
        inclusive,
        CanonicalizationMethod::InclusiveCanonical10
    ));

    let fallback = CanonicalizationMethod::from("unknown-c14n-mode".to_string());
    assert!(matches!(
        fallback,
        CanonicalizationMethod::ExclusiveCanonical10
    ));

    let c14n_error = CanonicalizationMethod::ExclusiveCanonical10.canonicalize("<broken>");
    assert!(
        c14n_error.is_err(),
        "invalid xml should fail canonicalization"
    );
}

#[test]
fn service_provider_helpers_parse_valid_metadata_and_reject_invalid_inputs() {
    let metadata = r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/metadata">
        <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
            <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" Index="1"/>
            <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT" Location="https://sp.example.com/logout" Index="2"/>
        </md:SPSSODescriptor>
    </md:EntityDescriptor>"#;

    let service_provider = match metadata.parse::<saml_rs::sp::ServiceProvider>() {
        Ok(value) => value,
        Err(error) => panic!("valid SP metadata should parse: {}", error),
    };

    assert_eq!(
        service_provider.entity_id,
        "https://sp.example.com/metadata"
    );
    assert!(service_provider.authn_requests_signed);
    assert!(!service_provider.want_assertions_signed);
    assert!(matches!(
        service_provider.nameid_format,
        NameIdFormat::Transient
    ));
    assert_eq!(service_provider.services.len(), 2);

    let first_acs = service_provider.find_first_acs();
    match first_acs {
        Ok(value) => {
            assert_eq!(value.location, "https://sp.example.com/acs");
            assert!(matches!(value.binding, BindingMethod::HttpPost));
        }
        Err(error) => panic!("expected ACS service binding: {}", error),
    }

    let missing_acs =
        saml_rs::sp::ServiceProvider::test_generic("https://sp.example.com").find_first_acs();
    assert!(
        missing_acs.is_err(),
        "SP without services must not report ACS"
    );

    let mismatched = "<EntityDescriptor><SPSSODescriptor></EntityDescriptor></SPSSODescriptor>";
    let mismatch_result = mismatched.parse::<saml_rs::sp::ServiceProvider>();
    match mismatch_result {
        Ok(_) => panic!("mismatched XML should fail parsing"),
        Err(error) => assert!(error.to_ascii_lowercase().contains("mismatched")),
    }

    let cdata_payload = "<EntityDescriptor><SPSSODescriptor><NameIDFormat><![CDATA[evil]]></NameIDFormat></SPSSODescriptor></EntityDescriptor>";
    let cdata_result = cdata_payload.parse::<saml_rs::sp::ServiceProvider>();
    match cdata_result {
        Ok(_) => panic!("CDATA content should fail strict metadata parsing"),
        Err(error) => assert!(error.to_ascii_lowercase().contains("cdata")),
    }

    let binding = ServiceBinding::default().set_binding("invalid-binding");
    assert!(binding.is_err(), "invalid binding name should fail");

    assert!(BindingMethod::from_str("urn:invalid").is_err());
    assert!(NameIdFormat::from_str("urn:invalid").is_err());
    assert!(SamlBindingType::from_str("invalid-service-type").is_err());
}

#[derive(Clone, Copy, Debug)]
enum ExpectedXmlRejection {
    PayloadTooLarge,
    DtdForbidden,
    ProcessingInstructionForbidden,
    CdataForbidden,
    IncludeForbidden,
    ExternalSchemaForbidden,
    DepthExceeded,
    AttributesExceeded,
    TextTooLarge,
}

#[derive(Clone, Copy, Debug)]
struct XmlHardeningCase {
    id: &'static str,
    attack: &'static str,
    intent: &'static str,
    payload: &'static str,
    limits: XmlSecurityLimits,
    expected: ExpectedXmlRejection,
}

fn strict_limits() -> XmlSecurityLimits {
    XmlSecurityLimits::strict()
}

#[test]
fn xml_preflight_rejects_malicious_inputs_with_expected_categories() {
    let mut tiny_payload_limit = strict_limits();
    tiny_payload_limit.max_xml_bytes = 10;

    let mut tiny_depth_limit = strict_limits();
    tiny_depth_limit.max_depth = 2;

    let mut tiny_attr_limit = strict_limits();
    tiny_attr_limit.max_attributes_per_element = 1;

    let mut tiny_text_limit = strict_limits();
    tiny_text_limit.max_text_bytes = 3;

    let cases = vec![
        XmlHardeningCase {
            id: "X01",
            attack: "Oversized XML payload",
            intent: "Attempt parser resource exhaustion by flooding payload bytes.",
            payload: "<a>this payload is larger than ten bytes</a>",
            limits: tiny_payload_limit,
            expected: ExpectedXmlRejection::PayloadTooLarge,
        },
        XmlHardeningCase {
            id: "X02",
            attack: "DOCTYPE / DTD injection",
            intent: "Attempt entity-based parser manipulation and exfiltration.",
            payload: "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><a>&xxe;</a>",
            limits: strict_limits(),
            expected: ExpectedXmlRejection::DtdForbidden,
        },
        XmlHardeningCase {
            id: "X03",
            attack: "Processing instruction injection",
            intent: "Attempt external stylesheet processing and parser confusion.",
            payload: "<?xml-stylesheet type=\"text/xsl\" href=\"https://evil.example/x.xsl\"?><a/>",
            limits: strict_limits(),
            expected: ExpectedXmlRejection::ProcessingInstructionForbidden,
        },
        XmlHardeningCase {
            id: "X04",
            attack: "CDATA section injection",
            intent: "Attempt text normalization ambiguity around security-critical values.",
            payload: "<a><![CDATA[evil]]></a>",
            limits: strict_limits(),
            expected: ExpectedXmlRejection::CdataForbidden,
        },
        XmlHardeningCase {
            id: "X05",
            attack: "XInclude external load",
            intent: "Attempt to include attacker-controlled remote XML content.",
            payload: "<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"https://evil.example/include.xml\" />",
            limits: strict_limits(),
            expected: ExpectedXmlRejection::IncludeForbidden,
        },
        XmlHardeningCase {
            id: "X06",
            attack: "External schema location reference",
            intent: "Attempt schema-time network fetch and SSRF behavior.",
            payload: "<a xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"https://evil.example/schema.xsd foo.xsd\"/>",
            limits: strict_limits(),
            expected: ExpectedXmlRejection::ExternalSchemaForbidden,
        },
        XmlHardeningCase {
            id: "X07",
            attack: "Deep nesting bomb",
            intent: "Attempt stack and parser depth exhaustion.",
            payload: "<a><b><c/></b></a>",
            limits: tiny_depth_limit,
            expected: ExpectedXmlRejection::DepthExceeded,
        },
        XmlHardeningCase {
            id: "X08",
            attack: "Attribute flood",
            intent: "Attempt attribute-driven parser stress and override ambiguity.",
            payload: "<a x=\"1\" y=\"2\"/>",
            limits: tiny_attr_limit,
            expected: ExpectedXmlRejection::AttributesExceeded,
        },
        XmlHardeningCase {
            id: "X09",
            attack: "Oversized text node",
            intent: "Attempt memory pressure through oversized text token.",
            payload: "<a>1234</a>",
            limits: tiny_text_limit,
            expected: ExpectedXmlRejection::TextTooLarge,
        },
    ];

    for case in cases {
        let result = inspect_xml_payload(case.payload, case.limits);
        let error = match result {
            Ok(()) => panic!(
                "[{}] strict preflight unexpectedly accepted payload\nattack={}\nintent={}",
                case.id, case.attack, case.intent
            ),
            Err(value) => value,
        };

        let matched = matches!(
            (case.expected, &error),
            (
                ExpectedXmlRejection::PayloadTooLarge,
                SecurityError::XmlPayloadTooLarge { .. }
            ) | (
                ExpectedXmlRejection::DtdForbidden,
                SecurityError::XmlDtdForbidden
            ) | (
                ExpectedXmlRejection::ProcessingInstructionForbidden,
                SecurityError::XmlProcessingInstructionForbidden
            ) | (
                ExpectedXmlRejection::CdataForbidden,
                SecurityError::XmlCdataForbidden
            ) | (
                ExpectedXmlRejection::IncludeForbidden,
                SecurityError::XmlIncludeForbidden
            ) | (
                ExpectedXmlRejection::ExternalSchemaForbidden,
                SecurityError::XmlExternalSchemaReferenceForbidden
            ) | (
                ExpectedXmlRejection::DepthExceeded,
                SecurityError::XmlDepthExceeded { .. }
            ) | (
                ExpectedXmlRejection::AttributesExceeded,
                SecurityError::XmlAttributesExceeded { .. }
            ) | (
                ExpectedXmlRejection::TextTooLarge,
                SecurityError::XmlTextTooLarge { .. }
            )
        );

        assert!(
            matched,
            "[{}] strict preflight returned wrong rejection kind\nattack={}\nintent={}\nactual_error={:?}",
            case.id, case.attack, case.intent, error
        );
    }

    let safe_payload = "<AuthnRequest><Issuer>https://sp.example.com</Issuer></AuthnRequest>";
    let safe_result = inspect_xml_payload(safe_payload, strict_limits());
    assert!(
        safe_result.is_ok(),
        "well-formed payload should pass preflight"
    );
}

#[test]
fn sync_load_key_and_certificate_helpers_cover_file_paths() {
    let (private_key, cert) = generate_valid_signing_material("filetest.example.com");
    let key_pem = match private_key.private_key_to_pem_pkcs8() {
        Ok(value) => value,
        Err(error) => panic!("failed to render private key PEM: {:?}", error),
    };
    let cert_pem = match cert.to_pem() {
        Ok(value) => value,
        Err(error) => panic!("failed to render cert PEM: {:?}", error),
    };

    let key_path = unique_temp_file("sync-key", "pem");
    let cert_path = unique_temp_file("sync-cert", "pem");

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(value) => value,
        Err(error) => panic!(
            "failed to create tokio runtime for sync file test: {:?}",
            error
        ),
    };

    if let Err(error) = runtime.block_on(tokio::fs::write(&key_path, key_pem)) {
        panic!("failed writing temporary private key file: {:?}", error);
    }
    if let Err(error) = runtime.block_on(tokio::fs::write(&cert_path, cert_pem)) {
        panic!("failed writing temporary cert file: {:?}", error);
    }

    let key_result = saml_rs::sign::load_key_from_filename(key_path.to_string_lossy().as_ref());
    assert!(
        key_result.is_ok(),
        "private key file should load successfully"
    );

    let cert_result =
        saml_rs::sign::load_public_cert_from_filename(cert_path.to_string_lossy().as_ref());
    assert!(
        cert_result.is_ok(),
        "certificate file should load successfully"
    );

    let missing_key = saml_rs::sign::load_key_from_filename("/tmp/does-not-exist-key.pem");
    assert!(
        missing_key.is_err(),
        "missing key file should produce an error"
    );

    let missing_cert =
        saml_rs::sign::load_public_cert_from_filename("/tmp/does-not-exist-cert.pem");
    assert!(
        missing_cert.is_err(),
        "missing cert file should produce an error"
    );

    let _ = runtime.block_on(tokio::fs::remove_file(key_path));
    let _ = runtime.block_on(tokio::fs::remove_file(cert_path));
}

#[tokio::test(flavor = "current_thread")]
async fn async_load_key_and_certificate_helpers_cover_async_paths() {
    let (private_key, cert) = generate_valid_signing_material("async-filetest.example.com");
    let key_pem = match private_key.private_key_to_pem_pkcs8() {
        Ok(value) => value,
        Err(error) => panic!("failed to render async private key PEM: {:?}", error),
    };
    let cert_pem = match cert.to_pem() {
        Ok(value) => value,
        Err(error) => panic!("failed to render async cert PEM: {:?}", error),
    };

    let key_path = unique_temp_file("async-key", "pem");
    let cert_path = unique_temp_file("async-cert", "pem");

    if let Err(error) = tokio::fs::write(&key_path, key_pem).await {
        panic!(
            "failed writing async temporary private key file: {:?}",
            error
        );
    }
    if let Err(error) = tokio::fs::write(&cert_path, cert_pem).await {
        panic!("failed writing async temporary cert file: {:?}", error);
    }

    let key_result =
        saml_rs::sign::load_key_from_filename_async(key_path.to_string_lossy().as_ref()).await;
    assert!(
        key_result.is_ok(),
        "async private key file should load successfully"
    );

    let cert_result =
        saml_rs::sign::load_public_cert_from_filename_async(cert_path.to_string_lossy().as_ref())
            .await;
    assert!(
        cert_result.is_ok(),
        "async certificate file should load successfully"
    );

    let missing_key =
        saml_rs::sign::load_key_from_filename_async("/tmp/does-not-exist-async-key.pem").await;
    assert!(missing_key.is_err(), "missing async key file should error");

    let missing_cert =
        saml_rs::sign::load_public_cert_from_filename_async("/tmp/does-not-exist-async-cert.pem")
            .await;
    assert!(
        missing_cert.is_err(),
        "missing async cert file should error"
    );

    let _ = tokio::fs::remove_file(key_path).await;
    let _ = tokio::fs::remove_file(cert_path).await;
}
