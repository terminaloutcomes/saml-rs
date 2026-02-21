//! Legacy digest regression tests.
//!
//! These cases intentionally model historical SHA-1 vectors used by older SAML stacks.
//! In strict mode this crate rejects SHA-1 by default. In danger mode, SHA-1 can only be
//! enabled with an explicit runtime unlock.

#[cfg(feature = "danger_i_want_to_risk_it_all")]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use saml_rs::sign::{DigestAlgorithm, SigningAlgorithm, SigningKey};
#[cfg(feature = "danger_i_want_to_risk_it_all")]
use saml_rs::utils::to_hex_string;
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
struct LegacyDigestCase {
    id: &'static str,
    attack: &'static str,
    intent: &'static str,
    payload: &'static str,
    expected_sha1_hex: &'static str,
    expected_sha1_base64: &'static str,
}

fn legacy_digest_cases() -> Vec<LegacyDigestCase> {
    vec![
        LegacyDigestCase {
            id: "D01",
            attack: "Legacy SHA-1 digest acceptance",
            intent: "Older SAML federation peers may still emit SHA-1 digest references.",
            payload: "<Envelope xmlns=\"http://example.org/envelope\">\n  <Body>\n    Olá mundo\n  </Body>\n  \n</Envelope>",
            expected_sha1_hex: "516b984d8ba0d7427593984a7e89f1b6182b011f",
            expected_sha1_base64: "UWuYTYug10J1k5hKfonxthgrAR8=",
        },
        LegacyDigestCase {
            id: "D02",
            attack: "Legacy SHA-1 digest acceptance with large metadata-like body",
            intent: "Exercise compatibility vector with non-ASCII content and multi-node payload; this uses the crate byte-for-byte digest result.",
            payload: "<MsgHead xmlns=\"http://www.example.com/msghead\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema.xsd\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.example.com/msghead MsgHead.xsd\">\n  <MsgInfo>\n    <Type DN=\"Resept\" V=\"ERM1\"></Type>\n    <Patient>\n       <FamilyName>Nordmann</FamilyName>\n       <GivenName>Ola</GivenName>\n        <Ident>\n          <Id>12345678901</Id>\n          <TypeId DN=\"Fødselsnummer\" S=\"2.16.123.1.10.4.1.1.9999\" V=\"FNR\"></TypeId>\n        </Ident>\n      </Patient>\n    </MsgInfo>\n  <Document>\n    <RefDoc>foo bar</RefDoc>\n  </Document>\n\n</MsgHead>",
            expected_sha1_hex: "0fd1fa051f930c5faccfb05cf63ebfce27184bb0",
            expected_sha1_base64: "D9H6BR+TDF+sz7Bc9j6/zicYS7A=",
        },
    ]
}

#[cfg(not(feature = "danger_i_want_to_risk_it_all"))]
#[test]
fn strict_mode_rejects_legacy_sha1_vectors_and_sha1_signatures() {
    for case in legacy_digest_cases() {
        let digest_result = DigestAlgorithm::Sha1.hash(case.payload.as_bytes());
        assert!(
            digest_result.is_err(),
            "[{}] strict mode unexpectedly accepted SHA-1 digest input\nattack={}\nintent={}",
            case.id,
            case.attack,
            case.intent
        );
        assert!(!case.expected_sha1_hex.is_empty());
        assert!(!case.expected_sha1_base64.is_empty());
    }

    let signing_key: Arc<SigningKey> = Arc::new(saml_rs::sign::generate_private_key().into());

    assert!(
        saml_rs::sign::sign_data(SigningAlgorithm::RsaSha1, &signing_key, b"sha1-blocked").is_err(),
        "strict mode should block SHA-1 signing API"
    );

    assert!(
        saml_rs::sign::verify_data(
            SigningAlgorithm::RsaSha1,
            &signing_key,
            b"sha1-blocked",
            b"bogus",
        )
        .is_err(),
        "strict mode should block SHA-1 verification API"
    );
}

#[cfg(feature = "danger_i_want_to_risk_it_all")]
#[test]
fn danger_mode_allows_legacy_sha1_only_after_explicit_unlock() {
    for case in legacy_digest_cases() {
        let pre_unlock = DigestAlgorithm::Sha1.hash(case.payload.as_bytes());
        assert!(
            pre_unlock.is_err(),
            "[{}] danger feature should remain locked until explicit runtime unlock",
            case.id
        );
    }

    let token = saml_rs::security::danger::unlock();
    saml_rs::security::danger::enable_weak_algorithms(&token);

    for case in legacy_digest_cases() {
        let digest = match DigestAlgorithm::Sha1.hash(case.payload.as_bytes()) {
            Ok(value) => value,
            Err(error) => panic!(
                "[{}] SHA-1 digest should be enabled after explicit danger unlock: {:?}",
                case.id, error
            ),
        };
        let digest_hex = to_hex_string(digest.as_ref(), None);
        let digest_base64 = BASE64_STANDARD.encode(digest);

        assert_eq!(
            digest_hex, case.expected_sha1_hex,
            "[{}] digest hex mismatch\nattack={}\nintent={}",
            case.id, case.attack, case.intent
        );
        assert_eq!(
            digest_base64, case.expected_sha1_base64,
            "[{}] digest base64 mismatch\nattack={}\nintent={}",
            case.id, case.attack, case.intent
        );
    }

    let signing_key: Arc<SigningKey> = Arc::new(saml_rs::sign::generate_private_key().into());
    let signed = saml_rs::sign::sign_data(
        SigningAlgorithm::RsaSha1,
        &signing_key,
        b"legacy-interoperability",
    )
    .expect("danger-unlocked mode should allow SHA-1 signing API");
    assert!(
        !signed.is_empty(),
        "danger-unlocked mode should permit SHA-1 signing for compatibility testing"
    );

    let verified = match saml_rs::sign::verify_data(
        SigningAlgorithm::RsaSha1,
        &signing_key,
        b"legacy-interoperability",
        &signed,
    ) {
        Ok(value) => value,
        Err(error) => panic!(
            "danger-unlocked mode should allow SHA-1 verification API: {}",
            error
        ),
    };
    assert!(
        verified,
        "generated SHA-1 signature should verify in danger mode"
    );
}
