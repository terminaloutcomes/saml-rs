//! Adversarial SAML/XML attack matrix tests.
//!
//! This suite is intentionally table-driven so each fixture carries:
//! - attack class and intent
//! - attacker objective
//! - safe-mode expected behavior
//! - danger-mode expected behavior
//! - expected rejection hint
//!
//! Detailed prose for each case lives in `tests/fixtures/attacks/ATTACK_EXPECTATIONS.md`.

use std::path::PathBuf;

use openssl::pkey::PKey;
use openssl::rsa::Rsa;

#[derive(Clone, Copy, Debug)]
enum AttackTarget {
    AuthnRequest,
    ServiceProviderMetadata,
}

#[derive(Clone, Copy, Debug)]
struct AttackCase {
    id: &'static str,
    title: &'static str,
    filename: &'static str,
    target: AttackTarget,
    attack_intent: &'static str,
    attacker_goal: &'static str,
    safe_mode_expectation: &'static str,
    danger_mode_expectation: &'static str,
    expected_rejection_hint: Option<&'static str>,
}

fn fixture_path(filename: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("attacks")
        .join(filename)
}

fn load_fixture(filename: &str) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime build should succeed");
    let bytes = runtime
        .block_on(tokio::fs::read(fixture_path(filename)))
        .expect("failed to read fixture");
    String::from_utf8(bytes).expect("fixture was not valid utf8")
}

fn attack_cases() -> Vec<AttackCase> {
    vec![
        AttackCase {
            id: "A01",
            title: "XXE Local File Exfiltration",
            filename: "01_xxe_local_file_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Inject DTD entity pointing to local filesystem.",
            attacker_goal: "Leak host-local secrets (for example /etc/passwd).",
            safe_mode_expectation: "Reject payload before semantic parse.",
            danger_mode_expectation: "Still reject; structural XML exploit remains blocked.",
            expected_rejection_hint: Some("doctype"),
        },
        AttackCase {
            id: "A02",
            title: "XXE Remote SSRF",
            filename: "02_xxe_remote_ssrf_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Inject DTD entity with remote SYSTEM identifier.",
            attacker_goal: "Trigger outbound HTTP fetch/SSRF from parser host.",
            safe_mode_expectation: "Reject DTD usage before parser traversal.",
            danger_mode_expectation: "Still reject; no remote entity resolution allowed.",
            expected_rejection_hint: Some("doctype"),
        },
        AttackCase {
            id: "A03",
            title: "Parameter Entity Expansion",
            filename: "03_parameter_entity_expansion_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Use parameter entities to smuggle external entity declarations.",
            attacker_goal: "Bypass simplistic XXE filters and force entity expansion.",
            safe_mode_expectation: "Reject all DTD constructs.",
            danger_mode_expectation: "Still reject all DTD constructs.",
            expected_rejection_hint: Some("doctype"),
        },
        AttackCase {
            id: "A04",
            title: "Billion Laughs DoS",
            filename: "04_billion_laughs_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Define recursively expanding entities.",
            attacker_goal: "Consume CPU/memory via exponential expansion.",
            safe_mode_expectation: "Reject DTD/entity declarations before expansion.",
            danger_mode_expectation: "Still reject DTD/entity declarations.",
            expected_rejection_hint: Some("doctype"),
        },
        AttackCase {
            id: "A05",
            title: "External Schema Resolution",
            filename: "05_external_schema_location_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Set remote `xsi:schemaLocation` URL.",
            attacker_goal: "Induce network fetch and parser differentials.",
            safe_mode_expectation: "Reject external schema reference.",
            danger_mode_expectation: "Still reject external schema reference.",
            expected_rejection_hint: Some("external schema"),
        },
        AttackCase {
            id: "A06",
            title: "XInclude Remote Load",
            filename: "06_xinclude_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Use `xi:include` with external URL.",
            attacker_goal: "Import attacker-controlled XML into trusted parse tree.",
            safe_mode_expectation: "Reject include directive.",
            danger_mode_expectation: "Still reject include directive.",
            expected_rejection_hint: Some("xinclude"),
        },
        AttackCase {
            id: "A07",
            title: "Stylesheet Processing Instruction",
            filename: "07_xml_stylesheet_pi_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Inject XML PI with remote stylesheet reference.",
            attacker_goal: "Coerce unsafe external resource handling.",
            safe_mode_expectation: "Reject processing instructions.",
            danger_mode_expectation: "Still reject processing instructions.",
            expected_rejection_hint: Some("processing instructions"),
        },
        AttackCase {
            id: "A08",
            title: "CDATA Injection Surface",
            filename: "08_cdata_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Inject CDATA near key protocol content.",
            attacker_goal: "Exploit parser discrepancies over text normalization.",
            safe_mode_expectation: "Reject CDATA sections.",
            danger_mode_expectation: "Still reject CDATA sections.",
            expected_rejection_hint: Some("cdata"),
        },
        AttackCase {
            id: "A09",
            title: "Deep Nesting Stress",
            filename: "09_too_deep_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Build excessive XML depth.",
            attacker_goal: "Cause parser stack stress and resource exhaustion.",
            safe_mode_expectation: "Reject at depth limit.",
            danger_mode_expectation: "Still reject at depth limit.",
            expected_rejection_hint: Some("depth"),
        },
        AttackCase {
            id: "A10",
            title: "Attribute Flood",
            filename: "10_too_many_attributes_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Inject oversized attribute set on root element.",
            attacker_goal: "Stress parser and attempt override via duplicate-ish fields.",
            safe_mode_expectation: "Reject at attribute-per-element limit.",
            danger_mode_expectation: "Still reject at attribute-per-element limit.",
            expected_rejection_hint: Some("attributes"),
        },
        AttackCase {
            id: "A11",
            title: "Duplicate ID Confusion",
            filename: "11_duplicate_id_attribute_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Supply multiple `ID` values.",
            attacker_goal: "Create ambiguity for reference/signature matching.",
            safe_mode_expectation: "Reject duplicate root attributes.",
            danger_mode_expectation: "Still reject duplicate root attributes.",
            expected_rejection_hint: Some("duplicate"),
        },
        AttackCase {
            id: "A12",
            title: "Duplicate Destination Override",
            filename: "12_duplicate_destination_attribute_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Supply multiple `Destination` values.",
            attacker_goal: "Exploit first-win/last-win parser differences.",
            safe_mode_expectation: "Reject duplicate root attributes.",
            danger_mode_expectation: "Still reject duplicate root attributes.",
            expected_rejection_hint: Some("duplicate"),
        },
        AttackCase {
            id: "A13",
            title: "Duplicate Issuer Confusion",
            filename: "13_duplicate_issuer_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Provide two Issuer elements with conflicting values.",
            attacker_goal: "Bypass issuer-based trust mapping.",
            safe_mode_expectation: "Reject duplicate Issuer content.",
            danger_mode_expectation: "Still reject duplicate Issuer content.",
            expected_rejection_hint: Some("duplicate issuer"),
        },
        AttackCase {
            id: "A14",
            title: "Empty Issuer Bypass",
            filename: "14_empty_issuer_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Provide syntactically present but empty Issuer.",
            attacker_goal: "Exploit missing issuer validation logic.",
            safe_mode_expectation: "Reject empty Issuer.",
            danger_mode_expectation: "Still reject empty Issuer.",
            expected_rejection_hint: Some("issuer"),
        },
        AttackCase {
            id: "A15",
            title: "Nested AuthnRequest Wrapping",
            filename: "15_nested_authnrequest_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Embed nested AuthnRequest with alternate values.",
            attacker_goal: "Trigger signature/reference confusion and bypass checks.",
            safe_mode_expectation: "Reject nested/duplicate root protocol element.",
            danger_mode_expectation: "Still reject nested/duplicate root protocol element.",
            expected_rejection_hint: Some("nested"),
        },
        AttackCase {
            id: "A16",
            title: "Protocol Version Downgrade",
            filename: "16_version_downgrade_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Use SAML version other than 2.0.",
            attacker_goal: "Force permissive handling of unsupported protocol revision.",
            safe_mode_expectation: "Reject non-2.0 requests.",
            danger_mode_expectation: "Still reject non-2.0 requests.",
            expected_rejection_hint: Some("version!=2.0"),
        },
        AttackCase {
            id: "A17",
            title: "Malformed XML / Unbalanced Tags",
            filename: "17_malformed_unbalanced_authn.xml",
            target: AttackTarget::AuthnRequest,
            attack_intent: "Break tag balancing around critical fields.",
            attacker_goal: "Trigger differential parser recovery behavior.",
            safe_mode_expectation: "Reject malformed document.",
            danger_mode_expectation: "Still reject malformed document.",
            expected_rejection_hint: Some("malformed"),
        },
        AttackCase {
            id: "A18",
            title: "General Entity Reference in Metadata",
            filename: "18_general_entity_ref_metadata.xml",
            target: AttackTarget::ServiceProviderMetadata,
            attack_intent: "Inject non-predefined entity reference in metadata content.",
            attacker_goal: "Abuse entity expansion or parser fallback behavior.",
            safe_mode_expectation: "Reject unknown/general entity references.",
            danger_mode_expectation: "Still reject unknown/general entity references.",
            expected_rejection_hint: Some("entity"),
        },
        AttackCase {
            id: "A19",
            title: "External Schema in Metadata",
            filename: "19_external_schema_location_metadata.xml",
            target: AttackTarget::ServiceProviderMetadata,
            attack_intent: "Reference remote schema from SP metadata.",
            attacker_goal: "Cause metadata parser SSRF or schema poisoning.",
            safe_mode_expectation: "Reject external schema references.",
            danger_mode_expectation: "Still reject external schema references.",
            expected_rejection_hint: Some("external schema"),
        },
        AttackCase {
            id: "A20",
            title: "XXE Remote in Metadata",
            filename: "20_xxe_metadata_remote.xml",
            target: AttackTarget::ServiceProviderMetadata,
            attack_intent: "Inject remote XXE in metadata document DTD.",
            attacker_goal: "Trigger metadata-time SSRF/data exfiltration.",
            safe_mode_expectation: "Reject DTD declarations.",
            danger_mode_expectation: "Still reject DTD declarations.",
            expected_rejection_hint: Some("doctype"),
        },
    ]
}

fn run_attack_case(case: AttackCase) -> Result<(), String> {
    let payload = load_fixture(case.filename);
    match case.target {
        AttackTarget::AuthnRequest => saml_rs::parse_authn_request(&payload)
            .map(|_| ())
            .map_err(|error| error.message),
        AttackTarget::ServiceProviderMetadata => payload
            .parse::<saml_rs::sp::ServiceProvider>()
            .map(|_| ())
            .map_err(|error| error.to_string()),
    }
}

fn assert_attack_is_rejected(case: AttackCase, mode_label: &str) {
    let result = run_attack_case(case);
    let err = match result {
        Ok(()) => {
            panic!(
                "[{}:{} {}] unexpectedly parsed.\nattack_intent={}\nattacker_goal={}\nsafe_expectation={}\ndanger_expectation={}",
                mode_label,
                case.id,
                case.title,
                case.attack_intent,
                case.attacker_goal,
                case.safe_mode_expectation,
                case.danger_mode_expectation
            );
        }
        Err(error) => error,
    };

    if let Some(hint) = case.expected_rejection_hint {
        let hint_lower = hint.to_ascii_lowercase();
        let err_lower = err.to_ascii_lowercase();
        assert!(
            err_lower.contains(&hint_lower),
            "[{}:{} {}] rejection reason did not include expected hint.\nexpected_hint={}\nactual_error={}\nattack_intent={}\nattacker_goal={}\nsafe_expectation={}\ndanger_expectation={}",
            mode_label,
            case.id,
            case.title,
            hint,
            err,
            case.attack_intent,
            case.attacker_goal,
            case.safe_mode_expectation,
            case.danger_mode_expectation
        );
    }
}

#[cfg(not(feature = "danger_i_want_to_risk_it_all"))]
#[test]
fn rejects_attack_matrix_in_safe_mode() {
    for case in attack_cases() {
        assert_attack_is_rejected(case, "safe");
    }

    assert!(!saml_rs::security::weak_algorithms_allowed());
    assert!(!saml_rs::security::unsigned_authn_requests_allowed());
    assert!(!saml_rs::security::unknown_service_providers_allowed());

    let rsa = Rsa::generate(2048).expect("rsa generation should succeed");
    let signing_key = PKey::from_rsa(rsa).expect("private key should be constructible");
    let public_pem = signing_key
        .public_key_to_pem()
        .expect("public key pem should render");
    let verify_key = PKey::public_key_from_pem(&public_pem).expect("public key should parse");

    let signed = saml_rs::sign::sign_data(
        saml_rs::sign::SigningAlgorithm::Sha1,
        &signing_key,
        b"downgrade-check",
    );
    assert!(
        signed.is_empty(),
        "SHA-1 signing should be blocked in safe mode"
    );

    let verify_result = saml_rs::sign::verify_data(
        saml_rs::sign::SigningAlgorithm::Sha1,
        &verify_key,
        b"downgrade-check",
        b"bogus",
    );
    assert!(
        verify_result.is_err(),
        "SHA-1 verification should be blocked in safe mode"
    );
}

#[cfg(feature = "danger_i_want_to_risk_it_all")]
#[test]
fn rejects_attack_matrix_before_runtime_danger_unlock() {
    for case in attack_cases() {
        assert_attack_is_rejected(case, "danger-locked");
    }
}

#[cfg(feature = "danger_i_want_to_risk_it_all")]
#[test]
fn danger_mode_requires_explicit_unlock_and_only_relaxes_selected_controls() {
    let token = saml_rs::security::danger::unlock();
    saml_rs::security::danger::enable_weak_algorithms(&token);
    saml_rs::security::danger::enable_unsigned_authn_requests(&token);
    saml_rs::security::danger::enable_unknown_service_providers(&token);

    assert!(saml_rs::security::weak_algorithms_allowed());
    assert!(saml_rs::security::unsigned_authn_requests_allowed());
    assert!(saml_rs::security::unknown_service_providers_allowed());

    let rsa = Rsa::generate(2048).expect("rsa generation should succeed");
    let signing_key = PKey::from_rsa(rsa).expect("private key should be constructible");
    let public_pem = signing_key
        .public_key_to_pem()
        .expect("public key pem should render");
    let verify_key = PKey::public_key_from_pem(&public_pem).expect("public key should parse");

    let signed = saml_rs::sign::sign_data(
        saml_rs::sign::SigningAlgorithm::Sha1,
        &signing_key,
        b"downgrade-check",
    );
    assert!(
        !signed.is_empty(),
        "SHA-1 signing should only be possible after explicit danger unlock"
    );

    let verified = saml_rs::sign::verify_data(
        saml_rs::sign::SigningAlgorithm::Sha1,
        &verify_key,
        b"downgrade-check",
        &signed,
    )
    .expect("verification call should succeed");
    assert!(
        verified,
        "SHA-1 signature should verify after explicit danger unlock"
    );

    for case in attack_cases() {
        assert_attack_is_rejected(case, "danger-unlocked");
    }
}
