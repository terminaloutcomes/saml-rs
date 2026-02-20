use chrono::{DateTime, Duration, NaiveDate, Utc};
use saml_rs::assertion::AssertionAttribute;
use saml_rs::response::{AuthNStatement, ResponseElements};
use saml_rs::sign::SigningKey;
use saml_rs::test_samples::TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION;
use saml_rs::utils::generate_keypair;
use std::str::from_utf8;

#[test]
/// tests test_full_response_something_something
fn test_full_response_something_something() {
    // Session up the AuthNStatement
    let authn_instant = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2014, 7, 17)
            .expect("Failed to create NaiveDate for authn_instant in test_full_response_something_something")
            .and_hms_opt(1, 1, 48)
            .expect("Failed to create NaiveTime for authn_instant in test_full_response_something_something"),
        Utc,
    );
    // 2024-07-17T09:01:48Z
    // adding three years including skip years
    let session_expiry = match DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2014, 7, 17)
            .expect("Failed to create NaiveDate for session_expiry in test_full_response_something_something")
            .and_hms_opt(9, 1, 48)
            .expect("Failed to create NaiveTime for session_expiry in test_full_response_something_something"),
        Utc,
    )
    .checked_add_signed(Duration::days(3653))
    {
        Some(value) => value,
        _ => Utc::now(),
    };

    let authnstatement = AuthNStatement {
        instant: authn_instant,
        session_index: String::from("_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"),
        classref: String::from("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"),
        expiry: Some(session_expiry),
    };

    let responseattributes = [
        AssertionAttribute::basic("uid", ["test"].to_vec().clone()),
        AssertionAttribute::basic("mail", ["test@example.com"].to_vec()),
        AssertionAttribute::basic("eduPersonAffiliation", ["users", "examplerole1"].to_vec()),
    ]
    .to_vec();

    let inputdata = ResponseElements {
        issuer: String::from("http://idp.example.com/metadata.php"),
        response_id: String::from("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"),
        // issue_instant: String::from("2014-07-17T01:01:48Z"),
        issue_instant: DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2014, 7, 17)
                .expect("Failed to create NaiveDate for issue_instant in test_full_response_something_something")
                .and_hms_opt(1, 1, 48)
                .expect("Failed to create NaiveTime for issue_instant in test_full_response_something_something"),
            Utc,
        ),
        in_response_to: String::from("ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"),
        attributes: responseattributes,
        destination: String::from("http://sp.example.com/demo1/index.php?acs"),
        authnstatement,
        assertion_id: String::from("_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"),
        service_provider: saml_rs::sp::ServiceProvider::test_generic("sp.example.com"),
        nameid_value: "test-user".to_string(),
        assertion_consumer_service: Some(String::from("http://sp.example.com/demo1/index.php?acs")),
        session_length_seconds: 1,
        // TODO: Set a proper statuscode and test it in test_full_response_something_something
        status: saml_rs::constants::StatusCode::AuthnFailed,
        sign_assertion: false,
        sign_message: false,
        signing_key: SigningKey::from(generate_keypair().expect("failed to generate keypair").0)
            .into(),
        signing_cert: None,
        signing_algorithm: saml_rs::sign::SigningAlgorithm::RsaSha256,
        digest_algorithm: saml_rs::sign::DigestAlgorithm::Sha256,
        canonicalization_method: saml_rs::sign::CanonicalizationMethod::ExclusiveCanonical10,
    };
    let response_vec: Vec<u8> = inputdata.into();

    let response = from_utf8(&response_vec).expect("Failed to convert response to UTF-8 string");

    let test1 = TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION.replace("\n", "");
    let test2 = response.replace("\n", "");
    let changeset = dissimilar::diff(&test1, &test2);
    let whitespace_re = regex::Regex::new(r"\s+").expect("Failed to compile whitespace regex");
    println!("{:?}", changeset);
    for item in changeset {
        match item {
            dissimilar::Chunk::Equal(_) => {}
            dissimilar::Chunk::Delete(del) => {
                if whitespace_re.is_match(del) {
                    // eprintln!("Deleted whitespace");
                } else {
                    eprintln!("Deleted: {}", del);
                }
            }
            dissimilar::Chunk::Insert(ins) => eprintln!("Inserted: {}", ins),
        }
    }
}
