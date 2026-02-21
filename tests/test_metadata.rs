use chrono::{DateTime, NaiveDate, Utc};
use saml_rs::metadata::SamlMetadata;

#[test]
/// tests saml_rs::metadata::SamlMetadata::new()
fn metadata_new_set_foo_example_com() {
    let test_metadata = SamlMetadata::new(
        "foo.example.com",
        None,
        None,
        None,
        None,
        None,
        Some(
            saml_rs::cert::gen_self_signed_certificate("foo.example.com")
                .expect("failed to generate self-signed certificate for test metadata"),
        ),
    );

    assert_eq!(test_metadata.hostname, String::from("foo.example.com"));
    assert_eq!(
        test_metadata.baseurl,
        String::from("https://foo.example.com/SAML")
    );
    assert_eq!(test_metadata.entity_id, String::from("foo.example.com"));
    assert_eq!(
        test_metadata.logout_url(),
        String::from("https://foo.example.com/SAML/Logout")
    );
    assert_eq!(
        test_metadata.redirect_url(),
        String::from("https://foo.example.com/SAML/Redirect")
    );
    assert_eq!(
        test_metadata.post_url(),
        String::from("https://foo.example.com/SAML/POST")
    );

    let test_metadata = SamlMetadata::new(
        "foo.example.com",
        None,
        None,
        Some("/fooooooo".to_string()),
        None,
        None,
        Some(
            saml_rs::cert::gen_self_signed_certificate("foo.example.com")
                .expect("failed to generate self-signed certificate for test metadata"),
        ), // certificate placeholder
    );
    assert_eq!(
        test_metadata.logout_url(),
        String::from("https://foo.example.com/SAML/fooooooo")
    );
}
#[test]
/// tests saml_rs::metadata::SamlMetadata::from_hostname()
fn metadata_from_hostname_foo_example_com() {
    let test_metadata = SamlMetadata::from_hostname("foo.example.com")
        .expect("failed to create test metadata from hostname");

    assert_eq!(test_metadata.hostname, String::from("foo.example.com"));
    assert_eq!(
        test_metadata.baseurl,
        String::from("https://foo.example.com/SAML")
    );
    assert_eq!(test_metadata.entity_id, String::from("foo.example.com"));
    assert_eq!(
        test_metadata.logout_url(),
        String::from("https://foo.example.com/SAML/Logout")
    );
    assert_eq!(
        test_metadata.redirect_url(),
        String::from("https://foo.example.com/SAML/Redirect")
    );
    assert_eq!(
        test_metadata.post_url(),
        String::from("https://foo.example.com/SAML/POST")
    );

    let test_metadata = SamlMetadata::from_hostname("foo.example.com")
        .expect("failed to create test metadata from hostname");
    assert_ne!(test_metadata.hostname, String::from("zot.example.com"));
}

#[test]
fn test_parse_saml_xml_authn_request() {
    let test_parse =
        saml_rs::parse_authn_request(saml_rs::test_samples::TEST_AUTHN_REQUEST_EXAMPLE_COM);
    let result = match test_parse {
        Ok(value) => value,
        Err(error) => {
            panic!("Failed to parse test sample, this seems bad: {:?}", error);
        }
    };

    let expected_result = saml_rs::AuthnRequest {
        request_id: String::from("_6c1cd5d32c2df1bab98f58a144f9b971"),
        issuer: String::from("https://samltest.id/saml/sp"),
        issue_instant: DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2021, 7, 19)
                .expect("failed to create NaiveDate for expected result in test_parse_saml_xml_authn_request")
                .and_hms_opt(12, 6, 25)
                .expect("failed to create NaiveTime for expected result in test_parse_saml_xml_authn_request"),
            Utc,
        ),
        consumer_service_url: String::from("https://samltest.id/Shibboleth.sso/SAML2/POST"),
        version: String::from("2.0"),
        destination: String::from("https://example.com/v1/SAML/Redirect"),
        sigalg: None,
        signature: None,
    };
    assert_eq!(
        result.request_id,
        String::from("_6c1cd5d32c2df1bab98f58a144f9b971")
    );
    assert_eq!(result.request_id, expected_result.request_id);
    assert_eq!(result.issuer, expected_result.issuer);
    assert_eq!(
        result.issue_instant_string(),
        expected_result.issue_instant_string()
    );
    assert_eq!(
        result.consumer_service_url,
        expected_result.consumer_service_url
    );
    assert_eq!(result.version, expected_result.version);
    // nothing, hopefully!
    assert_eq!(result.signature, expected_result.signature);
    assert_eq!(result.sigalg, expected_result.sigalg);
}

/// tests parsing saml_rs::test_samples::TEST_AUTHN_REQUEST_EXAMPLE_COM_BASE64_DEFLATED
#[test]
fn test_parse_test_parse_saml_base64_authn_request() {
    let decoded = saml_rs::decode_authn_request_base64_encoded(
        saml_rs::test_samples::TEST_AUTHN_REQUEST_EXAMPLE_COM_BASE64_DEFLATED.to_string(),
    )
    .expect("failed to decode base64-encoded SAML request in test_parse_test_parse_saml_base64_authn_request");

    assert!(saml_rs::parse_authn_request(&decoded).is_ok());
}

#[test]
fn test_validate_metadata_samltool() {
    let metadata_input = SamlMetadata::new(
        "example.com",
        None,
        None,
        None,
        None,
        None,
        Some(
            saml_rs::cert::gen_self_signed_certificate("example.com")
                .expect("failed to generate self-signed certificate for test metadata"),
        ),
    );
    let metadata: String = saml_rs::metadata::generate_metadata_xml(&metadata_input)
        .expect("failed to generate metadata XML for test");

    let params = [
        ("xsd", "md-metadata"),
        ("act_validate_xml", "Validate+XML+with+the+XSD+schema"),
        ("xml", &metadata),
    ];

    eprintln!("metadata XML:\n{}", metadata);

    let client = reqwest::blocking::Client::new();
    let value = client
        .post("https://www.samltool.com/validate_xml.php")
        .form(&params)
        .send().expect("failed to send POST request to SAML XML validation endpoint in test_validate_metadata_samltool");

    eprintln!("success doing post: {:?}", value);
    // debug!("{:?}", value.bytes());

    let content = value.text().expect("Failed to read response text from SAML XML validation request in test_validate_metadata_samltool");
    /* looking for this

                <div class="validatexml-area3"><br>

                    <div class="alert alert-success">
                        <h3>The XML is valid.</h3>
                    </div>
                </div>
    */

    assert!(
        content.contains("The XML is valid."),
        "failed to find \"The XML is valid.\" in response content from SAML XML validation request in test_validate_metadata_samltool {}",
        content
    );
}
