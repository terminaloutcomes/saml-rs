#[cfg(test)]
mod tests {
    use chrono::{DateTime, NaiveDate, Utc};
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use saml_rs::assertion::AssertionAttribute;
    use saml_rs::response::{AuthNStatement, ResponseElements};
    use saml_rs::sign::{CanonicalizationMethod, DigestAlgorithm, SigningAlgorithm};

    fn build_response(
        sign_assertion: bool,
        sign_message: bool,
        canonicalization_method: CanonicalizationMethod,
    ) -> String {
        let authnstatement = AuthNStatement {
            instant: DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDate::from_ymd_opt(2014, 7, 17)
                    .unwrap()
                    .and_hms_opt(1, 1, 48)
                    .unwrap(),
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

        let response = ResponseElements {
            issuer: String::from("http://idp.example.com/metadata.php"),
            response_id: String::from("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"),
            issue_instant: DateTime::<Utc>::from_naive_utc_and_offset(
                NaiveDate::from_ymd_opt(2014, 7, 17)
                    .unwrap()
                    .and_hms_opt(1, 1, 48)
                    .unwrap(),
                Utc,
            ),
            relay_state: String::from("ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"),
            attributes: responseattributes,
            destination: String::from("http://sp.example.com/demo1/index.php?acs"),
            authnstatement,
            assertion_id: String::from("_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"),
            service_provider: saml_rs::sp::ServiceProvider::test_generic("sp.example.com"),
            assertion_consumer_service: Some(String::from(
                "http://sp.example.com/demo1/index.php?acs",
            )),
            session_length_seconds: 1,
            status: saml_rs::constants::StatusCode::Success,
            sign_assertion,
            sign_message,
            signing_key: PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap(),
            signing_cert: Some(saml_rs::cert::gen_self_signed_certificate("idp.example.com")),
            signing_algorithm: SigningAlgorithm::Sha256,
            digest_algorithm: DigestAlgorithm::Sha256,
            canonicalization_method,
        };
        String::from_utf8(response.into()).unwrap()
    }

    #[test]
    fn assertion_only_signs_assertion() {
        let xml = build_response(true, false, CanonicalizationMethod::ExclusiveCanonical10);
        let assertion_start = xml.find("<saml:Assertion").unwrap();
        let response_segment = &xml[..assertion_start];
        let assertion_segment = &xml[assertion_start..];
        assert!(!response_segment.contains("<ds:Signature"));
        assert!(assertion_segment.contains("<ds:Signature"));
    }

    #[test]
    fn message_only_signs_response_message() {
        let xml = build_response(false, true, CanonicalizationMethod::ExclusiveCanonical10);
        let assertion_start = xml.find("<saml:Assertion").unwrap();
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
}
