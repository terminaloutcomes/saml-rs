#[cfg(test)]
mod tests {
    use saml_rs;
    use saml_rs::metadata::SamlMetadata;

    #[test]
    /// tests saml_rs::metadata::SamlMetadata::new()
    fn metadata_new_set_foo_example_com() {
        let test_metadata = SamlMetadata::new("foo.example.com", None, None, None, None, None);

        assert_eq!(test_metadata.hostname, String::from("foo.example.com"));
        assert_eq!(
            test_metadata.baseurl,
            String::from("https://foo.example.com/SAML")
        );
        assert_eq!(
            test_metadata.entity_id,
            String::from("https://foo.example.com/SAML/idp")
        );
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
        );
        assert_eq!(
            test_metadata.logout_url(),
            String::from("https://foo.example.com/SAML/fooooooo")
        );
    }
    #[test]
    /// tests saml_rs::metadata::SamlMetadata::from_hostname()
    fn metadata_from_hostname_foo_example_com() {
        let test_metadata = SamlMetadata::from_hostname("foo.example.com");

        assert_eq!(test_metadata.hostname, String::from("foo.example.com"));
        assert_eq!(
            test_metadata.baseurl,
            String::from("https://foo.example.com/SAML")
        );
        assert_eq!(
            test_metadata.entity_id,
            String::from("https://foo.example.com/SAML/idp")
        );
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

        let test_metadata = SamlMetadata::from_hostname("foo.example.com");
        assert_ne!(test_metadata.hostname, String::from("zot.example.com"));
    }

    #[test]
    fn test_parse_saml_xml_authn_request() {
        let test_parse =
            saml_rs::parse_authn_request(saml_rs::test_samples::TEST_AUTHN_REQUEST_EXAMPLE_COM);
        let result = match test_parse {
            Ok(value) => value,
            Err(error) => {
                panic!("Failed to parse test sample, this seems bad: {}", error);
            }
        };

        let expected_result = saml_rs::SamlAuthnRequest {
            request_id: String::from("_6c1cd5d32c2df1bab98f58a144f9b971"),
            issuer: String::from("https://samltest.id/saml/sp"),
            issue_instant: String::from("2021-07-19T12:06:25Z"),
            consumer_service_url: String::from("https://samltest.id/Shibboleth.sso/SAML2/POST"),
            version: String::from("2.0"),
            destination: String::from("https://example.com/v1/SAML/Redirect"),
        };
        assert_eq!(
            result.request_id,
            String::from("_6c1cd5d32c2df1bab98f58a144f9b971")
        );
        assert_eq!(result.request_id, expected_result.request_id);
        assert_eq!(result.issuer, expected_result.issuer);
        assert_eq!(result.issue_instant, expected_result.issue_instant);
        assert_eq!(
            result.consumer_service_url,
            expected_result.consumer_service_url
        );
        assert_eq!(result.version, expected_result.version);
    }

    /// tests parsing saml_rs::test_samples::TEST_AUTHN_REQUEST_EXAMPLE_COM_BASE64_DEFLATED
    #[test]
    #[should_panic]
    fn test_parse_test_parse_saml_base64_authn_request() {
        // TODO: This is silly and should be fixed
        match saml_rs::parse_authn_request(
            saml_rs::test_samples::TEST_AUTHN_REQUEST_EXAMPLE_COM_BASE64_DEFLATED,
        ) {
            Ok(_) => panic!(),
            Err(_) => assert_eq!(1, 1),
        }
    }
}
