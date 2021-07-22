
#[cfg(test)]
mod tests {
    use saml_rs;
    use difference::{Difference, Changeset};


    use saml_rs::test_samples::TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION;
    use saml_rs::response::create_response;
    use std::str::from_utf8;
    #[test]
    /// tests saml_rs::metadata::SamlMetadata::new()
    fn metadata_new_set_foo_example_com() {
        let response_vec: Vec<u8> = create_response(
            String::from("http://idp.example.com/metadata.php").to_string(),
        );

        let response = from_utf8(&response_vec).unwrap();

        let changeset = Changeset::new(
            TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION,
            response,
            " ");
        println!("{}", changeset);
        assert_eq!(changeset.diffs, vec![
            Difference::Same("<saml".to_string()),
            // Difference::Rem("s".to_string()),
            // Difference::Add("n".to_string()),
            // Difference::Same("t".to_string())
        ]);

    }
}