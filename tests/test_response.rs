
#[cfg(test)]
mod tests {
    use difference::{Changeset};
    // use difference::{Difference};


    use saml_rs::test_samples::TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION;
    use saml_rs::response::{create_response,ResponseAttribute,ResponseElements};
    use std::str::from_utf8;
    #[test]
    /// tests saml_rs::metadata::SamlMetadata::new()
    fn metadata_new_set_foo_example_com() {

        let responseattributes = [
            ResponseAttribute::basic("uid", ["test".to_string()].to_vec().clone()),
            ResponseAttribute::basic("mail", ["test@example.com".to_string()].to_vec()),
            ResponseAttribute::basic("eduPersonAffiliation",
                                                [
                                                "users".to_string(),
                                                "examplerole1".to_string(),
                                                ].to_vec()),
        ].to_vec();

        let inputdata = ResponseElements {
            issuer: String::from("http://idp.example.com/metadata.php"),
            id: String::from("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"),
            issue_instant: String::from("2014-07-17T01:01:48Z"),
            request_id: String::from("ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"),
            attributes: responseattributes,
            destination: String::from("http://sp.example.com/demo1/index.php?acs"),
        };
        let response_vec: Vec<u8> = create_response(
            inputdata
        );

        let response = from_utf8(&response_vec).unwrap();

        let changeset = Changeset::new(
            &TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION.replace("\n",""),
            &response.replace("\n",""),
            " ");
        println!("{}", changeset);
        // assert_eq!(changeset.diffs, vec![
        //     Difference::Same("<samlp:Response".to_string()),
        //     // Difference::Rem("s".to_string()),
        //     // Difference::Add("n".to_string()),
        //     // Difference::Same("t".to_string())
        // ]);

    }
}