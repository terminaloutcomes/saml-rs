#[cfg(test)]
mod tests {
    use difference::Changeset;

    use chrono::{DateTime, Duration, NaiveDate, Utc};

    use saml_rs::response::{create_response, AuthNStatement, ResponseAttribute, ResponseElements};
    use saml_rs::test_samples::TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION;
    use std::str::from_utf8;
    #[test]
    /// tests saml_rs::metadata::SamlMetadata::new()
    fn metadata_new_set_foo_example_com() {
        // Session up the AuthNStatement
        let authn_instant =
            DateTime::<Utc>::from_utc(NaiveDate::from_ymd(2014, 7, 17).and_hms(1, 1, 48), Utc);
        // 2024-07-17T09:01:48Z
        // adding three years including skip years
        let session_expiry = match DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd(2014, 7, 17).and_hms(9, 1, 48),
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
            ResponseAttribute::basic("uid", ["test".to_string()].to_vec().clone()),
            ResponseAttribute::basic("mail", ["test@example.com".to_string()].to_vec()),
            ResponseAttribute::basic(
                "eduPersonAffiliation",
                ["users".to_string(), "examplerole1".to_string()].to_vec(),
            ),
        ]
        .to_vec();

        let inputdata = ResponseElements {
            issuer: String::from("http://idp.example.com/metadata.php"),
            response_id: String::from("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"),
            // issue_instant: String::from("2014-07-17T01:01:48Z"),
            issue_instant: DateTime::<Utc>::from_utc(
                NaiveDate::from_ymd(2014, 7, 17).and_hms(1, 1, 48),
                Utc,
            ),
            request_id: String::from("ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"),
            attributes: responseattributes,
            destination: String::from("http://sp.example.com/demo1/index.php?acs"),
            authnstatement,
            assertion_id: String::from("_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"),
        };
        let response_vec: Vec<u8> = create_response(inputdata);

        let response = from_utf8(&response_vec).unwrap();

        let changeset = Changeset::new(
            &TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION.replace("\n", ""),
            &response.replace("\n", ""),
            " ",
        );
        println!("{}", changeset);
        // assert_eq!(changeset.diffs, vec![
        //     Difference::Same("<samlp:Response".to_string()),
        //     // Difference::Rem("s".to_string()),
        //     // Difference::Add("n".to_string()),
        //     // Difference::Same("t".to_string())
        // ]);
    }
}