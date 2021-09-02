//#! Testing my hashing skills
// input from

#[cfg(test)]
pub mod test {

    use saml_rs::sign::DigestAlgorithm;
    use saml_rs::utils::to_hex_string;

    #[test]
    /// Tests that we're doing digests the same as the reference examples here: <https://www.di-mgt.com.au/xmldsig2.html#twotypes>
    fn test_hash_digest() {
        println!("Starting up");
        /*
        The SHA-1 digest of this data is (0x)516b984d8ba0d7427593984a7e89f1b6182b011f or UWuYTYug10J1k5hKfonxthgrAR8= in base64.
        */

        let test_envelope = "<Envelope xmlns=\"http://example.org/envelope\">\n  <Body>\n    Olá mundo\n  </Body>\n  \n</Envelope>";

        let result_hexes = to_hex_string(test_envelope.as_bytes().to_vec(), Some(""));
        println!("test_envelope raw:\n{:?}", test_envelope);
        println!("test_envelope as bytes: {:?}", test_envelope.as_bytes());
        println!("test_envelope as hexes: {:?}", result_hexes);

        let expected_result_hexes = "3c456e76656c6f706520786d6c6e733d22687474703a2f2f6578616d706c652e6f72672f656e76656c6f7065223e0a20203c426f64793e0a202020204f6cc3a1206d756e646f0a20203c2f426f64793e0a20200a3c2f456e76656c6f70653e";
        println!("expected_rslt as hexes: {:?}", expected_result_hexes);
        println!("Matches? {:?}", result_hexes == expected_result_hexes);

        // let mut hasher = Sha1::new();
        // hasher.update(test_envelope.as_bytes());
        // let result = openssl::hash::Hasher
        // use openssl::hash::{hash, MessageDigest};

        // let data = b"\x42\xF4\x97\xE0";
        // let spec = b"\x7c\x43\x0f\x17\x8a\xef\xdf\x14\x87\xfe\xe7\x14\x4e\x96\x41\xe2";
        // let result = hash(MessageDigest::sha1(), ).unwrap();
        let result = DigestAlgorithm::Sha1
            .hash(test_envelope.as_bytes())
            .unwrap();
        // assert_eq!(&*res, spec);
        // let result = hasher.finalize();
        let base64_bytes = base64::encode(result);
        use hex::FromHex;

        let digest_from_example_base64 = "UWuYTYug10J1k5hKfonxthgrAR8=";
        let digest_from_example_bytes = base64::decode(&digest_from_example_base64).unwrap();

        eprintln!();
        eprintln!("digest_from_example_base64: {}", digest_from_example_base64);
        eprintln!(
            "digest_from_example_bytes: {:?}",
            &digest_from_example_bytes
        );
        eprintln!(
            "digest_from_example_bytes: {:?}",
            to_hex_string(digest_from_example_bytes, Some("")).to_lowercase()
        );
        // eprintln!("digest_from_example_bytes: {:#X}", u128::from_be_bytes(&digest_from_example_bytes[..]));
        // eprintln!("digest_from_example_bytes: {}", digest_from_example_bytes);

        let fromhex = Vec::from_hex("516b984d8ba0d7427593984a7e89f1b6182b011f").unwrap();
        eprintln!("\ndigest bytes: {:?}", &result[..]);
        eprintln!("should match: {:?}", &fromhex);
        eprintln!("matches: {:?}", result[..] == fromhex);
        assert_eq!(result[..], fromhex);

        eprintln!("\nbase64 bytes: {}", base64_bytes);
        eprintln!("should match: UWuYTYug10J1k5hKfonxthgrAR8=");
        eprintln!(
            "matches: {:?}",
            base64_bytes == "UWuYTYug10J1k5hKfonxthgrAR8="
        );
        assert_eq!(base64_bytes, "UWuYTYug10J1k5hKfonxthgrAR8=");
    }
}

/*
Compose the canonicalized SignedInfo element and compute its SignatureValue

The canonicalized version of the SignedInfo element is as follows, with newlines shown as  and leading spaces shown as  :

<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>
        <DigestValue>UWuYTYug10J1k5hKfonxthgrAR8=</DigestValue>
      </Reference>
    </SignedInfo>

These 626 bytes are shown in this hexdump. Note that:

    The first character is "<" and the last character is ">".
    All leading space characters inbetween (shown as  ) are retained.
    Empty elements of the form <tag /> are changed to the form <tag></tag>
    Line-endings are converted to the LF character (0x0A).
    The namespace xmlns="http://www.w3.org/2000/09/xmldsig#" is propagated down from the parent Signature element. This "over-rules" the default namespace from the Envelope element.

The SHA-1 digest of this is (0x)a25a06d339d68b625cd7383a932357889956a54e or oloG0znWi2Jc1zg6kyNXiJlWpU4= in base64, and the SignatureValue computed using Alice's RSA key is

TSQUoVrQ0kg1eiltNwIhKPrIdsi1VhWjYNJlXvfQqW2EKk3X37X862SCfrz7v8IYJ7OorWwlFpGDStJDSR6saO
ScqSvmesCrGEEq+U6zegR9nH0lvcGZ8Rvc/y7U9kZrE4fHqEiLyfpmzJyPmWUT9Uta14nPJYsl3cmdThHB8Bs=
*/

//   let test_string = String::from(r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
//   <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></CanonicalizationMethod>
//   <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod>
//   <Reference URI="">
//     <Transforms>
//       <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform>
//     </Transforms>
//     <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod>
//     <DigestValue>UWuYTYug10J1k5hKfonxthgrAR8=</DigestValue>
//   </Reference>
// </SignedInfo>"#);

//   println!("{}", test_string);

//     println!("Done!");
// }
