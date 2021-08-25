//! Functions for signing data
//!
//! Here be crypto-dragons.
//!
//! - <https://stackoverflow.com/questions/6960886/sign-saml-response-with-or-without-assertion-signature/7073749#7073749>
//!
//! SAML is awful, every time I read answer they are almost correct, here is the correct algorithm distilled:
//! 1. SHA1 the canonical version of the Assertion.
//! 2. Generate a SignedInfo XML fragment with the SHA1 signature
//! 3. Sign the SignedInfo XML fragment, again the canonical form
//! 4. Take the SignedInfo, the Signature and the key info and create a Signature XML fragment
//! 5. Insert this SignatureXML into the Assertion ( should go right before the saml:subject)
//! 6. Now take the assertion(with the signature included) and insert it into the Response
//! 7. SHA1 this response
//! 8. Generate a SignedInfo XML fragment with the SHA1 signature
//! 9. Sign the SignedInfo XML fragment, again the canonical form
//! 10. Take the SignedInfo, the Signature and the key info and create a Signature XML fragment
//! 11. Insert this SignatureXML into the Response
//! 12. Add the XML version info to the response.
//!
//! Thats it. SAML is completely awful. There are tons of little subtleties that make implementing SAML a nightmare(like calculating the canonical form of a subset of the XML(the assertion), also the XML version of XML documents is not included.
//!

use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

// use std::io;
use openssl::pkey::Private;
use openssl::x509::X509;
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;

/// Options of Signing Algorithms for things
#[derive(Clone, Debug)]
pub enum SigningAlgorithm {
    /// SHA1 Algorithm
    Sha1,
    /// SHA256 Algorithm
    Sha256,
}

// impl SigningAlgorithm {
//     fn as_str(self) -> &'static str {
//         format!("{}", self.to_string()).clone()
//     }
// }

impl FromStr for SigningAlgorithm {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha1" => Ok(SigningAlgorithm::Sha1),
            "sha256" => Ok(SigningAlgorithm::Sha256),
            _ => Err("invalid type"),
        }
    }
}

impl ToString for SigningAlgorithm {
    fn to_string(&self) -> String {
        match self {
            Self::Sha1 => "sha1".to_string(),
            Self::Sha256 => "sha256".to_string(),
        }
    }
}

/// Loads a PEM-encoded public key into a PKey object
pub fn load_key_from_filename(key_filename: &str) -> Result<PKey<Private>, String> {
    let mut f = match File::open(key_filename) {
        Ok(value) => value,
        Err(error) => return Err(format!("Error loading file {}: {:?}", &key_filename, error)),
    };
    let mut pkey_buffer = Vec::new();
    // read the whole file
    match f.read_to_end(&mut pkey_buffer) {
        Ok(_) => eprintln!("Read private key OK"),
        Err(error) => {
            return Err(format!("Failed to read private key? {:?}", error));
        }
    }

    debug!("key:  {}", key_filename);
    let keypair = match Rsa::private_key_from_pem(&pkey_buffer) {
        Ok(value) => value,
        Err(error) => {
            return Err(format!("Failed to load pkey from pem bytes: {:?}", error));
        }
    };
    // let keypair = Rsa::generate(2048).unwrap();
    match PKey::from_rsa(keypair) {
        Ok(value) => Ok(value),
        Err(error) => Err(format!("Failed to convert into PKey object: {:?}", error)),
    }
}

/// Loads a public cert from a PEM file into an X509 object
pub fn load_public_cert_from_filename(cert_filename: &str) -> Result<X509, String> {
    log::debug!("loading cert:  {}", cert_filename);

    let mut f = match File::open(&cert_filename) {
        Ok(value) => value,
        Err(error) => {
            return Err(format!(
                "Error loading certificate file {}: {:?}",
                &cert_filename, error
            ))
        }
    };

    let mut cert_buffer = Vec::new();
    // read the whole file
    // TODO: handle file read errors, but if we've gotten here without bailing then well, how'd the server start up?
    match f.read_to_end(&mut cert_buffer) {
        Ok(_) => eprintln!("Read certificate OK"),
        Err(error) => {
            return Err(format!("Failed to read cert? {:?}", error));
        }
    }

    match X509::from_pem(&cert_buffer) {
        Ok(value) => Ok(value),
        Err(error) => Err(format!(
            "Failed to load certificate from pem bytes: {:?}",
            error
        )),
    }
}

// TODO add some testing, and validation of sign_data
// TODO implement sign_data properly
/// Sign some data, with a key
pub fn sign_data(
    message_digest: openssl::hash::MessageDigest,
    signing_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    bytes_to_sign: &[u8],
) {
    // Sign the data

    let mut signer = Signer::new(message_digest, &signing_key).unwrap();
    signer.update(bytes_to_sign).unwrap();

    let signature = signer.sign_to_vec().unwrap();
    log::error!("Signature: {:?}", signature);

    // Verify the data
    let mut verifier = Verifier::new(message_digest, &signing_key).unwrap();
    verifier.update(bytes_to_sign).unwrap();
    // verifier.update(data2).unwrap();
    assert!(verifier.verify(&signature).unwrap());
    log::error!("Signed things, maybe?");

    use openssl::hash::hash;

    let digest_bytes = hash(message_digest, bytes_to_sign).unwrap();

    log::debug!("base64'd digest: {:?}", base64::encode(digest_bytes));

    log::debug!("base64'd signature: {:?}", base64::encode(signature));
}
