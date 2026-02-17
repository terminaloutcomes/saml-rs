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
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;

/// Options of Signing Algorithms for things
///
/// <https://www.w3.org/TR/xmldsig-core/#sec-PKCS1>
#[derive(Copy, Clone, Debug)]
pub enum SigningAlgorithm {
    // /// SHA1 Algorithm - nope
    // Sha1,
    /// Really?
    Sha224,
    /// SHA256 Algorithm
    Sha256,
    /// For when 256 isn't enough
    Sha384,
    /// Size does matter, I guess?
    Sha512,
    /// If you try to use the wrong one
    InvalidAlgorithm,
}

impl From<SigningAlgorithm> for openssl::hash::MessageDigest {
    fn from(src: SigningAlgorithm) -> openssl::hash::MessageDigest {
        match src {
            // SigningAlgorithm::Sha1 => openssl::hash::MessageDigest::sha1(),
            SigningAlgorithm::Sha224 => openssl::hash::MessageDigest::sha224(),
            SigningAlgorithm::Sha256 => openssl::hash::MessageDigest::sha256(),
            SigningAlgorithm::Sha384 => openssl::hash::MessageDigest::sha384(),
            SigningAlgorithm::Sha512 => openssl::hash::MessageDigest::sha512(),
            SigningAlgorithm::InvalidAlgorithm => panic!("How did you even get here?"),
        }
    }
}

// impl SigningAlgorithm {
//     fn as_str(self) -> &'static str {
//         format!("{}", self.to_string()).clone()
//     }
// }

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<String> for SigningAlgorithm {
    // type Err = &'static str;

    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            // "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Self::Sha1,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224" => Self::Sha224,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Self::Sha256,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Self::Sha384,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Self::Sha512,
            _ => Self::InvalidAlgorithm,
        }
    }
}

impl From<SigningAlgorithm> for String {
    fn from(sa: SigningAlgorithm) -> String {
        match sa {
            // SigningAlgorithm::Sha1 => String::from("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
            SigningAlgorithm::Sha224 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224")
            }
            SigningAlgorithm::Sha256 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            }
            SigningAlgorithm::Sha384 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")
            }
            SigningAlgorithm::Sha512 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")
            }
            _ => {
                let result = format!("Invalid Algorithm specified: {:?}", sa);
                log::error!("{}", result);
                result
            }
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

/// Options of Digest Algorithms for things
///
/// <https://www.w3.org/TR/xmldsig-core/#sec-AlgID>
#[derive(Copy, Clone, Debug)]
pub enum DigestAlgorithm {
    /// SHA1 Algorithm (Use is DISCOURAGED; see SHA-1 Warning)
    Sha1,
    /// Really?
    Sha224,
    /// SHA256 Algorithm
    Sha256,
    /// For when 256 isn't enough
    Sha384,
    /// Size does matter, I guess?
    Sha512,
    /// If you try to use the wrong one
    InvalidAlgorithm,
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<DigestAlgorithm> for openssl::hash::MessageDigest {
    fn from(src: DigestAlgorithm) -> openssl::hash::MessageDigest {
        match src {
            DigestAlgorithm::Sha1 => openssl::hash::MessageDigest::sha1(),
            DigestAlgorithm::Sha224 => openssl::hash::MessageDigest::sha224(),
            DigestAlgorithm::Sha256 => openssl::hash::MessageDigest::sha256(),
            DigestAlgorithm::Sha384 => openssl::hash::MessageDigest::sha384(),
            DigestAlgorithm::Sha512 => openssl::hash::MessageDigest::sha512(),
            DigestAlgorithm::InvalidAlgorithm => panic!("How did you even get here?"),
        }
    }
}

impl From<openssl::hash::MessageDigest> for DigestAlgorithm {
    fn from(_md: openssl::hash::MessageDigest) -> Self {
        Self::InvalidAlgorithm
    }
}

impl From<String> for DigestAlgorithm {
    fn from(s: String) -> Self {
        match s.to_lowercase().as_str() {
            "http://www.w3.org/2000/09/xmldsig#sha1" => Self::Sha1,
            "http://www.w3.org/2001/04/xmlenc#sha256" => Self::Sha256,

            "http://www.w3.org/2001/04/xmldsig-more#sha224" => Self::Sha224,
            "http://www.w3.org/2001/04/xmldsig-more#sha384" => Self::Sha384,
            "http://www.w3.org/2001/04/xmlenc#sha512" => Self::Sha512,
            _ => Self::InvalidAlgorithm,
        }
    }
}

impl From<DigestAlgorithm> for String {
    fn from(sa: DigestAlgorithm) -> String {
        match sa {
            DigestAlgorithm::Sha1 => String::from("http://www.w3.org/2000/09/xmldsig#sha1"),
            DigestAlgorithm::Sha256 => String::from("http://www.w3.org/2001/04/xmlenc#sha256"),

            DigestAlgorithm::Sha224 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#sha224")
            }
            DigestAlgorithm::Sha384 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#sha384")
            }
            DigestAlgorithm::Sha512 => String::from("http://www.w3.org/2001/04/xmlenc#sha512"),
            _ => {
                let result = format!("Invalid Algorithm specified: {:?}", sa);
                log::error!("{}", result);
                result
            }
        }
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

impl DigestAlgorithm {
    /// Hash a set of bytes using an [openssl::hash::MessageDigest]
    ///
    pub fn hash(
        self,
        bytes_to_hash: &[u8],
    ) -> Result<openssl::hash::DigestBytes, openssl::error::ErrorStack> {
        // do the hashy bit
        match openssl::hash::hash(self.into(), bytes_to_hash) {
            Ok(value) => {
                debug!("Hashed bytes result: {:?}", value);
                Ok(value)
            }
            Err(error) => {
                eprintln!("Failed to hash bytes: {:?}", error);
                Err(error)
            }
        }
    }
}
// TODO add some testing, and validation of sign_data
// TODO implement sign_data properly
/// Sign some data, with a key
pub fn sign_data(
    signing_algorithm: crate::sign::SigningAlgorithm,
    signing_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    bytes_to_sign: &[u8],
) -> Vec<u8> {
    // Sign the data

    let signing_algorithm: openssl::hash::MessageDigest = signing_algorithm.into();
    let mut signer = Signer::new(signing_algorithm, &signing_key).unwrap();
    signer.update(bytes_to_sign).unwrap();

    let signature = signer.sign_to_vec().unwrap();
    log::debug!("Signature: {:?}", signature);

    // Verify the data
    let mut verifier = Verifier::new(signing_algorithm, &signing_key).unwrap();
    verifier.update(bytes_to_sign).unwrap();
    // verifier.update(data2).unwrap();
    assert!(verifier.verify(&signature).unwrap());
    log::error!("Signed things, maybe?");

    signature
}
