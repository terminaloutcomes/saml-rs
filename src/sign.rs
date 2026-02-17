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

use log::debug;
use log::error;
use log::info;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use std::fmt;

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
            SigningAlgorithm::InvalidAlgorithm => {
                error!("Invalid signing algorithm requested, falling back to SHA-256");
                openssl::hash::MessageDigest::sha256()
            }
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
                error!("{}", result);
                result
            }
        }
    }
}

fn read_file_bytes(path: &str) -> Result<Vec<u8>, String> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(value) => value,
        Err(error) => return Err(format!("Failed to create tokio runtime: {:?}", error)),
    };
    runtime
        .block_on(tokio::fs::read(path))
        .map_err(|error| format!("Failed to read {}: {:?}", path, error))
}

async fn read_file_bytes_async(path: &str) -> Result<Vec<u8>, String> {
    tokio::fs::read(path)
        .await
        .map_err(|error| format!("Failed to read {}: {:?}", path, error))
}

/// Loads a PEM-encoded public key into a PKey object
pub fn load_key_from_filename(key_filename: &str) -> Result<PKey<Private>, String> {
    let pkey_buffer = match read_file_bytes(key_filename) {
        Ok(value) => value,
        Err(error) => return Err(format!("Error loading file {}: {}", key_filename, error)),
    };
    info!("Read private key OK");

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

/// Async version of [load_key_from_filename] for callers that already run inside a tokio runtime.
pub async fn load_key_from_filename_async(key_filename: &str) -> Result<PKey<Private>, String> {
    let pkey_buffer = match read_file_bytes_async(key_filename).await {
        Ok(value) => value,
        Err(error) => return Err(format!("Error loading file {}: {}", key_filename, error)),
    };
    info!("Read private key OK");

    debug!("key:  {}", key_filename);
    let keypair = match Rsa::private_key_from_pem(&pkey_buffer) {
        Ok(value) => value,
        Err(error) => {
            return Err(format!("Failed to load pkey from pem bytes: {:?}", error));
        }
    };

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
            DigestAlgorithm::InvalidAlgorithm => {
                error!("Invalid digest algorithm requested, falling back to SHA-256");
                openssl::hash::MessageDigest::sha256()
            }
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
                error!("{}", result);
                result
            }
        }
    }
}

/// Loads a public cert from a PEM file into an X509 object
pub fn load_public_cert_from_filename(cert_filename: &str) -> Result<X509, String> {
    debug!("loading cert:  {}", cert_filename);

    let cert_buffer = match read_file_bytes(cert_filename) {
        Ok(value) => value,
        Err(error) => {
            return Err(format!(
                "Error loading certificate file {}: {}",
                cert_filename, error
            ));
        }
    };
    eprintln!("Read certificate OK");

    match X509::from_pem(&cert_buffer) {
        Ok(value) => Ok(value),
        Err(error) => Err(format!(
            "Failed to load certificate from pem bytes: {:?}",
            error
        )),
    }
}

/// Async version of [load_public_cert_from_filename] for callers that already run inside a tokio runtime.
pub async fn load_public_cert_from_filename_async(cert_filename: &str) -> Result<X509, String> {
    debug!("loading cert:  {}", cert_filename);

    let cert_buffer = match read_file_bytes_async(cert_filename).await {
        Ok(value) => value,
        Err(error) => {
            return Err(format!(
                "Error loading certificate file {}: {}",
                cert_filename, error
            ));
        }
    };
    eprintln!("Read certificate OK");

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
                error!("Failed to hash bytes: {:?}", error);
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
    let mut signer = match Signer::new(signing_algorithm, signing_key) {
        Ok(value) => value,
        Err(error) => {
            error!("Failed to create signer: {:?}", error);
            return Vec::new();
        }
    };
    if let Err(error) = signer.update(bytes_to_sign) {
        error!("Failed to update signer: {:?}", error);
        return Vec::new();
    }

    let signature = match signer.sign_to_vec() {
        Ok(value) => value,
        Err(error) => {
            error!("Failed to sign data: {:?}", error);
            return Vec::new();
        }
    };
    debug!("Signature: {:?}", signature);

    // Verify the data
    match Verifier::new(signing_algorithm, signing_key) {
        Ok(mut verifier) => {
            if let Err(error) = verifier.update(bytes_to_sign) {
                error!("Failed to update verifier: {:?}", error);
            } else {
                match verifier.verify(&signature) {
                    Ok(true) => debug!("Signature verification succeeded"),
                    Ok(false) => error!("Signature verification failed"),
                    Err(error) => error!("Signature verification errored: {:?}", error),
                }
            }
        }
        Err(error) => error!("Failed to create verifier: {:?}", error),
    }

    signature
}
