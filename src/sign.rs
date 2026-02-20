//! Functions for signing data
//!
//! Here be crypto-dragons.
//!
//! - <https://stackoverflow.com/questions/6960886/sign-saml-response-with-or-without-assertion-signature/7073749#7073749>
//!
//! SAML is awful, every time I read answers they are almost correct, here is the correct algorithm distilled:
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
//! That's it. SAML is completely awful. There are tons of little subtleties that make implementing SAML a nightmare (like calculating the canonical form of a subset of the XML (the assertion), also the XML version of XML documents is not included.
//!

use log::debug;
use log::error;
use log::info;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::x509::X509;
use std::fmt;
use xml_c14n::{CanonicalizationMode, CanonicalizationOptions, canonicalize_xml};

/// Options of Signing Algorithms for things
///
/// <https://www.w3.org/TR/xmldsig-core/#sec-PKCS1>
#[derive(Copy, Clone, Debug)]
pub enum SigningAlgorithm {
    /// SHA1 algorithm.
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

/// Content encryption algorithms for SAML assertion encryption
///
/// <https://www.w3.org/TR/xmldsig-core/#sec-PKCS1>
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug)]
pub enum ContentEncryptionAlgorithm {
    /// AES-128-CBC with HMAC-SHA-256
    A128CBC_HS256,
    /// AES-256-CBC with HMAC-SHA-512 (default)
    A256CBC_HS512,
    /// AES-128-GCM
    A128GCM,
    /// AES-256-GCM
    A256GCM,
}

impl ContentEncryptionAlgorithm {
    /// Returns the URI for this algorithm
    pub fn as_uri(&self) -> &'static str {
        match self {
            ContentEncryptionAlgorithm::A128CBC_HS256 => {
                "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
            }
            ContentEncryptionAlgorithm::A256CBC_HS512 => {
                "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
            }
            ContentEncryptionAlgorithm::A128GCM => "http://www.w3.org/2001/04/xmlenc#aes128-gcm",
            ContentEncryptionAlgorithm::A256GCM => "http://www.w3.org/2001/04/xmlenc#aes256-gcm",
        }
    }
}

/// Key encryption algorithms for SAML assertion encryption
#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum KeyEncryptionAlgorithm {
    /// RSAES-OAEP with SHA-1 (deprecated but sometimes required)
    RSA_OAEP,
    /// RSAES-OAEP with SHA-256 (default)
    RSA_OAEP_256,
    /// RSAES-OAEP with SHA-384
    RSA_OAEP_384,
    /// RSAES-OAEP with SHA-512
    RSA_OAEP_512,
    /// ECDH-ES with AES-KW 128-bit key
    ECDH_ES_AES_KW_128,
    /// ECDH-ES with AES-KW 192-bit key
    ECDH_ES_AES_KW_192,
    /// ECDH-ES with AES-KW 256-bit key
    ECDH_ES_AES_KW_256,
}

impl KeyEncryptionAlgorithm {
    /// Gets the padding scheme for a given key encryption algorithm
    pub fn as_rsa_padding(&self) -> Option<Box<rsa::Oaep>> {
        match self {
            Self::RSA_OAEP_512 => Some(Box::new(rsa::Oaep::new::<sha2::Sha512>())),
            Self::RSA_OAEP_384 => Some(Box::new(rsa::Oaep::new::<sha2::Sha384>())),
            Self::RSA_OAEP_256 => Some(Box::new(rsa::Oaep::new::<sha2::Sha256>())),
            _ => None, // For unsupported algorithms, return None
        }
    }

    /// Encrypts data using this key encryption algorithm and the provided public key.
    pub fn encrypt_rsa(
        self,
        data: &[u8],
        public_key: &rsa::RsaPublicKey,
    ) -> Result<Vec<u8>, rsa::Error> {
        let mut rng = aes_gcm::aead::OsRng;
        let padding = *self.as_rsa_padding().ok_or(rsa::Error::InvalidArguments)?;
        let encrypted_data = public_key.encrypt(&mut rng, padding, data)?;

        Ok(encrypted_data)
    }

    /// Decrypts data
    pub fn decrypt_rsa(
        &self,
        encrypted_data: &[u8],
        private_key: &rsa::RsaPrivateKey,
    ) -> Result<Vec<u8>, rsa::Error> {
        let oaep = *self.as_rsa_padding().ok_or(rsa::Error::InvalidArguments)?;
        private_key.decrypt(oaep, encrypted_data)
    }

    /// Returns the URI for this algorithm
    pub fn as_uri(&self) -> &'static str {
        match self {
            KeyEncryptionAlgorithm::RSA_OAEP => "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            KeyEncryptionAlgorithm::RSA_OAEP_256 => {
                "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p#sha256"
            }
            KeyEncryptionAlgorithm::RSA_OAEP_384 => {
                "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p#sha384"
            }
            KeyEncryptionAlgorithm::RSA_OAEP_512 => {
                "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p#sha512"
            }
            KeyEncryptionAlgorithm::ECDH_ES_AES_KW_128 => {
                "http://www.w3.org/2001/04/xmlenc#ECDH-ES"
            }
            KeyEncryptionAlgorithm::ECDH_ES_AES_KW_192 => {
                "http://www.w3.org/2001/04/xmlenc#ECDH-ES"
            }
            KeyEncryptionAlgorithm::ECDH_ES_AES_KW_256 => {
                "http://www.w3.org/2001/04/xmlenc#ECDH-ES"
            }
        }
    }
}

impl SigningAlgorithm {
    fn message_digest(self) -> Result<openssl::hash::MessageDigest, String> {
        match self {
            SigningAlgorithm::Sha1 => {
                if crate::security::weak_algorithms_allowed() {
                    Ok(openssl::hash::MessageDigest::sha1())
                } else {
                    Err("SHA-1 signing algorithms are disabled by default".to_string())
                }
            }
            SigningAlgorithm::Sha224 => Ok(openssl::hash::MessageDigest::sha224()),
            SigningAlgorithm::Sha256 => Ok(openssl::hash::MessageDigest::sha256()),
            SigningAlgorithm::Sha384 => Ok(openssl::hash::MessageDigest::sha384()),
            SigningAlgorithm::Sha512 => Ok(openssl::hash::MessageDigest::sha512()),
            SigningAlgorithm::InvalidAlgorithm => Err(
                "Invalid signing algorithm requested and strict policy forbids fallback"
                    .to_string(),
            ),
        }
    }
}

/// Canonicalization methods supported for XML signatures.
#[derive(Copy, Clone, Debug, Default)]
pub enum CanonicalizationMethod {
    /// Exclusive Canonical XML 1.0 (`xml-exc-c14n`).
    #[default]
    ExclusiveCanonical10,
    /// Canonical XML 1.0 (inclusive).
    InclusiveCanonical10,
}

impl CanonicalizationMethod {
    /// Canonicalize XML bytes according to this method.
    pub fn canonicalize(self, input_xml: &str) -> Result<String, String> {
        let mode = match self {
            Self::ExclusiveCanonical10 => CanonicalizationMode::ExclusiveCanonical1_0,
            Self::InclusiveCanonical10 => CanonicalizationMode::Canonical1_0,
        };
        canonicalize_xml(
            input_xml,
            CanonicalizationOptions {
                mode,
                keep_comments: false,
                inclusive_ns_prefixes: vec![],
            },
        )
        .map_err(|error| format!("Failed to canonicalize XML: {:?}", error))
    }
}

impl From<CanonicalizationMethod> for String {
    fn from(method: CanonicalizationMethod) -> String {
        match method {
            CanonicalizationMethod::ExclusiveCanonical10 => {
                String::from("http://www.w3.org/2001/10/xml-exc-c14n#")
            }
            CanonicalizationMethod::InclusiveCanonical10 => {
                String::from("http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
            }
        }
    }
}

impl From<String> for CanonicalizationMethod {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "inclusive" | "http://www.w3.org/tr/2001/rec-xml-c14n-20010315" => {
                Self::InclusiveCanonical10
            }
            _ => Self::ExclusiveCanonical10,
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
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Self::Sha1,
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
            SigningAlgorithm::Sha1 => String::from("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
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
    fn message_digest(self) -> Result<openssl::hash::MessageDigest, String> {
        match self {
            DigestAlgorithm::Sha1 => {
                if crate::security::weak_algorithms_allowed() {
                    Ok(openssl::hash::MessageDigest::sha1())
                } else {
                    Err("SHA-1 digest algorithms are disabled by default".to_string())
                }
            }
            DigestAlgorithm::Sha224 => Ok(openssl::hash::MessageDigest::sha224()),
            DigestAlgorithm::Sha256 => Ok(openssl::hash::MessageDigest::sha256()),
            DigestAlgorithm::Sha384 => Ok(openssl::hash::MessageDigest::sha384()),
            DigestAlgorithm::Sha512 => Ok(openssl::hash::MessageDigest::sha512()),
            DigestAlgorithm::InvalidAlgorithm => Err(
                "Invalid digest algorithm requested and strict policy forbids fallback".to_string(),
            ),
        }
    }

    /// Hash a set of bytes using an [openssl::hash::MessageDigest]
    ///
    pub fn hash(
        self,
        bytes_to_hash: &[u8],
    ) -> Result<openssl::hash::DigestBytes, openssl::error::ErrorStack> {
        let digest = self
            .message_digest()
            .map_err(|_| openssl::error::ErrorStack::get())?;
        // do the hashy bit
        match openssl::hash::hash(digest, bytes_to_hash) {
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
/// Sign some data with a private key.
pub fn sign_data(
    signing_algorithm: crate::sign::SigningAlgorithm,
    signing_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    bytes_to_sign: &[u8],
) -> Vec<u8> {
    let signing_algorithm = match signing_algorithm.message_digest() {
        Ok(value) => value,
        Err(error) => {
            error!("{}", error);
            return Vec::new();
        }
    };
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

    match signer.sign_to_vec() {
        Ok(value) => value,
        Err(error) => {
            error!("Failed to sign data: {:?}", error);
            Vec::new()
        }
    }
}

/// Verify a signature over bytes with a public key.
pub fn verify_data(
    signing_algorithm: crate::sign::SigningAlgorithm,
    verification_key: &openssl::pkey::PKey<Public>,
    bytes_to_verify: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let signing_algorithm = signing_algorithm.message_digest()?;
    let mut verifier = Verifier::new(signing_algorithm, verification_key)
        .map_err(|error| format!("Failed to create verifier: {:?}", error))?;
    verifier
        .update(bytes_to_verify)
        .map_err(|error| format!("Failed to update verifier: {:?}", error))?;
    verifier
        .verify(signature)
        .map_err(|error| format!("Failed to verify signature: {:?}", error))
}

/// Verify a signature over bytes with an X509 certificate.
pub fn verify_data_with_cert(
    signing_algorithm: crate::sign::SigningAlgorithm,
    certificate: &X509,
    bytes_to_verify: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let public_key = certificate
        .public_key()
        .map_err(|error| format!("Failed to extract public key from cert: {:?}", error))?;
    verify_data(signing_algorithm, &public_key, bytes_to_verify, signature)
}
