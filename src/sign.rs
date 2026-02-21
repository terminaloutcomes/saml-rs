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

use k256::ecdsa::signature::{Signer as _, Verifier as _};
use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
use k256::pkcs8::{
    DecodePrivateKey as K256DecodePrivateKey, DecodePublicKey as K256DecodePublicKey,
};
use log::debug;
use log::error;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::rand_core;
use sha1::Digest as _;
use std::fmt;
use std::sync::Arc;
use tokio::fs;
use x509_cert::Certificate;
use x509_cert::der::{DecodePem, Encode};
use xml_c14n::{CanonicalizationMode, CanonicalizationOptions, canonicalize_xml};

use crate::error::SamlError;

/// Options of Signing Algorithms for things
///
/// <https://www.w3.org/TR/xmldsig-core/#sec-PKCS1>
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SigningAlgorithm {
    /// DSA with SHA1 (Use is DISCOURAGED; see SHA-1 Warning)
    DsaSha1,
    /// DSA with 256
    DsaSha256,
    /// SHA1 algorithm.
    RsaSha1,
    /// SHA224 algorithm.
    RsaSha224,
    /// SHA256 Algorithm
    RsaSha256,
    /// For when 256 isn't enough
    RsaSha384,
    /// Size does matter, I guess?
    RsaSha512,
    /// <http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1>
    EcDsaSha1,
    /// <http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224>
    EcDsaSha224,
    /// <http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256>
    EcDsaSha256,
    /// <http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384>
    EcDsaSha384,
    /// <http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512>
    EcDsaSha512,

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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
            Self::RSA_OAEP => Some(Box::new(rsa::Oaep::new::<sha1::Sha1>())),
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
    pub fn canonicalize(self, input_xml: &str) -> Result<String, SamlError> {
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
        .map_err(SamlError::from)
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
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Self::RsaSha1,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224" => Self::RsaSha224,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => Self::RsaSha256,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => Self::RsaSha384,
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => Self::RsaSha512,
            _ => Self::InvalidAlgorithm,
        }
    }
}

impl From<SigningAlgorithm> for String {
    fn from(sa: SigningAlgorithm) -> String {
        match sa {
            SigningAlgorithm::RsaSha1 => String::from("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
            SigningAlgorithm::RsaSha224 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224")
            }
            SigningAlgorithm::RsaSha256 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            }
            SigningAlgorithm::RsaSha384 => {
                String::from("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")
            }
            SigningAlgorithm::RsaSha512 => {
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

/// Loads a public cert from a PEM file into a Certificate
pub async fn load_public_cert_from_filename(cert_filename: &str) -> Result<Certificate, SamlError> {
    debug!("loading cert:  {}", cert_filename);

    let cert_buffer = fs::read(cert_filename).await?;

    Certificate::from_pem(&cert_buffer).map_err(SamlError::from)
}

impl DigestAlgorithm {
    /// Hash a set of bytes
    pub fn hash(self, bytes_to_hash: &[u8]) -> Result<Vec<u8>, SamlError> {
        if matches!(self, DigestAlgorithm::Sha1) && !crate::security::weak_algorithms_allowed() {
            return Err(SamlError::WeakAlgorithm(
                "SHA-1 digest is disabled by security policy".to_string(),
            ));
        }

        match self {
            DigestAlgorithm::Sha1 => Ok(sha1::Sha1::digest(bytes_to_hash).to_vec()),
            DigestAlgorithm::Sha224 => Ok(sha2::Sha224::digest(bytes_to_hash).to_vec()),
            DigestAlgorithm::Sha256 => Ok(sha2::Sha256::digest(bytes_to_hash).to_vec()),
            DigestAlgorithm::Sha384 => Ok(sha2::Sha384::digest(bytes_to_hash).to_vec()),
            DigestAlgorithm::Sha512 => Ok(sha2::Sha512::digest(bytes_to_hash).to_vec()),
            DigestAlgorithm::InvalidAlgorithm => Err(SamlError::UnsupportedAlgorithm(
                "Invalid digest algorithm requested and strict policy forbids fallback".to_string(),
            )),
        }
    }
}

fn rsa_digest_for_signing(
    signing_algorithm: SigningAlgorithm,
) -> Result<DigestAlgorithm, SamlError> {
    match signing_algorithm {
        SigningAlgorithm::RsaSha1 => Ok(DigestAlgorithm::Sha1),
        SigningAlgorithm::RsaSha224 => Ok(DigestAlgorithm::Sha224),
        SigningAlgorithm::RsaSha256 => Ok(DigestAlgorithm::Sha256),
        SigningAlgorithm::RsaSha384 => Ok(DigestAlgorithm::Sha384),
        SigningAlgorithm::RsaSha512 => Ok(DigestAlgorithm::Sha512),
        _ => Err(SamlError::UnsupportedAlgorithm(format!(
            "Unsupported RSA signing algorithm: {:?}",
            signing_algorithm
        ))),
    }
}

fn rsa_pkcs1v15_padding(signing_algorithm: SigningAlgorithm) -> Result<Pkcs1v15Sign, SamlError> {
    match signing_algorithm {
        SigningAlgorithm::RsaSha1 => {
            if !crate::security::weak_algorithms_allowed() {
                return Err(SamlError::WeakAlgorithm(
                    "SHA-1 signing is disabled by security policy".to_string(),
                ));
            }
            Ok(Pkcs1v15Sign::new_unprefixed())
        }
        SigningAlgorithm::RsaSha224 => Ok(Pkcs1v15Sign::new::<sha2::Sha224>()),
        SigningAlgorithm::RsaSha256 => Ok(Pkcs1v15Sign::new::<sha2::Sha256>()),
        SigningAlgorithm::RsaSha384 => Ok(Pkcs1v15Sign::new::<sha2::Sha384>()),
        SigningAlgorithm::RsaSha512 => Ok(Pkcs1v15Sign::new::<sha2::Sha512>()),
        _ => Err(SamlError::UnsupportedAlgorithm(format!(
            "Unsupported RSA signing algorithm: {:?}",
            signing_algorithm
        ))),
    }
}

fn is_ecdsa_algorithm(signing_algorithm: SigningAlgorithm) -> bool {
    matches!(
        signing_algorithm,
        SigningAlgorithm::EcDsaSha1
            | SigningAlgorithm::EcDsaSha224
            | SigningAlgorithm::EcDsaSha256
            | SigningAlgorithm::EcDsaSha384
            | SigningAlgorithm::EcDsaSha512
    )
}

/// Sign some data with a private key.
pub fn sign_data(
    signing_algorithm: crate::sign::SigningAlgorithm,
    signing_key: &Arc<SigningKey>,
    bytes_to_sign: &[u8],
) -> Result<Vec<u8>, SamlError> {
    if signing_key.is_none() {
        return Err(SamlError::NoKeyAvailable);
    }

    if matches!(
        signing_algorithm,
        SigningAlgorithm::RsaSha1 | SigningAlgorithm::DsaSha1 | SigningAlgorithm::EcDsaSha1
    ) && !crate::security::weak_algorithms_allowed()
    {
        return Err(SamlError::WeakAlgorithm(
            "SHA-1 signing is disabled by security policy".to_string(),
        ));
    }

    debug!("Signing data with algorithm: {:?}", signing_algorithm);
    debug!("Bytes to sign: {:?}", bytes_to_sign);

    let private_key = match signing_key.as_ref() {
        SigningKey::Rsa(key) => key,
        SigningKey::EcDsa256(key) => {
            if signing_algorithm != SigningAlgorithm::EcDsaSha256 {
                return Err(SamlError::UnsupportedAlgorithm(format!(
                    "Unsupported ECDSA signing algorithm for P-256 key: {:?}",
                    signing_algorithm
                )));
            }
            let signature: K256Signature = key.sign(bytes_to_sign);
            return Ok(signature.to_der().as_bytes().to_vec());
        }
        SigningKey::None => return Err(SamlError::NoKeyAvailable),
    };

    let digest_algorithm = rsa_digest_for_signing(signing_algorithm)?;
    let digest = digest_algorithm.hash(bytes_to_sign)?;
    let padding = rsa_pkcs1v15_padding(signing_algorithm)?;

    private_key.sign(padding, &digest).map_err(SamlError::from)
}

/// Verify a signature over bytes with a public key.
pub fn verify_data(
    signing_algorithm: crate::sign::SigningAlgorithm,
    verification_key: &Arc<SigningKey>,
    bytes_to_verify: &[u8],
    signature: &[u8],
) -> Result<bool, SamlError> {
    if matches!(
        signing_algorithm,
        SigningAlgorithm::RsaSha1 | SigningAlgorithm::DsaSha1 | SigningAlgorithm::EcDsaSha1
    ) && !crate::security::weak_algorithms_allowed()
    {
        return Err(SamlError::WeakAlgorithm(
            "SHA-1 verification is disabled by security policy".to_string(),
        ));
    }

    let private_key = match verification_key.as_ref() {
        SigningKey::None => return Err(SamlError::NoKeyAvailable),
        SigningKey::Rsa(key) => key,
        SigningKey::EcDsa256(key) => {
            if signing_algorithm != SigningAlgorithm::EcDsaSha256 {
                return Err(SamlError::UnsupportedAlgorithm(format!(
                    "Unsupported ECDSA verification algorithm for P-256 key: {:?}",
                    signing_algorithm
                )));
            }
            let signature = match K256Signature::from_der(signature) {
                Ok(value) => value,
                Err(_) => return Ok(false),
            };
            let verifying_key = key.verifying_key();
            return Ok(verifying_key.verify(bytes_to_verify, &signature).is_ok());
        }
    };

    let public_key = RsaPublicKey::from(private_key);
    let digest_algorithm = rsa_digest_for_signing(signing_algorithm)?;
    let digest = digest_algorithm.hash(bytes_to_verify)?;
    let padding = rsa_pkcs1v15_padding(signing_algorithm)?;

    match public_key.verify(padding, &digest, signature) {
        Ok(_) => Ok(true),
        Err(rsa::Error::Verification) => Ok(false),
        Err(err) => Err(SamlError::from(err)),
    }
}

/// Verify a signature over bytes with an X509 certificate.
pub fn verify_data_with_cert(
    signing_algorithm: crate::sign::SigningAlgorithm,
    certificate: &Certificate,
    bytes_to_verify: &[u8],
    signature: &[u8],
) -> Result<bool, SamlError> {
    if matches!(
        signing_algorithm,
        SigningAlgorithm::RsaSha1 | SigningAlgorithm::DsaSha1 | SigningAlgorithm::EcDsaSha1
    ) && !crate::security::weak_algorithms_allowed()
    {
        return Err(SamlError::WeakAlgorithm(
            "SHA-1 verification is disabled by security policy".to_string(),
        ));
    }

    let spki_der = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|error| {
            SamlError::Certificate(format!(
                "Failed to serialize certificate SubjectPublicKeyInfo: {:?}",
                error
            ))
        })?;
    if is_ecdsa_algorithm(signing_algorithm) {
        if signing_algorithm != SigningAlgorithm::EcDsaSha256 {
            return Err(SamlError::UnsupportedAlgorithm(format!(
                "Unsupported certificate verification algorithm: {:?}",
                signing_algorithm
            )));
        }
        let verifying_key =
            k256::ecdsa::VerifyingKey::from_public_key_der(&spki_der).map_err(|error| {
                SamlError::Certificate(format!(
                    "Failed to decode ECDSA public key from certificate: {:?}",
                    error
                ))
            })?;
        let parsed_signature = match K256Signature::from_der(signature) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        return Ok(verifying_key
            .verify(bytes_to_verify, &parsed_signature)
            .is_ok());
    }

    let digest_algorithm = rsa_digest_for_signing(signing_algorithm)?;
    let padding = rsa_pkcs1v15_padding(signing_algorithm)?;

    let public_key = RsaPublicKey::from_public_key_der(&spki_der)?;

    let digest = digest_algorithm.hash(bytes_to_verify)?;
    match public_key.verify(padding, &digest, signature) {
        Ok(_) => Ok(true),
        Err(rsa::Error::Verification) => Ok(false),
        Err(error) => Err(SamlError::from(error)),
    }
}

#[derive(Clone, Debug, Default)]
/// Internal Storage for the signing Key
#[allow(clippy::large_enum_variant)]
pub enum SigningKey {
    /// None
    #[default]
    None,
    /// RSA signing key
    Rsa(RsaPrivateKey),
    /// ECDSA P-256 signing key
    EcDsa256(K256SigningKey),
}

impl SigningKey {
    /// Load a PEM-encoded RSA private key file into a SigningKey
    pub fn rsa_from_pem(pem_data: &str) -> Result<Self, SamlError> {
        RsaPrivateKey::from_pkcs1_pem(pem_data)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(pem_data))
            .map(SigningKey::Rsa)
            .map_err(|error| {
                SamlError::Key(format!(
                    "Failed to parse RSA private key from PEM: {:?}",
                    error
                ))
            })
    }

    /// Load a PEM-encoded ECDSA P-256 private key file into a SigningKey
    pub fn ecdsa_from_pem(pem_data: &str) -> Result<Self, SamlError> {
        K256SigningKey::from_pkcs8_pem(pem_data)
            .map(SigningKey::EcDsa256)
            .map_err(|error| {
                SamlError::Key(format!(
                    "Failed to parse ECDSA private key from PEM (expected PKCS#8): {:?}",
                    error
                ))
            })
    }

    /// Check if this signing key is None
    pub fn is_none(&self) -> bool {
        matches!(self, SigningKey::None)
    }
}

impl From<RsaPrivateKey> for SigningKey {
    fn from(key: RsaPrivateKey) -> Self {
        SigningKey::Rsa(key)
    }
}

impl From<Vec<u8>> for SigningKey {
    fn from(pem_data: Vec<u8>) -> Self {
        let pem = std::str::from_utf8(&pem_data).unwrap_or("");
        if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem) {
            return SigningKey::Rsa(key);
        }
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem) {
            return SigningKey::Rsa(key);
        }
        if let Ok(key) = K256SigningKey::from_pkcs8_pem(pem) {
            return SigningKey::EcDsa256(key);
        }
        error!("Failed to parse signing key from PEM data");
        SigningKey::None
    }
}

/// Generates a private key for testing purposes
pub fn generate_private_key() -> RsaPrivateKey {
    let mut rng = rand_core::OsRng;
    #[allow(clippy::expect_used)] // because... we only use this in debug, right?
    RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate private key")
}
