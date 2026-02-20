//! Certificate and signing-related things

// #![deny(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use certkit::cert::params::{CertificationRequestInfo, DistinguishedName};
use std::fmt;
use x509_cert::Certificate;
use x509_cert::der::Decode;

#[derive(Debug)]
/// Error type for when parsing certificates from input
pub struct CertParseError(String);

impl fmt::Display for CertParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to handle certificate: {}", self.0)
    }
}

impl std::error::Error for CertParseError {}

/// this is a terrible function and only used for me to figure out how to parse out the cert from an SP Metadata file
pub fn init_cert_from_base64(buf: &str) -> Result<Certificate, CertParseError> {
    let buf = buf.replace("\n", "").replace(" ", "");

    let decoded = BASE64_STANDARD
        .decode(buf)
        .map_err(|err| CertParseError(format!("Base64 decode error: {:?}", err)))?;

    Certificate::from_der(&decoded)
        .map_err(|err| CertParseError(format!("Error parsing DER cert: {:?}", err)))
}

/// Strips `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` off a String,
/// good for including a certificate in an XML declaration for example
pub fn strip_cert_headers(cert_string: &str) -> String {
    cert_string
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .trim()
        .to_string()
}

/// generates a really terrible self-signed certificate for testing purposes
pub fn gen_self_signed_certificate(hostname: &str) -> Result<x509_cert::Certificate, String> {
    let key_pair = certkit::key::KeyPair::generate_rsa(2048).map_err(|err| err.to_string())?;

    let subject = DistinguishedName::builder()
        .common_name(hostname.to_string())
        .organization("Example organization".to_string())
        .country("AU".to_string())
        .state("QLD".to_string())
        .build();

    let cert_info = CertificationRequestInfo::builder()
        .subject(subject)
        .subject_public_key(certkit::key::PublicKey::from_key_pair(&key_pair))
        .build();

    let certificate = certkit::cert::Certificate::new_self_signed(&cert_info, &key_pair);
    Ok(certificate.inner)
}
