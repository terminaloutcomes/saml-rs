//! Certificate and signing-related things

// #![deny(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use log::error;
use openssl;
use openssl::x509::{X509, X509NameBuilder};
use std::fmt;

#[derive(Debug)]
/// Error type for when parsing certificates from input
pub struct CertParseError;

impl fmt::Display for CertParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to handle certificate")
    }
}

impl std::error::Error for CertParseError {}

/// this is a terrible function and only used for me to figure out how to parse out the cert from an SP Metadata file
pub fn init_cert_from_base64(buf: &str) -> Result<X509, CertParseError> {
    let buf = buf.replace("\n", "").replace(" ", "");

    // let mut buf = Vec::new();
    // File::open("my_cert.der")?
    //     .read_to_end(&mut buf)?;

    let decoded = BASE64_STANDARD.decode(buf);

    match decoded {
        Err(error) => {
            error!("base64 decode error: {:?}", error);
            Err(CertParseError)
        }
        Ok(value) => match X509::from_der(&value) {
            Ok(value) => Ok(value),
            Err(error) => {
                error!("Error parsing DER cert: {:?}", error);
                Err(CertParseError)
            }
        },
    }
}

/* cert validation things

https://docs.rs/openssl/0.10.35/openssl/pkey/index.html

*/

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
pub fn gen_self_signed_certificate(hostname: &str) -> X509 {
    let mut x509_name = match X509NameBuilder::new() {
        Ok(value) => value,
        Err(error) => {
            error!("Failed to create x509 name builder: {:?}", error);
            std::process::exit(1)
        }
    };
    if let Err(error) = x509_name.append_entry_by_text("C", "AU") {
        error!("Failed to set x509 subject country: {:?}", error);
        std::process::exit(1);
    }
    if let Err(error) = x509_name.append_entry_by_text("ST", "Woo") {
        error!("Failed to set x509 subject state: {:?}", error);
        std::process::exit(1);
    }
    if let Err(error) = x509_name.append_entry_by_text("O", "Example organization") {
        error!("Failed to set x509 subject organization: {:?}", error);
        std::process::exit(1);
    }
    if let Err(error) = x509_name.append_entry_by_text("CN", hostname) {
        error!("Failed to set x509 subject common name: {:?}", error);
        std::process::exit(1);
    }
    let x509_name = x509_name.build();

    let mut x509 = match X509::builder() {
        Ok(value) => value,
        Err(error) => {
            error!("Failed to create x509 builder: {:?}", error);
            std::process::exit(1)
        }
    };
    if let Err(error) = x509.set_subject_name(&x509_name) {
        error!("Failed to set x509 subject name: {:?}", error);
        std::process::exit(1);
    }

    x509.build()
}
