//! Certificate and signing-related things

// #![deny(unsafe_code)]

use openssl;
use openssl::x509::{X509NameBuilder, X509};

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

    let decoded = base64::decode(buf);

    match decoded {
        Err(error) => {
            eprintln!("base64 decode error: {:?}", error);
            Err(CertParseError)
        }
        Ok(value) => match X509::from_der(&value) {
            Ok(value) => Ok(value),
            Err(error) => {
                eprintln!("Error parsing DER cert: {:?}", error);
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
pub fn strip_cert_headers(cert_string: String) -> String {
    cert_string
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .trim()
        .to_string()
}

/// generates a really terrible self-signed certificate for testing purposes
pub fn gen_self_signed_certificate(hostname: &str) -> X509 {
    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "AU").unwrap();
    x509_name.append_entry_by_text("ST", "Woo").unwrap();
    x509_name
        .append_entry_by_text("O", "Example organization")
        .unwrap();
    x509_name.append_entry_by_text("CN", &hostname).unwrap();
    let x509_name = x509_name.build();

    let mut x509 = X509::builder().unwrap();
    x509.set_subject_name(&x509_name).unwrap();

    x509.build()
}
