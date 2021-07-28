//! Certificate and signing-related things

#![deny(unsafe_code)]

use openssl;

use std::fmt;

#[derive(Debug)]
pub struct CertParseError;

impl fmt::Display for CertParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to handle certificate")
    }
}

impl std::error::Error for CertParseError {}

/// this is a terrible function and only used for me to figure out how to parse out the cert from an SP Metadata file
pub fn init_cert_from_base64(buf: &str) -> Result<openssl::x509::X509, CertParseError> {
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
        Ok(value) => match openssl::x509::X509::from_der(&value) {
            Ok(value) => Ok(value),
            Err(error) => {
                eprintln!("Error parsing DER cert: {:?}", error);
                Err(CertParseError)
            }
        },
    }

    // let mut buf = Vec::new();
    // File::open("my_cert.pem")?
    // .read_to_end(&mut buf)?;
    // let cert = reqwest::Certificate::from_pem(&buf)?;
}

/* cert validation things

https://docs.rs/openssl/0.10.35/openssl/pkey/index.html

*/

pub fn strip_cert_headers(cert_string: String) -> String {
    cert_string
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
}
