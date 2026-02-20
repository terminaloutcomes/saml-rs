//! Extensions for things and generic utilities

use chrono::{DateTime, SecondsFormat, Utc};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Extensions for [chrono::DateTime] for nicer functionality
pub trait DateTimeUtils {
    /// return a DateTime object as a string
    fn to_saml_datetime_string(&self) -> String;
}

impl DateTimeUtils for DateTime<Utc> {
    /// return a DateTime object as a string
    fn to_saml_datetime_string(&self) -> String {
        self.to_rfc3339_opts(SecondsFormat::Secs, true)
    }
}

/// Takes a [Vec<u8>] and turns it into a [String]
///
/// With an optional "join" string to allow you to space it out etc.
///
/// From <https://illegalargumentexception.blogspot.com/2015/05/rust-byte-array-to-hex-string.html>
pub fn to_hex_string(bytes: &[u8], join: Option<&str>) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|b| format!("{:02X}", b).to_lowercase())
        .collect();
    match join {
        Some(joinval) => strs.join(joinval),
        None => strs.join(""),
    }
}

/// Generates a new RSA key pair for testing purposes.
pub fn generate_keypair() -> Result<(RsaPrivateKey, RsaPublicKey), rsa::errors::Error> {
    let mut rng = aes_gcm::aead::OsRng;
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits)?;
    let pub_key = RsaPublicKey::from(&priv_key);

    Ok((priv_key, pub_key))
}
