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

/// Takes a set of bytes and turns it into a string of hex characters, with an optional "join" string in between each byte.
/// ```rust
/// use saml_rs::utils::to_hex_string;
///
/// let hex_string = to_hex_string(&[0x01, 0xAB, 0xFF], None);
/// assert_eq!(hex_string, "01abff");
/// let hex_string_joined = to_hex_string(&[0x01, 0xAB, 0xFF], Some(":"));
/// assert_eq!(hex_string_joined, "01:ab:ff");
/// let hex_string_joined = to_hex_string(&[0x01, 0xAB, 0xFF], Some("😍"));
/// assert_eq!(hex_string_joined, "01😍ab😍ff");
/// ```
///
/// With an optional "join" string to allow you to format it how you like.
///
pub fn to_hex_string(bytes: &[u8], join: Option<&str>) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b).to_lowercase())
        .collect::<Vec<String>>()
        .join(join.unwrap_or(""))
}

/// Generates a new RSA key pair for testing purposes.
pub fn generate_test_keypair() -> Result<(RsaPrivateKey, RsaPublicKey), rsa::errors::Error> {
    let mut rng = aes_gcm::aead::OsRng;
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits)?;
    let pub_key = RsaPublicKey::from(&priv_key);

    Ok((priv_key, pub_key))
}

#[test]
fn utils_hex_and_datetime_formatting_are_stable() {
    let rendered = to_hex_string(&[0x01, 0xAB, 0xFF], None);
    assert_eq!(rendered, "01abff");

    let rendered_joined = to_hex_string(&[0x01, 0xAB, 0xFF], Some(":"));
    assert_eq!(rendered_joined, "01:ab:ff");

    let ts = DateTime::<Utc>::from_naive_utc_and_offset(
        chrono::NaiveDate::from_ymd_opt(2024, 1, 2)
            .and_then(|value| value.and_hms_opt(3, 4, 5))
            .expect("failed to construct datetime for formatting test"),
        Utc,
    );
    assert_eq!(ts.to_saml_datetime_string(), "2024-01-02T03:04:05Z");
}
