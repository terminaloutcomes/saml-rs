//! Extensions for things and generic utilities

use chrono::{DateTime, SecondsFormat, Utc};

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
