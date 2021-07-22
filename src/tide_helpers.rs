//! Helpers for working with tide-based HTTP(S) services
//!

use crate::metadata::{generate_metadata_xml, SamlMetadata};
// use crate::{decode_authn_request_base64_encoded, parse_authn_request, SamlAuthnRequest};
use tide;
use tide::prelude::Deserialize;

/// Responds with the metadata XML file in a 200-status response with the right content-type
pub fn tide_metadata_response(metadata: SamlMetadata) -> tide::Response {
    let mut res = tide::Response::new(200);
    // Metadata spec is here http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
    // application/samlmetadata+xml
    res.set_content_type("application/samlmetadata+xml");
    res.set_body(generate_metadata_xml(metadata));
    res
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub struct SAMLRedirectQuery {
    /// Used in the SAML Redirect GET request to pull out the query values
    pub SAMLRequest: String,
    pub RelayState: String,
}
