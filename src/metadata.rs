//! Handy for the XML metadata part of SAML

#![deny(unsafe_code)]

// use serde::Serialize;
use std::str::from_utf8;
use tera::{Context, Tera};

/// Stores the required data for generating a SAML metadata XML file
#[derive(Debug)]
pub struct SamlMetadata {
    pub hostname: String,
    pub baseurl: String,
    /// entityID is transmitted in all requests
    /// Every SAML system entity has an entity ID, a globally-unique identifier used in software configurations, relying-party databases, and client-side cookies. On the wire, every SAML protocol message contains the entity ID of the issuer
    // #[serde(rename = "entityID")]
    pub entity_id: String,
    /// Appended to the baseurl when using the [SamlMetadata::logout_url] function
    pub logout_suffix: String,
    /// Appended to the baseurl when using the [SamlMetadata::redirect_url] function
    pub redirect_suffix: String,
    /// Appended to the baseurl when using the [SamlMetadata::post_url] function
    pub post_suffix: String,
    pub x509_certificate: openssl::x509::X509,
}

// use openssl::x509::X509;

impl SamlMetadata {
    pub fn new(
        hostname: &str,
        baseurl: Option<String>,
        entity_id: Option<String>,
        logout_suffix: Option<String>,
        redirect_suffix: Option<String>,
        post_suffix: Option<String>,
        x509_certificate: openssl::x509::X509,
    ) -> Self {
        let hostname = hostname.to_string();
        let baseurl = baseurl.unwrap_or(format!("https://{}/SAML", hostname));
        let entity_id = entity_id.unwrap_or(format!("{}/idp", baseurl));
        let logout_suffix_default = String::from("/Logout");
        SamlMetadata {
            hostname,
            baseurl,
            entity_id,
            logout_suffix: logout_suffix.unwrap_or(logout_suffix_default),
            redirect_suffix: redirect_suffix.unwrap_or_else(|| String::from("/Redirect")),
            post_suffix: post_suffix.unwrap_or_else(|| String::from("/POST")),
            x509_certificate,
        }
    }

    pub fn from_hostname(hostname: &str) -> SamlMetadata {
        let cert = crate::cert::gen_self_signed_certificate(hostname);
        SamlMetadata::new(hostname, None, None, None, None, None, cert)
    }

    pub fn logout_url(&self) -> String {
        format!("{}{}", self.baseurl, self.logout_suffix)
    }
    pub fn redirect_url(&self) -> String {
        format!("{}{}", self.baseurl, self.redirect_suffix)
    }
    pub fn post_url(&self) -> String {
        format!("{}{}", self.baseurl, self.post_suffix)
    }
}

/// Generates the XML For a metadata file
///
/// Current response data is based on the data returned from  https://samltest.id/saml/idp
pub fn generate_metadata_xml(metadata: SamlMetadata) -> String {
    // Load the signing (public) certificate

    // Base64 Encode it
    // TODO: the base64 encoded cert bit

    let mut context = Context::new();
    context.insert("entity_id", &metadata.entity_id);
    context.insert("logout_url", metadata.logout_url().as_str());
    context.insert("redirect_url", &metadata.redirect_url());

    log::debug!("{}", metadata.logout_url());
    log::debug!("{}", metadata.redirect_url());

    let cert_pem = metadata.x509_certificate.to_pem().unwrap();
    let cert_pem = from_utf8(&cert_pem).unwrap().to_string();
    let base64_encoded_certificate = crate::cert::strip_cert_headers(cert_pem);

    context.insert("base64_encoded_certificate", &base64_encoded_certificate);

    let metadata_contents = String::from(
        r#"<?xml version="1.0"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{{entity_id | safe}}">
    <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
    {% if base64_encoded_certificate %}<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
            <ds:X509Certificate>{{base64_encoded_certificate | safe }}</ds:X509Certificate>
        </ds:X509Data>
    </ds:KeyInfo>{% endif %}
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
    {% if base64_encoded_certificate %}
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data>
                <ds:X509Certificate>{{base64_encoded_certificate | safe }}</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>{% endif %}
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{{logout_url | safe }}"/>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{{redirect_url | safe }}"/>
    </md:IDPSSODescriptor>
    <md:ContactPerson contactType="technical">
        <md:GivenName>Admin</md:GivenName>
        <md:EmailAddress>mailto:admin@example.com</md:EmailAddress>
    </md:ContactPerson>
</md:EntityDescriptor>"#,
    );

    Tera::one_off(&metadata_contents, &context, true).unwrap()
    // metadata_contents
}
