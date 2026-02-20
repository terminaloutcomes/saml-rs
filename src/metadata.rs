//! Handy for the XML metadata part of SAML

use crate::xml::write_event;
use std::io::Write;
use std::str::from_utf8;
use x509_cert::Certificate;
use x509_cert::der::EncodePem;
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

/// Stores the required data for generating a SAML metadata XML file
#[derive(Debug)]
pub struct SamlMetadata {
    /// Hostname of the issuer, used for URLs etc
    pub hostname: String,
    /// Set this as the base of the suffix-items elsewhere
    pub baseurl: String,
    /// entityID is transmitted in all requests
    ///
    /// Every SAML system entity has an entity ID, a globally-unique identifier used in software configurations, relying-party databases, and client-side cookies. On the wire, every SAML protocol message contains the entity ID of the issuer. If you don't set it, it'll fall back to the bare hostname.
    // #[serde(rename = "entityID")]
    pub entity_id: String,
    /// Appended to the baseurl when using the [SamlMetadata::logout_url] function
    pub logout_suffix: String,
    /// Appended to the baseurl when using the [SamlMetadata::redirect_url] function
    pub redirect_suffix: String,
    /// Appended to the baseurl when using the [SamlMetadata::post_url] function
    pub post_suffix: String,
    /// Public certificate for signing/encryption
    pub x509_certificate: Option<x509_cert::Certificate>,
}

impl SamlMetadata {
    /// Create a new SamlMetadata object for your IdP
    pub fn new(
        hostname: &str,
        baseurl: Option<String>,
        entity_id: Option<String>,
        logout_suffix: Option<String>,
        redirect_suffix: Option<String>,
        post_suffix: Option<String>,
        x509_certificate: Option<Certificate>,
    ) -> Self {
        let hostname = hostname.to_string();
        let baseurl = baseurl.unwrap_or(format!("https://{}/SAML", hostname));
        let entity_id = match entity_id {
            Some(value) => value,
            None => hostname.to_string(),
        };
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

    /// really simple version with a self-signed certificate based on just the hostname. Mainly for testing.
    pub fn from_hostname(hostname: &str) -> Result<SamlMetadata, String> {
        let cert = crate::cert::gen_self_signed_certificate(hostname)?;
        Ok(SamlMetadata::new(
            hostname,
            None,
            None,
            None,
            None,
            None,
            Some(cert),
        ))
    }

    /// return the generated Logout URL based on the baseurl + logout_suffix
    pub fn logout_url(&self) -> String {
        format!("{}{}", self.baseurl, self.logout_suffix)
    }
    /// return the generated redirect URL based on the baseurl + redirect_suffix
    pub fn redirect_url(&self) -> String {
        format!("{}{}", self.baseurl, self.redirect_suffix)
    }
    /// return the generated post URL based on the baseurl + post_suffix
    pub fn post_url(&self) -> String {
        format!("{}{}", self.baseurl, self.post_suffix)
    }
}

/// Write a signing key to an XMLEventWriter
pub fn xml_add_certificate<W: Write>(
    key_use: &str,
    base64_encoded_certificate: &str,
    writer: &mut EventWriter<W>,
) {
    write_event(
        XmlEvent::start_element(("md", "KeyDescriptor"))
            .attr("use", key_use)
            .into(),
        writer,
    );
    write_event(
        XmlEvent::start_element(("ds", "KeyInfo"))
            .attr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
            .into(),
        writer,
    );
    write_event(XmlEvent::start_element(("ds", "X509Data")).into(), writer);
    write_event(
        XmlEvent::start_element(("ds", "X509Certificate")).into(),
        writer,
    );

    write_event(
        XmlEvent::characters(&base64_encoded_certificate.replace("\n", "")),
        writer,
    );
    // end the x509certificate
    write_event(XmlEvent::end_element().into(), writer);
    // end the x509data
    write_event(XmlEvent::end_element().into(), writer);
    // end the ds:keyinfo
    write_event(XmlEvent::end_element().into(), writer);
    // end the md:keydescriptor signing
    write_event(XmlEvent::end_element().into(), writer);
}

/// Generates the XML For a metadata file
///
/// Current response data is based on the data returned from  <https://samltest.id/saml/idp>
pub fn generate_metadata_xml(metadata: &SamlMetadata) -> Result<String, String> {
    let mut buffer = Vec::new();
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .write_document_declaration(false)
        .create_writer(&mut buffer);

    write_event(
        XmlEvent::start_element(("md", "EntityDescriptor"))
            .attr("xmlns:md", "urn:oasis:names:tc:SAML:2.0:metadata")
            .attr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
            .attr("entityID", &metadata.entity_id)
            .into(),
        &mut writer,
    );

    write_event(
        XmlEvent::start_element(("md", "IDPSSODescriptor"))
            .attr(
                "protocolSupportEnumeration",
                "urn:oasis:names:tc:SAML:2.0:protocol",
            )
            .into(),
        &mut writer,
    );

    if let Some(value) = &metadata.x509_certificate {
        let base64_encoded_certificate = value
            .to_pem(rsa::pkcs8::LineEnding::CRLF)
            .map_err(|e| format!("Failed to encode certificate to PEM: {}", e))?;
        xml_add_certificate("signing", &base64_encoded_certificate, &mut writer);
        // xml_add_certificate("encryption", &base64_encoded_certificate, &mut writer);
    };

    write_event(
        XmlEvent::start_element(("md", "SingleLogoutService"))
            // TODO: make the binding configurable, when we support something else 🤔
            .attr(
                "Binding",
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            )
            .attr("Location", metadata.logout_url().as_str())
            .into(),
        &mut writer,
    );
    write_event(XmlEvent::end_element().into(), &mut writer);

    write_event(
        XmlEvent::start_element(("md", "NameIDFormat")).into(),
        &mut writer,
    );
    write_event(
        // TODO: nameid-format should definitely be configurable
        XmlEvent::characters("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
        &mut writer,
    );
    write_event(XmlEvent::end_element().into(), &mut writer);

    write_event(
        XmlEvent::start_element(("md", "SingleSignOnService"))
            // TODO: make the binding configurable, when we support something else 🤔
            .attr(
                "Binding",
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            )
            .attr("Location", metadata.redirect_url().as_str())
            .into(),
        &mut writer,
    );
    write_event(XmlEvent::end_element().into(), &mut writer);

    // end md:IDPSSODescriptor
    write_event(XmlEvent::end_element().into(), &mut writer);

    write_event(
        XmlEvent::start_element(("md", "ContactPerson"))
            // TODO: be able to enumerate technical contacts in IdP metadata
            .attr("contactType", "technical")
            .into(),
        &mut writer,
    );

    write_event(
        XmlEvent::start_element(("md", "GivenName")).into(),
        &mut writer,
    );
    write_event(
        // TODO: md:contactperson name should be configurable
        XmlEvent::characters("Admin"),
        &mut writer,
    );
    write_event(XmlEvent::end_element().into(), &mut writer);

    write_event(
        XmlEvent::start_element(("md", "EmailAddress")).into(),
        &mut writer,
    );
    write_event(
        // TODO: md:contactperson EmailAddress should be configurable
        XmlEvent::characters("mailto:admin@example.com"),
        &mut writer,
    );
    write_event(XmlEvent::end_element().into(), &mut writer);

    // end md:ContactPerson
    write_event(XmlEvent::end_element().into(), &mut writer);

    // end md:EntityDescriptor
    write_event(XmlEvent::end_element().into(), &mut writer);

    // TODO: figure out if we really need that prepended silliness '<?xml version=\"1.0\"?>'
    match from_utf8(&buffer) {
        Ok(value) => Ok(format!("<?xml version=\"1.0\"?>\n{}", value)),
        Err(error) => Err(format!("Failed to render metadata as utf8: {:?}", error)),
    }
}
