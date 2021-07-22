//! Handy for the XML metadata part of SAML

use serde::Serialize;

/// Stores the required data for generating a SAML metadata XML file
#[derive(Debug, Serialize)]
pub struct SamlMetadata {
    pub hostname: String,
    pub baseurl: String,
    /// entityID is transmitted in all requests
    /// Every SAML system entity has an entity ID, a globally-unique identifier used in software configurations, relying-party databases, and client-side cookies. On the wire, every SAML protocol message contains the entity ID of the issuer
    #[serde(rename = "entityID")]
    pub entity_id: String,
    /// Appended to the baseurl when using the [SamlMetadata::logout_url] function
    pub logout_suffix: String,
    /// Appended to the baseurl when using the [SamlMetadata::redirect_url] function
    pub redirect_suffix: String,
    /// Appended to the baseurl when using the [SamlMetadata::post_url] function
    pub post_suffix: String,
}

impl SamlMetadata {
    pub fn new(
        hostname: &str,
        baseurl: Option<String>,
        entity_id: Option<String>,
        logout_suffix: Option<String>,
        redirect_suffix: Option<String>,
        post_suffix: Option<String>,
    ) -> Self {
        let hostname = hostname.to_string();
        let baseurl = baseurl.unwrap_or(format!("https://{}/SAML", hostname));
        let entity_id = entity_id.unwrap_or(format!("{}/idp", baseurl));
        let logout_suffix_default = String::from("/Logout");
        let redirect_suffix_default = String::from("/Redirect");
        let post_suffix_default = String::from("/POST");
        SamlMetadata {
            hostname,
            baseurl,
            entity_id,
            logout_suffix: logout_suffix.unwrap_or(logout_suffix_default),
            redirect_suffix: redirect_suffix.unwrap_or(redirect_suffix_default),
            post_suffix: post_suffix.unwrap_or(post_suffix_default),
        }
    }

    pub fn from_hostname(hostname: &str) -> SamlMetadata {
        SamlMetadata::new(hostname, None, None, None, None, None)
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
    let base64_encoded_certificate = base64::encode("yeah, soon.");

    let mut metadata_contents = String::new();
    metadata_contents.push_str(&format!(
        "<?xml version=\"1.0\"?>
<md:EntityDescriptor
    xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"
    xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"{}\">
    <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">
        ",
        metadata.entity_id
    ));

    metadata_contents.push_str(
        "
    <md:KeyDescriptor use=\"signing\">
    <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">
        <ds:X509Data>\n",
    );
    metadata_contents.push_str(&format!(
        "            <ds:X509Certificate>\n{}\n            </ds:X509Certificate>\n",
        base64_encoded_certificate
    ));
    metadata_contents.push_str(
        r#"        </ds:X509Data>
    </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
    "#,
    );
    metadata_contents.push_str(&format!(
        "            <ds:X509Certificate>{}\n            </ds:X509Certificate>\n",
        base64_encoded_certificate
    ));
    metadata_contents.push_str(&format!("
        </ds:X509Data>
    </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{}\"/>\n", metadata.logout_url()));
    metadata_contents.push_str("    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n");
    metadata_contents.push_str(&format!("    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{}\"/>\n", &metadata.redirect_url()));
    metadata_contents.push_str(
        "</md:IDPSSODescriptor>
    <md:ContactPerson contactType=\"technical\">
        <md:GivenName>Admin</md:GivenName>
        <md:EmailAddress>mailto:admin@example.com</md:EmailAddress>
    </md:ContactPerson>
</md:EntityDescriptor>",
    );

    metadata_contents
}
