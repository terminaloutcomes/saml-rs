//! Service Provider utilities and functions
//!

// #![deny(unsafe_code)]

use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use openssl;
use openssl::x509::X509;
use std::io::Cursor;
use xml::attribute::OwnedAttribute;
use xml::reader::{EventReader, XmlEvent};

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
/// Different types of name-id formats from the spec
#[derive(Default)]
pub enum NameIdFormat {
    /// Email Address
    EmailAddress,
    /// TODO: entity?
    Entity,
    /// Kerberos, the worst-eros
    Kerberos,
    /// Should stay the same
    Persistent,
    /// Don't keep this, it'll change
    Transient,
    /// 🤷‍♂️🤷‍♀️ who even knows
    #[default]
    Unspecified,
    /// Windows format
    WindowsDomainQualifiedName,
    /// X509 format
    X509SubjectName,
}

impl fmt::Display for NameIdFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameIdFormat::EmailAddress => {
                f.write_str("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
            }
            NameIdFormat::Entity => f.write_str("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"),
            NameIdFormat::Kerberos => {
                f.write_str(" urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos")
            }
            NameIdFormat::Persistent => {
                f.write_str("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
            }
            NameIdFormat::Transient => {
                f.write_str("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
            }
            NameIdFormat::Unspecified => {
                f.write_str("urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified")
            }
            NameIdFormat::WindowsDomainQualifiedName => {
                f.write_str("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName")
            }
            NameIdFormat::X509SubjectName => {
                f.write_str("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName")
            }
        }
    }
}
impl FromStr for NameIdFormat {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => {
                Ok(NameIdFormat::EmailAddress)
            }
            "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" => Ok(NameIdFormat::Entity),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" => Ok(NameIdFormat::Persistent),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos" => Ok(NameIdFormat::Kerberos),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" => Ok(NameIdFormat::Transient),
            "urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified" => {
                Ok(NameIdFormat::Unspecified)
            }
            "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" => {
                Ok(NameIdFormat::X509SubjectName)
            }
            "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName" => {
                Ok(NameIdFormat::WindowsDomainQualifiedName)
            }
            _ => Err("Must be a valid type"),
        }
    }
}

/// Allows one to build a definition with [SamlBindingType::AssertionConsumerService]\(s\) and [SamlBindingType::SingleLogoutService]\(s\)
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum SamlBindingType {
    /// AssertionConsumerService, where you send Authn Rssponses
    AssertionConsumerService,
    /// Logout endpoints
    SingleLogoutService,
}

impl fmt::Display for SamlBindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SamlBindingType::AssertionConsumerService => f.write_str("AssertionConsumerService"),
            SamlBindingType::SingleLogoutService => f.write_str("SingleLogoutService"),
        }
    }
}
impl FromStr for SamlBindingType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "AssertionConsumerService" => Ok(SamlBindingType::AssertionConsumerService),
            "SingleLogoutService" => Ok(SamlBindingType::SingleLogoutService),
            _ => Err("Must be a valid type"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
/// Binding methods
#[derive(Default)]
pub enum BindingMethod {
    /// HTTP-POST method
    #[default]
    HttpPost,
    /// HTTP-REDIRECT method
    HttpRedirect,
}

// TODO: add these bindings, not that we can use them yet
// Failed to parse AssertionConsumerService: "UNMATCHED BINDING: urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign: Must be a valid type"
// Failed to parse AssertionConsumerService: "UNMATCHED BINDING: urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact: Must be a valid type"
// Failed to parse AssertionConsumerService: "UNMATCHED BINDING: urn:oasis:names:tc:SAML:2.0:bindings:PAOS: Must be a valid type"

impl fmt::Display for BindingMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingMethod::HttpPost => {
                f.write_str("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
            }
            BindingMethod::HttpRedirect => {
                f.write_str("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT")
            }
        }
    }
}
impl FromStr for BindingMethod {
    type Err = &'static str;

    /// turn a string into a SamlBinding
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" => Ok(BindingMethod::HttpPost),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT" => Ok(BindingMethod::HttpRedirect),
            _ => Err("Must be a valid type"),
        }
    }
}

/// Types of bindings for service providers
/// TODO: implement a way of pulling the first/a given logout, or the first/ a given assertionconsumer
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceBinding {
    /// [SamlBindingType] Binding type, things like `HTTP-POST` or `HTTP-REDIRECT`
    pub servicetype: SamlBindingType,
    #[serde(rename = "Binding")]
    /// Binding method
    pub binding: BindingMethod,
    /// Where to send the response to
    #[serde(rename = "Location")]
    pub location: String,
    /// Consumer index, if there's more than 256 then wow, seriously?
    #[serde(rename = "Index")]
    pub index: u8,
}

impl ServiceBinding {
    /// TODO: actually use this in ServiceProvider from_xml or something
    pub fn set_binding(self, binding: &str) -> Result<Self, String> {
        match BindingMethod::from_str(binding) {
            Err(_) => Err("Failed to match binding name".to_string()),
            Ok(saml_binding) => Ok(ServiceBinding {
                servicetype: self.servicetype,
                binding: saml_binding,
                location: self.location,
                index: self.index,
            }),
        }
    }
}

impl Default for ServiceBinding {
    /// return a default broken binding for testing or later changing - the ACS is set to `http://0.0.0.0:0/SAML/acs`
    fn default() -> Self {
        ServiceBinding {
            servicetype: SamlBindingType::AssertionConsumerService,
            binding: BindingMethod::default(),
            location: "http://0.0.0.0:0/SAML/acs".to_string(),
            index: 0,
        }
    }
}

/// Used for showing the details of the SP Metadata XML file
fn xml_indent(size: usize) -> String {
    const INDENT: &str = "    ";
    (0..size)
        .map(|_| INDENT)
        .fold(String::with_capacity(size * INDENT.len()), |r, s| r + s)
}

#[derive(Debug, Clone)]
/// SP metadata object, used for being able to find one when an AuthN request comes in (or IdP-initiated, eventually, maymbe?)
pub struct ServiceProvider {
    /// EntityID
    pub entity_id: String,
    /// Will this SP send signed requests? If so, we'll reject ones that aren't.
    pub authn_requests_signed: bool,
    /// Does this SP expect signed assertions?
    pub want_assertions_signed: bool,
    /// The signing (public) certificate for the SP
    pub x509_certificate: Option<X509>,
    /// SP Services
    pub services: Vec<ServiceBinding>,
    /// TODO protocol_support_enumeration? what's this?
    pub protocol_support_enumeration: Option<String>,
    /// [NameIdFormat] - how we should identify the user
    pub nameid_format: NameIdFormat,
}

impl FromStr for ServiceProvider {
    type Err = &'static str;

    fn from_str(source_xml: &str) -> Result<Self, Self::Err> {
        let bufreader = Cursor::new(source_xml);
        let parser = EventReader::new(bufreader);
        let mut depth = 0;
        let mut tag_name = "###INVALID###".to_string();
        let mut certificate_data = None::<X509>;

        let mut meta = ServiceProvider {
            entity_id: "".to_string(),
            authn_requests_signed: false,
            want_assertions_signed: false,
            x509_certificate: None,
            services: vec![],
            protocol_support_enumeration: None,
            nameid_format: NameIdFormat::default(),
        };
        let upstream_tag = "";
        for e in parser {
            match e {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    // println!("{}+{}", xml_indent(depth), name);
                    tag_name = name.local_name.to_string();

                    meta.attrib_parser(&tag_name, attributes, upstream_tag);
                    depth += 1;
                }
                Ok(XmlEvent::EndElement { .. /* name */ }) => {
                    depth -= 1;
                    // println!("{}-{}", xml_indent(depth), name);
                }
                Ok(XmlEvent::Characters(s)) => {
                    match tag_name.as_str() {
                        "NameIDFormat" => {
                            debug!("Found NameIDFormat!");
                            match NameIdFormat::from_str(&s) {
                                Err(error) => error!("Failed to parse NameIDFormat: {} {:?}", s, error),
                                Ok(value) => meta.nameid_format = value
                            }

                        }
                        "X509Certificate" => {
                            debug!("Found certificate!");
                            // certificate_data = s.to_string();
                            let certificate = crate::cert::init_cert_from_base64(&s);
                            match certificate {
                                Ok(value) => {
                                    debug!("Parsed cert successfully.");
                                    certificate_data = Some(value);
                                }
                                Err(error) => {
                                    error!("error! {:?}", error)
                                }
                            };
                            tag_name = "###INVALID###".to_string();
                        }
                        _ => {
                            println!("Characters: {}{}", xml_indent(depth + 1), s);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to parse token: {:?}", e);
                }
                _ => {}
            }
        }

        match certificate_data {
            Some(value) => {
                meta.x509_certificate = Some(value);
            }
            None => {
                error!("Didn't find a certificate");
            }
        }
        Ok(meta)
    }
}

impl ServiceProvider {
    /// Generate a test generic ServiceProvider with nonsense values for testing
    pub fn test_generic(entity_id: &str) -> Self {
        ServiceProvider {
            entity_id: entity_id.to_string(),
            authn_requests_signed: false,
            want_assertions_signed: false,
            x509_certificate: None,
            services: Vec::new(),
            protocol_support_enumeration: None,
            nameid_format: NameIdFormat::Transient,
        }
    }
    /// Used for handling the attributes of services in the tags of an SP Metadata XML file
    ///
    /// Types tested (poorly):
    /// - AssertionConsumerService
    /// - SingleLogoutService
    fn service_attrib_parser(
        &mut self,
        servicetype: SamlBindingType,
        attributes: Vec<OwnedAttribute>,
    ) -> Result<ServiceBinding, String> {
        let mut tmp_sb = ServiceBinding {
            servicetype,
            binding: BindingMethod::HttpPost,
            location: "".to_string(),
            index: 0,
        };
        for attribute in attributes {
            match attribute.name.local_name.to_lowercase().as_str() {
                "binding" => {
                    debug!("Found Binding");
                    let binding = match BindingMethod::from_str(&attribute.value) {
                        Ok(value) => value,
                        Err(error) => {
                            return Err(format!(
                                "UNMATCHED BINDING: {}: {}",
                                &attribute.value, error
                            ));
                        }
                    };
                    tmp_sb.binding = binding;
                }
                "location" => {
                    debug!("Found Location");
                    tmp_sb.location = attribute.value;
                }
                "index" => {
                    debug!("Found index");
                    tmp_sb.index = match attribute.value.parse::<u8>() {
                        Ok(value) => value,
                        Err(error) => {
                            return Err(format!(
                                "UNMATCHED INDEX: {}: {:?}",
                                &attribute.value, error
                            ));
                        }
                    };
                }
                _ => {
                    error!(
                        "Found unhandled attribute in AssertionConsumerService: {:?}",
                        attribute
                    );
                }
            }
        }
        debug!("Returning {:?}", tmp_sb);
        Ok(tmp_sb)
    }

    /// return the first AssertionConsumerService we find
    pub fn find_first_acs(&self) -> Result<ServiceBinding, &'static str> {
        if !self.services.is_empty() {
            for service in &self.services {
                if let SamlBindingType::AssertionConsumerService = service.servicetype {
                    return Ok(service.to_owned());
                };
            }
        }
        Err("Couldn't find ACS")
    }

    /// Let's parse some attributes!
    fn attrib_parser(&mut self, tag: &str, attributes: Vec<OwnedAttribute>, upstream_tag: &str) {
        debug!("attrib_parser - tag={}, attr:{:?}", tag, attributes);
        debug!("Current upstream tag: {}", upstream_tag);

        match tag {
            "AssertionConsumerService" => {
                debug!("AssertionConsumerService: {:?}", attributes);
                match self
                    .service_attrib_parser(SamlBindingType::AssertionConsumerService, attributes)
                {
                    Ok(value) => {
                        let mut a = vec![value];
                        self.services.append(&mut a);
                    }
                    Err(error) => {
                        error!("Failed to parse AssertionConsumerService: {:?}", error);
                    }
                }
            }
            "EntityDescriptor" => {
                for attribute in attributes {
                    debug!("attribute: {}", attribute);
                    match attribute.name.local_name.as_str() {
                        "entityID" => {
                            debug!("Setting entityID: {}", attribute.value);
                            self.entity_id = attribute.value;
                        }
                        "ID" => {
                            debug!("Setting entityID: {}", attribute.value);
                            self.entity_id = attribute.value;
                        }
                        // TODO validUntil example value "2100-01-01T00:00:42Z"
                        _ => {
                            error!(
                                "found an EntityDescriptor attribute that's not entityID: {:?}",
                                attribute
                            );
                        }
                    }
                }
            }
            "SingleLogoutService" => {
                debug!("SingleLogoutService: {:?}", attributes);
                match self.service_attrib_parser(SamlBindingType::SingleLogoutService, attributes) {
                    Ok(value) => {
                        let mut a = vec![value];
                        self.services.append(&mut a);
                    }
                    Err(error) => error!("Failed to parse SingleLogoutService: {:?}", error),
                }
            }

            "SPSSODescriptor" => {
                debug!("Dumping SPSSODescriptor: {:?}", attributes);
                for attribute in attributes {
                    match attribute.name.local_name.to_lowercase().as_str() {
                        "authnrequestssigned" => {
                            // AuthnRequestsSigned
                            match attribute.value.to_lowercase().as_str() {
                                "true" => self.authn_requests_signed = true,
                                "false" => self.authn_requests_signed = false,
                                _ => error!(
                                    "Couldn't parse value of AuthnRequestsSigned: {}",
                                    attribute.value.to_lowercase()
                                ),
                            }
                        }
                        "wantassertionssigned" => {
                            // WantAssertionsSigned
                            match attribute.value.to_lowercase().as_str() {
                                "true" => self.want_assertions_signed = true,
                                "false" => self.want_assertions_signed = false,
                                _ => error!(
                                    "Couldn't parse value of WantAssertionsSigned: {}",
                                    attribute.value.to_lowercase()
                                ),
                            }
                        }
                        "protocolsupportenumeration" => {
                            self.protocol_support_enumeration = Some(attribute.value.to_string())
                        }
                        _ => error!("SPSSODescriptor attribute not handled {:?}", attribute), // protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                                                                                              // WantAssertionsSigned="true"
                    }
                }
            }
            // TODO: RequestInitiator
            "RequestInitiator" => warn!("RequestInitiator is yet to be implemented, skipping"),
            // TODO: SPSSODescriptor?
            // "SPSSODescriptor" => warn!("SPSSODescriptor is yet to be implemented, skipping"),
            // TODO: SigningMethod - should be relevant to how we respond
            "SigningMethod" => warn!("SigningMethod is yet to be implemented, skipping"),
            // TODO: DigestMethod - should be relevant to how we respond
            "DigestMethod" => warn!("DigestMethod is yet to be implemented, skipping"),

            "NameIDFormat" => debug!("Don't need to parse attributes for NameIDFormat"),
            "KeyDescriptor" => debug!("Don't need to parse attributes for KeyDescriptor"),
            "KeyInfo" => debug!("Don't need to parse attributes for KeyInfo"),
            "X509Certificate" => debug!("Don't need to parse attributes for X509Certificate"),
            "X509Data" => debug!("Don't need to parse attributes for X509Data"),
            "Logo" => debug!("Don't need to parse attributes for Logo"),
            "Description" => debug!("Don't need to parse attributes for Description"),
            _ => error!(
                "!!! Asked to parse attributes for tag={}, not caught by anything {:?}",
                tag, attributes
            ),
        }
    }

    //    pub fn add_to_xmlevent(&self, writer: &mut EventWriter<W>) {

    // fn ssp_so_descriptor_handler<R: Read>(&self,
    //     parser: &mut EventReader<R>,
    //     meta: &mut ServiceProvider ) {

    // }
}

/*
From Running ServiceProvider::from_xml over the sp_metadata_splunk_self_signed.xml:


+{urn:oasis:names:tc:SAML:2.0:metadata}md:EntityDescriptor
    +{urn:oasis:names:tc:SAML:2.0:metadata}md:SPSSODescriptor
        +{urn:oasis:names:tc:SAML:2.0:metadata}md:KeyDescriptor
            +{http://www.w3.org/2000/09/xmldsig#}ds:KeyInfo
                +{http://www.w3.org/2000/09/xmldsig#}ds:X509Data
                    +{http://www.w3.org/2000/09/xmldsig#}ds:X509Certificate
                    -{http://www.w3.org/2000/09/xmldsig#}ds:X509Certificate
                -{http://www.w3.org/2000/09/xmldsig#}ds:X509Data
            -{http://www.w3.org/2000/09/xmldsig#}ds:KeyInfo
        -{urn:oasis:names:tc:SAML:2.0:metadata}md:KeyDescriptor
        +{urn:oasis:names:tc:SAML:2.0:metadata}md:SingleLogoutService
        -{urn:oasis:names:tc:SAML:2.0:metadata}md:SingleLogoutService
        +{urn:oasis:names:tc:SAML:2.0:metadata}md:AssertionConsumerService
        -{urn:oasis:names:tc:SAML:2.0:metadata}md:AssertionConsumerService
    -{urn:oasis:names:tc:SAML:2.0:metadata}md:SPSSODescriptor
-{urn:oasis:names:tc:SAML:2.0:metadata}md:EntityDescriptor

*/
