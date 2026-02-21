//! Service Provider utilities and functions.

use log::{debug, error, warn};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use x509_cert::Certificate;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::error::SamlError;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
/// Different types of name-id formats from the spec.
#[derive(Default)]
pub enum NameIdFormat {
    /// Email Address.
    EmailAddress,
    /// TODO entity?
    Entity,
    /// Kerberos, the worst-eros.
    Kerberos,
    /// Should stay the same.
    Persistent,
    /// Don't keep this, it'll change.
    Transient,
    /// Fallback when no explicit format is supplied.
    #[default]
    Unspecified,
    /// Windows format.
    WindowsDomainQualifiedName,
    /// X509 format.
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
                f.write_str("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos")
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

/// Allows one to build a definition with [SamlBindingType::AssertionConsumerService](s) and [SamlBindingType::SingleLogoutService](s).
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum SamlBindingType {
    /// AssertionConsumerService, where you send Authn Responses.
    AssertionConsumerService,
    /// Logout endpoints.
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
/// Binding methods.
#[derive(Default)]
pub enum BindingMethod {
    /// HTTP-POST method.
    #[default]
    HttpPost,
    /// HTTP-REDIRECT method.
    HttpRedirect,
}

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

    /// Turn a string into a SAML binding.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" => Ok(BindingMethod::HttpPost),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT" => Ok(BindingMethod::HttpRedirect),
            _ => Err("Must be a valid type"),
        }
    }
}

/// Types of bindings for service providers.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceBinding {
    /// [SamlBindingType] Binding type, things like `HTTP-POST` or `HTTP-REDIRECT`.
    pub servicetype: SamlBindingType,
    #[serde(rename = "Binding")]
    /// Binding method.
    pub binding: BindingMethod,
    /// Where to send the response to.
    #[serde(rename = "Location")]
    pub location: String,
    /// Consumer index.
    #[serde(rename = "Index")]
    pub index: u8,
}

impl ServiceBinding {
    /// Sets the binding from a string value.
    pub fn set_binding(self, binding: &str) -> Result<Self, SamlError> {
        match BindingMethod::from_str(binding) {
            Err(_) => Err(SamlError::Other("Failed to match binding name".to_string())),
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
    /// Return a default broken binding for testing or later changing - the ACS is set to `http://0.0.0.0:0/SAML/acs`.
    fn default() -> Self {
        ServiceBinding {
            servicetype: SamlBindingType::AssertionConsumerService,
            binding: BindingMethod::default(),
            location: "http://0.0.0.0:0/SAML/acs".to_string(),
            index: 0,
        }
    }
}

#[derive(Debug, Clone)]
/// SP metadata object, used for finding one when an AuthN request arrives.
pub struct ServiceProvider {
    /// EntityID.
    pub entity_id: String,
    /// Will this SP send signed requests? If so, unsigned requests should be rejected.
    pub authn_requests_signed: bool,
    /// Does this SP expect signed assertions?
    pub want_assertions_signed: bool,
    /// The signing (public) certificate for the SP.
    pub x509_certificate: Option<Certificate>,
    /// SP services.
    pub services: Vec<ServiceBinding>,
    /// Protocol support enumeration.
    pub protocol_support_enumeration: Option<String>,
    /// [NameIdFormat] - how we should identify the user.
    pub nameid_format: NameIdFormat,
}

fn decode_local_name(start: &BytesStart<'_>) -> String {
    String::from_utf8_lossy(start.local_name().as_ref()).to_string()
}

fn decode_attributes(start: &BytesStart<'_>) -> Result<Vec<(String, String)>, SamlError> {
    let mut result = Vec::new();
    let mut attributes = start.attributes();
    attributes.with_checks(true);

    for attribute in attributes {
        let attribute = attribute
            .map_err(|error| SamlError::Other(format!("Invalid attribute: {:?}", error)))?;
        let key = String::from_utf8_lossy(attribute.key.local_name().as_ref()).to_string();
        let value = attribute
            .decode_and_unescape_value(start.decoder())
            .map_err(|error| SamlError::Other(format!("Invalid attribute value: {:?}", error)))?
            .to_string();
        result.push((key, value));
    }

    Ok(result)
}

fn is_safe_general_reference(reference: &str) -> bool {
    matches!(reference, "amp" | "lt" | "gt" | "apos" | "quot") || reference.starts_with('#')
}

impl FromStr for ServiceProvider {
    type Err = SamlError;

    fn from_str(source_xml: &str) -> Result<Self, Self::Err> {
        let limits = crate::security::SecurityPolicy::default()
            .effective()
            .xml_limits;
        crate::security::inspect_xml_payload(source_xml, limits)
            .inspect_err(|error| error!("SP metadata XML preflight check failed: {}", error))?;

        let mut reader = Reader::from_str(source_xml);
        reader.config_mut().trim_text(true);

        let mut tag_stack: Vec<String> = Vec::new();
        let mut certificate_data = None::<Certificate>;
        let mut meta = ServiceProvider {
            entity_id: "".to_string(),
            authn_requests_signed: false,
            want_assertions_signed: false,
            x509_certificate: None,
            services: vec![],
            protocol_support_enumeration: None,
            nameid_format: NameIdFormat::default(),
        };

        loop {
            match reader.read_event() {
                Ok(Event::Start(start)) => {
                    let tag_name = decode_local_name(&start);
                    let attributes = decode_attributes(&start)?;
                    meta.attrib_parser(&tag_name, attributes);
                    tag_stack.push(tag_name);
                }
                Ok(Event::Empty(start)) => {
                    let tag_name = decode_local_name(&start);
                    let attributes = decode_attributes(&start)?;
                    meta.attrib_parser(&tag_name, attributes);
                }
                Ok(Event::End(end)) => {
                    let end_name = String::from_utf8_lossy(end.local_name().as_ref()).to_string();
                    let Some(open_name) = tag_stack.pop() else {
                        return Err(SamlError::XmlParsing(
                            "Malformed SP metadata XML: unexpected closing tag".to_string(),
                        ));
                    };
                    if open_name != end_name {
                        return Err(SamlError::XmlParsing(format!(
                            "Malformed SP metadata XML: mismatched closing tag {} for {}",
                            end_name, open_name
                        )));
                    }
                }
                Ok(Event::Text(text)) => {
                    let content = text
                        .decode()
                        .map_err(|error| {
                            SamlError::XmlParsing(format!(
                                "Failed to decode text node: {:?}",
                                error
                            ))
                        })?
                        .trim()
                        .to_string();
                    if content.is_empty() {
                        continue;
                    }
                    match tag_stack.last().map(String::as_str) {
                        Some("NameIDFormat") => match NameIdFormat::from_str(&content) {
                            Err(error) => {
                                error!("Failed to parse NameIDFormat: {} {:?}", content, error);
                                return Err(SamlError::XmlParsing(format!(
                                    "Failed to parse NameIDFormat: {} {:?}",
                                    content, error
                                )));
                            }
                            Ok(value) => meta.nameid_format = value,
                        },
                        Some("X509Certificate") => {
                            let certificate = crate::cert::init_cert_from_base64(&content)
                                .map_err(|error| {
                                    SamlError::XmlParsing(format!(
                                        "Invalid Certificate {:?}",
                                        error
                                    ))
                                })?;
                            certificate_data = Some(certificate);
                        }
                        _ => {}
                    }
                }

                Ok(Event::CData(text)) => {
                    let content = text
                        .decode()
                        .map_err(|error| {
                            SamlError::XmlParsing(format!(
                                "Failed to decode CDATA node: {:?}",
                                error
                            ))
                        })?
                        .trim()
                        .to_string();
                    if !content.is_empty() {
                        return Err(SamlError::XmlParsing(
                            "SP metadata contains unsupported CDATA content in strict mode"
                                .to_string(),
                        ))?;
                    }
                }
                Ok(Event::DocType(_)) => {
                    return Err(SamlError::XmlParsing(
                        "SP metadata contains forbidden DOCTYPE/DTD declarations".to_string(),
                    ));
                }
                Ok(Event::PI(_)) => {
                    return Err(SamlError::XmlParsing(
                        "SP metadata contains forbidden processing instructions".to_string(),
                    ));
                }
                Ok(Event::GeneralRef(reference)) => {
                    let name = reference
                        .decode()
                        .map_err(|error| {
                            SamlError::XmlParsing(format!(
                                "Failed to decode entity reference: {:?}",
                                error
                            ))
                        })?
                        .to_string();
                    if !is_safe_general_reference(name.as_str()) {
                        return Err(SamlError::XmlParsing(format!(
                            "SP metadata contains forbidden entity/reference: {}",
                            name
                        )));
                    }
                }
                Ok(Event::Decl(_)) => Err(SamlError::XmlParsing(
                    "SP metadata contains forbidden XML declaration".to_string(),
                ))?,
                Ok(Event::Comment(_)) => Err(SamlError::XmlParsing(
                    "SP metadata contains forbidden XML comments".to_string(),
                ))?,
                Ok(Event::Eof) => break,
                Err(error) => {
                    return Err(SamlError::XmlParsing(format!(
                        "Failed to parse SP metadata XML: {:?}",
                        error
                    )));
                }
            }
        }

        if !tag_stack.is_empty() {
            return Err(SamlError::XmlParsing(
                "Malformed SP metadata XML: unclosed XML elements".to_string(),
            ));
        }

        meta.x509_certificate = certificate_data;
        if meta.x509_certificate.is_none() {
            warn!("SP metadata did not include an X509 certificate");
        }
        Ok(meta)
    }
}

impl ServiceProvider {
    /// Generate a generic ServiceProvider with placeholder values for testing.
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

    /// Used for handling the attributes of service endpoint tags.
    fn service_attrib_parser(
        &mut self,
        servicetype: SamlBindingType,
        attributes: Vec<(String, String)>,
    ) -> Result<ServiceBinding, SamlError> {
        let mut binding = ServiceBinding {
            servicetype,
            binding: BindingMethod::HttpPost,
            location: String::new(),
            index: 0,
        };
        for (key, value) in attributes {
            match key.to_ascii_lowercase().as_str() {
                "binding" => {
                    binding.binding = BindingMethod::from_str(&value).map_err(|error| {
                        SamlError::Other(format!("UNMATCHED BINDING: {}: {}", value, error))
                    })?;
                }
                "location" => {
                    binding.location = value;
                }
                "index" => {
                    binding.index = value.parse::<u8>().map_err(|error| {
                        SamlError::Other(format!("UNMATCHED INDEX: {}: {:?}", value, error))
                    })?;
                }
                _ => {
                    error!(
                        "Unhandled service attribute in {}: {}={}",
                        servicetype, key, value
                    );
                }
            }
        }
        Ok(binding)
    }

    /// Return the first AssertionConsumerService we find.
    pub fn find_first_acs(&self) -> Result<ServiceBinding, SamlError> {
        for service in &self.services {
            if let SamlBindingType::AssertionConsumerService = service.servicetype {
                return Ok(service.to_owned());
            }
        }
        Err(SamlError::XmlParsing(
            "Couldn't find ACS in SP metadata".to_string(),
        ))
    }

    /// Parse service provider metadata attributes for a given tag.
    fn attrib_parser(&mut self, tag: &str, attributes: Vec<(String, String)>) {
        debug!("attrib_parser - tag={}, attr:{:?}", tag, attributes);
        match tag {
            "AssertionConsumerService" => {
                match self
                    .service_attrib_parser(SamlBindingType::AssertionConsumerService, attributes)
                {
                    Ok(value) => self.services.push(value),
                    Err(error) => error!("Failed to parse AssertionConsumerService: {}", error),
                }
            }
            "EntityDescriptor" => {
                for (key, value) in attributes {
                    match key.as_str() {
                        "entityID" | "ID" => {
                            self.entity_id = value;
                        }
                        _ => {
                            error!(
                                "Found unexpected EntityDescriptor attribute {}={}",
                                key, value
                            );
                        }
                    }
                }
            }
            "SingleLogoutService" => {
                match self.service_attrib_parser(SamlBindingType::SingleLogoutService, attributes) {
                    Ok(value) => self.services.push(value),
                    Err(error) => error!("Failed to parse SingleLogoutService: {}", error),
                }
            }
            "SPSSODescriptor" => {
                for (key, value) in attributes {
                    match key.to_ascii_lowercase().as_str() {
                        "authnrequestssigned" => match value.to_ascii_lowercase().as_str() {
                            "true" => self.authn_requests_signed = true,
                            "false" => self.authn_requests_signed = false,
                            _ => error!("Couldn't parse AuthnRequestsSigned value: {}", value),
                        },
                        "wantassertionssigned" => match value.to_ascii_lowercase().as_str() {
                            "true" => self.want_assertions_signed = true,
                            "false" => self.want_assertions_signed = false,
                            _ => error!("Couldn't parse WantAssertionsSigned value: {}", value),
                        },
                        "protocolsupportenumeration" => {
                            self.protocol_support_enumeration = Some(value);
                        }
                        _ => error!("SPSSODescriptor attribute not handled {}={}", key, value),
                    }
                }
            }
            "RequestInitiator" => warn!("RequestInitiator is not implemented, skipping"),
            "SigningMethod" => warn!("SigningMethod is not implemented, skipping"),
            "DigestMethod" => warn!("DigestMethod is not implemented, skipping"),
            "NameIDFormat" | "KeyDescriptor" | "KeyInfo" | "X509Certificate" | "X509Data"
            | "Logo" | "Description" => {}
            _ => error!(
                "Asked to parse attributes for unhandled tag {} ({:?})",
                tag, attributes
            ),
        }
    }
}
