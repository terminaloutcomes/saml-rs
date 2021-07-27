//! Service Provider utilities and functions
//!

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::str::FromStr;

use std::io::Cursor;
use xml::attribute::OwnedAttribute;
use xml::reader::{EventReader, XmlEvent};

/// Allows one to build a definition with [SamlBindingType::AssertionConsumerService]\(s\) and [SamlBindingType::SingleLogoutService]\(s\)
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum SamlBindingType {
    AssertionConsumerService,
    SingleLogoutService,
}

impl ToString for SamlBindingType {
    fn to_string(&self) -> String {
        match self {
            SamlBindingType::AssertionConsumerService => "AssertionConsumerService".to_string(),
            SamlBindingType::SingleLogoutService => "SingleLogoutService".to_string(),
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
pub enum SamlBinding {
    HttpPost,
    HttpRedirect,
}

impl Default for SamlBinding {
    fn default() -> Self {
        SamlBinding::HttpPost
    }
}
impl ToString for SamlBinding {
    fn to_string(&self) -> String {
        #[allow(clippy::match_single_binding)]
        match self {
            SamlBinding::HttpPost => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
            SamlBinding::HttpRedirect => {
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT".to_string()
            }
        }
    }
}
impl FromStr for SamlBinding {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" => Ok(SamlBinding::HttpPost),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT" => Ok(SamlBinding::HttpRedirect),
            _ => Err("Must be a valid type"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServiceBinding {
    pub servicetype: SamlBindingType,
    #[serde(rename = "Binding")]
    pub binding: SamlBinding,
    /// Where to send the response to
    #[serde(rename = "Location")]
    pub location: String,
    /// Consumer index, if there's more than 256 then wow, seriously?
    #[serde(rename = "Index")]
    pub index: u8,
}

impl ServiceBinding {
    pub fn default() -> Self {
        ServiceBinding {
            servicetype: SamlBindingType::AssertionConsumerService,
            binding: SamlBinding::default(),
            location: "http://0.0.0.0:0/SAML/acs".to_string(),
            index: 0,
        }
    }

    /// TODO: actually use this in SpMetaData::fromxml()
    pub fn set_binding(self, binding: String) -> Result<Self, String> {
        match SamlBinding::from_str(&binding) {
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

use openssl;

#[derive(Debug, Clone)]
pub struct SpMetadata {
    /// EntityID
    pub entity_id: String,
    /// Will this SP send signed requests? If so, we'll reject ones that aren't.
    pub authn_requests_signed: bool,
    /// Does this SP expect signed assertions?
    pub want_assertions_signed: bool,
    /// The signing (public) certificate for the SP
    pub x509_certificate: Option<openssl::x509::X509>,
    /// SP Services
    pub services: Vec<ServiceBinding>,
}

/// Used for showing the details of the SP Metadata XML file
fn xml_indent(size: usize) -> String {
    const INDENT: &str = "    ";
    (0..size)
        .map(|_| INDENT)
        .fold(String::with_capacity(size * INDENT.len()), |r, s| r + s)
}

impl SpMetadata {
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
            binding: SamlBinding::HttpPost,
            location: "".to_string(),
            index: 0,
        };
        for attribute in attributes {
            match attribute.name.local_name.to_lowercase().as_str() {
                "binding" => {
                    log::debug!("Found Binding");
                    let binding = match SamlBinding::from_str(&attribute.value) {
                        Ok(value) => value,
                        Err(error) => {
                            return Err(format!(
                                "UNMATCHED BINDING: {}: {}",
                                &attribute.value, error
                            ))
                        }
                    };
                    tmp_sb.binding = binding;
                }
                "location" => {
                    log::debug!("Found Location");
                    tmp_sb.location = attribute.value;
                }
                "index" => {
                    log::debug!("Found index");
                    tmp_sb.index = attribute.value.parse::<u8>().unwrap();
                }
                _ => {
                    eprintln!(
                        "Found unhandled attribute in AssertionConsumerService: {:?}",
                        attribute
                    );
                }
            }
        }
        eprintln!("Returning {:?}", tmp_sb);
        Ok(tmp_sb)
    }

    /// Let's parse some attributes!
    fn attrib_parser(&mut self, tag: &str, attributes: Vec<OwnedAttribute>) {
        // eprintln!("attrib_parser - tag={}, attr:{:?}", tag, attributes);
        match tag {
            "AssertionConsumerService" => {
                log::debug!("AssertionConsumerService: {:?}", attributes);
                match self
                    .service_attrib_parser(SamlBindingType::AssertionConsumerService, attributes)
                {
                    Ok(value) => {
                        let mut a = vec![value];
                        self.services.append(&mut a);
                    }
                    Err(error) => {
                        eprintln!("Failed to parse AssertionConsumerService: {:?}", error)
                    }
                }
            }
            "SingleLogoutService" => {
                log::debug!("SingleLogoutService: {:?}", attributes);
                match self.service_attrib_parser(SamlBindingType::SingleLogoutService, attributes) {
                    Ok(value) => {
                        let mut a = vec![value];
                        self.services.append(&mut a);
                    }
                    Err(error) => eprintln!("Failed to parse SingleLogoutService: {:?}", error),
                }
            }

            // TODO: SPSSODescriptor
            "EntityDescriptor" => {
                for attribute in attributes {
                    log::debug!("attribute: {}", attribute);
                    match attribute.name.local_name.as_str() {
                        "entityID" => {
                            eprintln!("Setting entityID: {}", attribute.value);
                            self.entity_id = attribute.value;
                        }
                        _ => {
                            log::debug!(
                                "found an EntityDescriptor attribute that's not entityID: {:?}",
                                attribute
                            );
                        }
                    }
                }
            }
            _ => log::warn!(
                "Asked to parse attributes for tag={}, not caught by anything {:?}",
                tag,
                attributes
            ),
        }

        // eprintln!("attribute found: {:?}", attribute);
        // eprintln!("local_name: {}", attribute.name.local_name);
        // eprintln!("value: {}", attribute.value);
    }

    /// Hand this a bucket of string data and you should get a struct with all the SP's metadata.
    ///
    pub fn from_xml(source_xml: &str) -> SpMetadata {
        let bufreader = Cursor::new(source_xml);
        let parser = EventReader::new(bufreader);
        let mut depth = 0;
        let mut tag_name = "###INVALID###".to_string();
        let mut certificate_data = None::<openssl::x509::X509>;

        let mut meta = SpMetadata {
            entity_id: "".to_string(),
            authn_requests_signed: false,
            want_assertions_signed: false,
            x509_certificate: None,
            services: vec![],
        };

        for e in parser {
            match e {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    println!("{}+{}", xml_indent(depth), name);
                    tag_name = name.local_name.to_string();
                    meta.attrib_parser(&tag_name, attributes);
                    depth += 1;
                }
                Ok(XmlEvent::EndElement { name }) => {
                    depth -= 1;
                    println!("{}-{}", xml_indent(depth), name);
                }
                Ok(XmlEvent::Characters(s)) => {
                    if tag_name == "X509Certificate" {
                        debug!("Found certificate!");
                        // certificate_data = s.to_string();
                        let certificate = crate::cert::init_cert_from_base64(&s);
                        match certificate {
                            Ok(value) => {
                                eprintln!("Parsed cert successfully.");
                                certificate_data = Some(value);
                            }
                            Err(error) => {
                                eprintln!("error! {:?}", error)
                            }
                        };
                        tag_name = "###INVALID###".to_string();
                    } else {
                        println!("Characters: {}{}", xml_indent(depth + 1), s);
                    }
                }
                Err(e) => {
                    println!("Error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        match certificate_data {
            Some(value) => {
                meta.x509_certificate = Some(value);
            }
            None => {
                eprintln!("Didn't find a certificate");
            }
        }
        meta
    }
}

/*
From Running SpMetaData::from_xml over the sp_metadata_splunk_self_signed.xml:


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
