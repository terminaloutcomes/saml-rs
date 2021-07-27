//! Service Provider utilities and functions
//!

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::str::FromStr;

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
        }
    }
}
impl FromStr for SamlBinding {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" => Ok(SamlBinding::HttpPost),
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

#[derive(Debug, Clone)] // Serialize, Deserialize,
                        // #[allow(clippy::dead_code)]
pub struct SpMetadata {
    // #[serde(rename = "entityID")]
    pub entity_id: String,

    // #[serde(rename = "AuthnRequestsSigned")]
    pub authn_requests_signed: bool,

    // #[serde(rename = "WantAssertionsSigned")]
    pub want_assertions_signed: bool,
    /// probably should be something else
    // #[serde(rename = "X509Certificate")]
    pub x509_certificate: Option<openssl::x509::X509>,
    pub services: Vec<ServiceBinding>,
}

use std::io::Cursor;
use xml::reader::EventReader;
use xml::reader::XmlEvent;

fn xml_indent(size: usize) -> String {
    const INDENT: &str = "    ";
    (0..size)
        .map(|_| INDENT)
        .fold(String::with_capacity(size * INDENT.len()), |r, s| r + s)
}

impl SpMetadata {
    /// hand this a bucket of string data and you should get something useful back out... one day.
    ///

    pub fn from_xml(source_xml: &str) -> SpMetadata {
        let bufreader = Cursor::new(source_xml);
        let parser = EventReader::new(bufreader);
        let mut depth = 0;
        let mut previous_name = "unknown".to_string();
        let mut certificate_data = None::<openssl::x509::X509>;
        for e in parser {
            match e {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    println!("{}+{}", xml_indent(depth), name);
                    for attribute in attributes {
                        debug!("attribute found: {:?}", attribute);
                    }
                    previous_name = name.local_name.to_string();
                    depth += 1;
                }
                Ok(XmlEvent::EndElement { name }) => {
                    depth -= 1;
                    println!("{}-{}", xml_indent(depth), name);
                }
                Ok(XmlEvent::Characters(s)) => {
                    if previous_name == "X509Certificate" {
                        debug!("Found certificate!");
                        // certificate_data = s.to_string();
                        let certificate = crate::cert::init_cert_from_base64(&s);
                        match certificate {
                            Ok(value) => {
                                eprintln!("Parsed cert successfully.");
                                certificate_data = Some(value);
                            }
                            Err(error) => {
                                eprintln!("{:?}", error)
                            }
                        };
                        previous_name = "done".to_string();
                    }

                    println!("{}{}", xml_indent(depth + 1), s);
                }
                Err(e) => {
                    println!("Error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        let mut meta = SpMetadata {
            entity_id: "splunkEntityId".to_string(),
            authn_requests_signed: true,
            want_assertions_signed: true,
            x509_certificate: None,
            services: [
                ServiceBinding {
                    servicetype: SamlBindingType::AssertionConsumerService,
                    binding: SamlBinding::HttpPost,
                    location: "http://15d49b9c30a5:8000/saml/acs".to_string(),
                    index: 0,
                },
                ServiceBinding {
                    servicetype: SamlBindingType::SingleLogoutService,
                    binding: SamlBinding::HttpPost,
                    location: "http://15d49b9c30a5:8000/saml/logout".to_string(),
                    index: 0,
                },
            ]
            .to_vec(),
        };
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
