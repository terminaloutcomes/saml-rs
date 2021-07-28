//! Internal utilities for doing things with XML

#![deny(unsafe_code)]

use serde::Serialize;
use std::io::Write;
use std::str::from_utf8;
use xml::writer::{EventWriter, XmlEvent};

// Extensions for [openssl::x509::X509] for nicer functionality
pub trait X509Utils {
    fn get_as_pem_string(&self, includeheaders: bool) -> String;
}

impl X509Utils for openssl::x509::X509 {
    /// return an X509 object as a string,
    /// either including the ```--- BEGIN LOLS ---```  or not
    fn get_as_pem_string(&self, includeheaders: bool) -> String {
        let cert_pem = &self.to_pem().unwrap();
        let cert_pem: String = from_utf8(&cert_pem).unwrap().to_string();

        match includeheaders {
            true => cert_pem,
            false => crate::cert::strip_cert_headers(cert_pem),
        }
    }
}

/// Used by the XML Event writer to append events to the response
pub fn write_event<W: Write>(event: XmlEvent, writer: &mut EventWriter<W>) -> String {
    match writer.write(event) {
        Ok(val) => format!("{:?}", val),
        Err(err) => format!("{:?}", err),
    }
}

// let mut animals: [&str; 2] = ["bird", "frog"];
#[derive(Debug, Default, Serialize, Clone)]
pub struct ResponseAttribute {
    name: String,
    nameformat: String,
    values: Vec<String>,
}

impl ResponseAttribute {
    pub fn basic(name: &str, values: Vec<String>) -> ResponseAttribute {
        ResponseAttribute {
            name: name.to_string(),
            nameformat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string(),
            values,
        }
    }
}

/// add an attribute to the statement
pub fn add_attribute<W: Write>(attr: ResponseAttribute, writer: &mut EventWriter<W>) {
    write_event(
        XmlEvent::start_element(("saml", "Attribute"))
            .attr("Name", attr.name.as_str())
            .attr("NameFormat", attr.nameformat.as_str())
            .into(),
        writer,
    );
    for value in attr.values {
        write_event(
            XmlEvent::start_element(("saml", "AttributeValue"))
                .attr("xsi:type", "xs:string")
                .into(),
            writer,
        );
        write_event(XmlEvent::characters(value.as_str()), writer);
        write_event(XmlEvent::end_element().into(), writer);
    }
    // write_event(XmlEvent::end_element().into(), writer);
    write_event(XmlEvent::end_element().into(), writer);
}
