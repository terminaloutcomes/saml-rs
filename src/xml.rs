//! Internal utilities for doing things with XML

// #![deny(unsafe_code)]

use serde::Serialize;
use std::io::Write;

use std::str::{from_utf8, FromStr};

use xml::writer::{EventWriter, XmlEvent};

/// Extensions for [openssl::x509::X509] for nicer functionality
pub trait X509Utils {
    /// return an X509 object as a string,
    /// either including the ```--- BEGIN LOLS ---```  or not
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
/// Attributes for responses
pub struct ResponseAttribute {
    name: String,
    nameformat: String,
    values: Vec<String>,
}

impl ResponseAttribute {
    /// new Response Attribute with `attrname-format:basic`
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

/// Options of Signing Algorithms for things
#[derive(Debug)]
pub enum SigningAlgorithm {
    /// SHA1 Algorithm
    Sha1,
    /// SHA256 Algorithm
    Sha256,
}

// impl SigningAlgorithm {
//     fn as_str(self) -> &'static str {
//         format!("{}", self.to_string()).clone()
//     }
// }

impl FromStr for SigningAlgorithm {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha1" => Ok(SigningAlgorithm::Sha1),
            "sha256" => Ok(SigningAlgorithm::Sha256),
            _ => Err("invalid type"),
        }
    }
}

impl ToString for SigningAlgorithm {
    fn to_string(&self) -> String {
        match self {
            Self::Sha1 => "sha1".to_string(),
            Self::Sha256 => "sha256".to_string(),
        }
    }
}

use openssl::x509::X509;

#[derive(Debug)]
/// The content of an assertion
pub struct AssertionData {
    /// Assertion ID, referred to in the signature as ds:Reference
    pub assertion_id: String,
    /// Signing algorithm
    pub signing_algorithm: SigningAlgorithm,
    /// Digest algorithm
    pub digest_algorithm: SigningAlgorithm,
    /// Digest value, based on alg
    pub digest_value: Option<String>,
    /// Signature value
    pub signature_value: Option<String>,
    /// Certificate for signing/digest? TODO: Figure this out
    pub certificate: X509,
}

impl AssertionData {
    /// Build an assertion based on the AssertionData, returns a String of XML.
    ///
    /// If you set sign, it'll sign the data.. eventually.
    pub fn build_assertion(&self, sign: bool) -> String {
        if sign {
            unimplemented!("Still need to refactor building the signed assertion")
        } else {
            unimplemented!("Still need to refactor building the assertion")
        }
        // String::from("Uh.. wait up.")
    }
}

/// add a signature to the statement
pub fn add_signature<W: Write>(attr: AssertionData, writer: &mut EventWriter<W>) {
    let algstring: String = format!(
        "http://www.w3.org/2000/09/xmldsig#rsa-{}",
        attr.signing_algorithm.to_string()
    );
    let digestmethod: String = format!(
        "http://www.w3.org/2000/09/xmldsig#{}",
        attr.digest_algorithm.to_string()
    );

    write_event(
        XmlEvent::start_element(("ds", "Signature"))
            .attr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
            .into(),
        writer,
    );
    write_event(XmlEvent::start_element(("ds", "SignedInfo")).into(), writer);
    write_event(
        XmlEvent::start_element(("ds", "CanonicalizationMethod"))
            .attr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            .into(),
        writer,
    );
    //end ds:CanonicalizationMethod
    write_event(XmlEvent::end_element().into(), writer);

    write_event(
        XmlEvent::start_element(("ds", "SignatureMethod"))
            .attr("Algorithm", &algstring)
            .into(),
        writer,
    );
    //end ds:Algorithm
    write_event(XmlEvent::end_element().into(), writer);

    /*
    TODO: this needs to be a reference to the ID
    5.4.2 References
    Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID
    attribute value of the root element of the assertion or protocol message being signed. For example, if the
    ID attribute value is "foo", then the URI attribute in the <ds:Reference> element MUST be "#foo".
    */
    write_event(
        XmlEvent::start_element(("ds", "Reference"))
            .attr("URI", "#pfx279776d1-c32a-3684-6dce-8eec41e02c33")
            .into(),
        writer,
    );

    write_event(XmlEvent::start_element(("ds", "Transforms")).into(), writer);

    write_event(
        XmlEvent::start_element(("ds", "Transform"))
            .attr(
                "Algorithm",
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
            )
            .into(),
        writer,
    );
    //end ds:Transform
    write_event(XmlEvent::end_element().into(), writer);

    write_event(
        XmlEvent::start_element(("ds", "Transform"))
            .attr("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            .into(),
        writer,
    );
    //end ds:Transform
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:Transforms
    write_event(XmlEvent::end_element().into(), writer);

    // start ds:DigestMethod
    write_event(
        XmlEvent::start_element(("ds", "DigestMethod"))
            .attr("Algorithm", &digestmethod)
            .into(),
        writer,
    );
    //end ds:DigestMethod
    write_event(XmlEvent::end_element().into(), writer);

    write_event(
        XmlEvent::start_element(("ds", "DigestValue")).into(),
        writer,
    );
    //"eACxbv4QcKTz/p8ir/fKxzHHUpA="
    // TODO: after implementing signed assertions, work out if we still to add error handling for this unwrap
    write_event(XmlEvent::characters(&attr.digest_value.unwrap()), writer);
    //end ds:DigestValue
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:Reference
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:SignedInfo
    write_event(XmlEvent::end_element().into(), writer);

    // start ds:SignatureValue
    write_event(
        XmlEvent::start_element(("ds", "SignatureValue")).into(),
        writer,
    );

    // NpWB3CIRUdvMP6pvYmpHIfJYnLmBxqqnBiwUBDh6N8FjiFC+wM0HDQdGn3Nchap7aQj84PCZu3+/0+v9RldfIe7EwSpt7B9HXr7yYMOdncki/ksEWyxY6nfNMNctvwDXa8pv7257OslGNNlo/XVeAOyiPvQ1f89wHsKGgkRn4w=
    // TODO: after implementing signed assertions, work out if we still to add error handling for this unwrap
    write_event(XmlEvent::characters(&attr.signature_value.unwrap()), writer);
    // characters
    // end ds:SignatureValue
    write_event(XmlEvent::end_element().into(), writer);

    // start ds:KeyInfo
    write_event(XmlEvent::start_element(("ds", "KeyInfo")).into(), writer);
    // start ds:X509Data
    write_event(XmlEvent::start_element(("ds", "X509Data")).into(), writer);
    // start ds:X509Certificate
    write_event(
        XmlEvent::start_element(("ds", "X509Certificate")).into(),
        writer,
    );
    // NpWB3CIRUdvMP6pvYmpHIfJYnLmBxqqnBiwUBDh6N8FjiFC+wM0HDQdGn3Nchap7aQj84PCZu3+/0+v9RldfIe7EwSpt7B9HXr7yYMOdncki/ksEWyxY6nfNMNctvwDXa8pv7257OslGNNlo/XVeAOyiPvQ1f89wHsKGgkRn4w=
    write_event(
        XmlEvent::characters(&attr.certificate.get_as_pem_string(false)),
        writer,
    );
    // end ds:X509Certificate
    write_event(XmlEvent::end_element().into(), writer);
    // end ds:X509Data
    write_event(XmlEvent::end_element().into(), writer);
    // end ds:KeyInfo
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:Signature
    write_event(XmlEvent::end_element().into(), writer);
}
