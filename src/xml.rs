//! Internal utilities for doing things with XML

// #![deny(unsafe_code)]

use std::io::Write;

use std::str::from_utf8;

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

        let result = match includeheaders {
            true => cert_pem,
            false => crate::cert::strip_cert_headers(cert_pem),
        };
        log::debug!(
            "############### start get_as_pem_string includeheaders: {} ###############",
            includeheaders
        );
        log::debug!("{}", result);
        log::debug!("############### end get_as_pem_string ###############");
        result
    }
}

/// Used by the XML Event writer to append events to the response
pub fn write_event<W: Write>(event: XmlEvent, writer: &mut EventWriter<W>) -> String {
    match writer.write(event) {
        Ok(val) => format!("{:?}", val),
        Err(err) => format!("{:?}", err),
    }
}

/// add a signature to the statement
pub fn add_assertion_signature<W: Write>(
    attr: &crate::assertion::Assertion,
    digest: String,
    signature: String,
    writer: &mut EventWriter<W>,
) {
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

    // https://www.w3.org/TR/xmldsig-core/#sec-SignatureMethod

    let test: String = attr.signing_algorithm.into();

    write_event(
        XmlEvent::start_element(("ds", "SignatureMethod"))
            .attr("Algorithm", &test)
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
            .attr("URI", &format!("#{}", attr.assertion_id))
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

    // TODO: make digestmethod configurable
    let digestmethod: String = crate::sign::DigestAlgorithm::Sha256.into();

    // start ds:DigestMethod
    // <https://www.w3.org/TR/xmldsig-core/#sec-DigestMethod>

    write_event(
        XmlEvent::start_element(("ds", "DigestMethod"))
            .attr("Algorithm", &digestmethod)
            .into(),
        writer,
    );
    //end ds:DigestMethod
    write_event(XmlEvent::end_element().into(), writer);

    // <https://www.w3.org/TR/xmldsig-core/#sec-DigestValue>
    // DigestValue is an element that contains the encoded value of the digest. The digest is always encoded using base64 RFC2045.
    write_event(
        XmlEvent::start_element(("ds", "DigestValue")).into(),
        writer,
    );

    write_event(XmlEvent::characters(&digest), writer);
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

    write_event(XmlEvent::characters(&signature), writer);
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

    let mut stripped_cert = attr.signing_cert.clone().unwrap().get_as_pem_string(false);
    // TODO: is this terrible, or is this terrible? It's terrible, find a better way of cleaning this up.
    stripped_cert = stripped_cert
        .replace("\r\n", "")
        .replace("\n", "")
        .replace(" ", "");
    write_event(XmlEvent::characters(&stripped_cert), writer);
    // end ds:X509Certificate
    write_event(XmlEvent::end_element().into(), writer);
    // end ds:X509Data
    write_event(XmlEvent::end_element().into(), writer);
    // end ds:KeyInfo
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:Signature
    write_event(XmlEvent::end_element().into(), writer);
}
