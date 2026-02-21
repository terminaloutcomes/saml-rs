//! Internal utilities for doing things with XML

use std::io::Write;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use x509_cert::der::Encode;
use xml::writer::{EventWriter, XmlEvent};

use crate::error::SamlError;

/// Used by the XML Event writer to append events to the response
pub fn write_event<W: Write>(event: XmlEvent, writer: &mut EventWriter<W>) -> String {
    match writer.write(event) {
        Ok(val) => format!("{:?}", val),
        Err(err) => format!("{:?}", err),
    }
}

/// Signature metadata used for generating XML-DSig blocks.
#[derive(Clone, Debug)]
pub struct SignatureConfig {
    /// The ID value of the element being signed, without leading `#`.
    pub reference_id: String,
    /// Signature algorithm URI.
    pub signing_algorithm: crate::sign::SigningAlgorithm,
    /// Digest algorithm URI.
    pub digest_algorithm: crate::sign::DigestAlgorithm,
    /// Canonicalization method URI.
    pub canonicalization_method: crate::sign::CanonicalizationMethod,
    /// Signing certificate to include in `ds:KeyInfo`.
    pub signing_cert: Option<x509_cert::Certificate>,
}

/// Add a `ds:SignedInfo` block.
pub fn generate_signedinfo<W: Write>(
    config: &SignatureConfig,
    digest: &str,
    writer: &mut EventWriter<W>,
) {
    // start ds:SignedInfo
    write_event(
        XmlEvent::start_element(("ds", "SignedInfo"))
            .attr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
            .into(),
        writer,
    );
    // start CanonicalizationMethod Tag
    let c14n_method: String = config.canonicalization_method.into();
    write_event(
        XmlEvent::start_element(("ds", "CanonicalizationMethod"))
            .attr("Algorithm", &c14n_method)
            .into(),
        writer,
    );
    //end ds:CanonicalizationMethod
    write_event(XmlEvent::end_element().into(), writer);

    // https://www.w3.org/TR/xmldsig-core/#sec-SignatureMethod

    let signing_algorithm: String = config.signing_algorithm.into();

    write_event(
        XmlEvent::start_element(("ds", "SignatureMethod"))
            .attr("Algorithm", &signing_algorithm)
            .into(),
        writer,
    );
    //end ds:Algorithm
    write_event(XmlEvent::end_element().into(), writer);

    /*
    TODO this needs to be a reference to the ID
    5.4.2 References
    Signatures MUST contain a single <ds:Reference> containing a same-document reference to the ID
    attribute value of the root element of the assertion or protocol message being signed. For example, if the
    ID attribute value is "foo", then the URI attribute in the <ds:Reference> element MUST be "#foo".
    */
    write_event(
        XmlEvent::start_element(("ds", "Reference"))
            .attr("URI", &format!("#{}", config.reference_id))
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
            .attr("Algorithm", &c14n_method)
            .into(),
        writer,
    );
    //end ds:Transform
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:Transforms
    write_event(XmlEvent::end_element().into(), writer);

    let digestmethod: String = config.digest_algorithm.into();

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

    write_event(XmlEvent::characters(digest), writer);
    //end ds:DigestValue
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:Reference
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:SignedInfo
    write_event(XmlEvent::end_element().into(), writer);
}

/// Add a `ds:Signature` block.
pub fn add_signature<W: Write>(
    config: &SignatureConfig,
    digest: &str,
    base64_encoded_signature: &str,
    writer: &mut EventWriter<W>,
) -> Result<(), SamlError> {
    write_event(
        XmlEvent::start_element(("ds", "Signature"))
            .attr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
            .into(),
        writer,
    );

    generate_signedinfo(config, digest, writer);

    // start ds:SignatureValue
    write_event(
        XmlEvent::start_element(("ds", "SignatureValue")).into(),
        writer,
    );

    write_event(XmlEvent::characters(base64_encoded_signature), writer);
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

    let stripped_cert = match config.signing_cert.as_ref() {
        Some(cert) => cert
            .to_der()
            .map(|der| BASE64_STANDARD.encode(der))
            .map_err(|err| {
                SamlError::Encoding(format!("Failed to convert cert to DER: {:?}", err))
            })?,
        None => {
            return Err(SamlError::NoCertAvailable);
        }
    };
    write_event(XmlEvent::characters(&stripped_cert), writer);
    // end ds:X509Certificate
    write_event(XmlEvent::end_element().into(), writer);
    // end ds:X509Data
    write_event(XmlEvent::end_element().into(), writer);
    // end ds:KeyInfo
    write_event(XmlEvent::end_element().into(), writer);

    //end ds:Signature
    write_event(XmlEvent::end_element().into(), writer);
    Ok(())
}
