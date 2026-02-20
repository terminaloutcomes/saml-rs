//! Assertion-related things
//!
//! Assertions *Require* the following (from <http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf> 2.3.3 Element Assertion):

//! * Version - The version of this assertion. The identifier for the version of SAML defined in this specification is "2.0". SAML versioning is discussed in Section 4.
//! * ID - The identifier for this assertion. It is of type xs:ID, and MUST follow the requirements specified in Section 1.3.4 for identifier uniqueness.
//! * IssueInstant - The time instant of issue in UTC, as described in Section 1.3.3.
//! * Issuer - The SAML authority that is making the claim(s) in the assertion. The issuer SHOULD be unambiguous to the intended relying parties. There's no requirement for this to be the same as the signer, other than in the design of the consumer.
//!
//! Optional things:
//!
//! * ds:Signature - an XML signature
//! * Subject - The subject of the statement(s) in the assertion.
//! * Conditions - Conditions that MUST be evaluated when assessing the validity of and/or when using the assertion. See Section 2.5 for additional information on how to evaluate conditions.
//! * Advice - Additional information related to the assertion that assists processing in certain situations but which MAY be ignored by applications that do not understand the advice or do not wish to make use of it.
//!
//! Zero or more of the following statement elements:
//!
//! * Statement - A statement of a type defined in an extension schema. An xsi:type attribute MUST be used to indicate the actual statement type.
//! * AuthnStatement - An authentication statement.
//! * AuthzDecisionStatement - An authorization decision statement.
//! * AttributeStatement - An attribute statement.
//!
//! An assertion with no statements MUST contain a \<Subject\> element. Such an assertion identifies a principal in a manner which can be referenced or confirmed using SAML methods, but asserts no further information associated with that principal.

use log::{debug, error};
use serde::Serialize;

use crate::sign::SigningKey;
use crate::utils::*;
use crate::xml::write_event;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, SecondsFormat, Utc};
use std::io::Write;
use std::str::from_utf8;
use std::{fmt, sync::Arc};
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

/// AssertionTypes, from <http://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd> ```<complexType name="AssertionType">```
#[allow(dead_code)]
enum AssertionType {
    Statement,
    AuthnStatement,
    AuthzDecisionStatement,
    AttributeStatement,
}

/// StatusCode values
#[allow(dead_code)]
enum StatusCode {
    /// `urn:oasis:names:tc:SAML:2.0:status:Success`
    Success,
}

#[derive(Debug)]
/// The content of an assertion
pub struct Assertion {
    /// Assertion ID, referred to in the signature as ds:Reference
    pub assertion_id: String,
    /// Issuer of the Assertion
    pub issuer: String,
    /// Signing algorithm
    pub signing_algorithm: crate::sign::SigningAlgorithm,
    /// Digest algorithm
    pub digest_algorithm: crate::sign::DigestAlgorithm,
    /// Canonicalization method used for digest and SignedInfo.
    pub canonicalization_method: crate::sign::CanonicalizationMethod,
    /// Issue/Generatino time of the Assertion
    pub issue_instant: DateTime<Utc>,
    /// TODO: work out what is necessary for [SubjectData]
    pub subject_data: SubjectData,
    /// Please don't let the user do this until ... now!
    pub conditions_not_before: DateTime<Utc>,
    /// Please don't let the user do whatever we're saying they can do after this.
    pub conditions_not_after: DateTime<Utc>,
    /// Who/what should be reading this. Probably a [crate::sp::ServiceProvider]
    pub audience: String,
    /// Attributes of the assertion, things like groups and email addresses and phone numbers and favourite kind of 🥔🍠
    pub attributes: Vec<AssertionAttribute>,

    /// Should we sign the assertion?
    pub sign_assertion: bool,

    /// a private key for signing
    pub signing_key: Arc<SigningKey>, // TODO find a better way to do this, maybe with a dyn trait
    /// Certificate for signing/digest
    pub signing_cert: Option<x509_cert::Certificate>,
}

fn write_assertion_tmpdir(buffer: &[u8]) {
    let mut assertionpath = std::env::temp_dir();
    let mut assertionfilename: String = chrono::Utc::now().timestamp().to_string();
    assertionfilename.push_str("-assertionout.xml");
    assertionpath.set_file_name(assertionfilename);
    debug!(
        "Assertion output path prepared ({:?}); skipping debug file write.",
        &assertionpath
    );
    debug!("Assertion output length: {}", buffer.len());
}

/// Creates a String full of XML based on the ResponsElements
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Assertion {
    fn into(self) -> Vec<u8> {
        match self.try_to_xml_bytes() {
            Ok(value) => value,
            Err(error) => {
                error!("Failed to render assertion XML: {}", error);
                Vec::new()
            }
        }
    }
}

impl Assertion {
    /// This exists so we can return a copy of an [Assertion] without the signature flags so we can trigger [Assertion.Into<Vec<u8>>] for signing
    pub fn without_signature(&self) -> Self {
        Self {
            assertion_id: self.assertion_id.clone(),
            issuer: self.issuer.clone(),
            signing_algorithm: self.signing_algorithm,
            digest_algorithm: self.digest_algorithm,
            canonicalization_method: self.canonicalization_method,
            issue_instant: self.issue_instant,
            subject_data: self.subject_data.clone(),
            conditions_not_before: self.conditions_not_before,
            conditions_not_after: self.conditions_not_after,
            audience: self.audience.clone(),
            attributes: self.attributes.clone(),
            sign_assertion: false,
            signing_key: self.signing_key.clone(),
            signing_cert: self.signing_cert.clone(),
        }
    }

    /// Build an assertion based on the Assertion, returns a String of XML.
    ///
    /// If you set sign, it'll sign the data.. eventually.
    pub fn build_assertion(&mut self, sign: bool) -> String {
        self.sign_assertion = sign;
        let assertion_bytes = match self.try_to_xml_bytes() {
            Ok(value) => value,
            Err(error) => {
                error!("Failed to render assertion XML: {}", error);
                return String::new();
            }
        };
        match from_utf8(&assertion_bytes) {
            Ok(value) => value.to_string(),
            Err(error) => {
                error!("Failed to render assertion as utf8: {:?}", error);
                String::new()
            }
        }
    }

    /// Render the assertion as XML bytes.
    pub fn try_to_xml_bytes(&self) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();
        let mut writer = EmitterConfig::new()
            .perform_indent(false)
            .pad_self_closing(false)
            .write_document_declaration(false)
            .normalize_empty_elements(false)
            .create_writer(&mut buffer);

        self.add_assertion_to_xml(&mut writer)?;
        debug!("Assertion into vec result:");
        match from_utf8(&buffer) {
            Ok(value) => debug!("{}", value),
            Err(error) => error!("Failed to decode assertion as utf8: {:?}", error),
        }

        write_assertion_tmpdir(&buffer);
        Ok(buffer)
    }

    /// adds a `saml:Conditions` statement to the writer
    fn add_conditions<W: Write>(&self, writer: &mut EventWriter<W>) {
        // start conditions statement
        write_event(
            XmlEvent::start_element(("saml", "Conditions"))
                // TODO: conditions_not_before
                .attr("NotBefore", &self.conditions_not_before.to_rfc3339())
                // TODO: conditions_not_after
                .attr("NotOnOrAfter", &self.conditions_not_after.to_rfc3339())
                .into(),
            writer,
        );

        write_event(
            XmlEvent::start_element(("saml", "AudienceRestriction")).into(),
            writer,
        );
        write_event(XmlEvent::start_element(("saml", "Audience")).into(), writer);
        // TODO: BUG: this is wrong. Assertion contains an unacceptable AudienceRestriction.
        write_event(XmlEvent::characters(&self.audience), writer);
        write_event(XmlEvent::end_element().into(), writer);
        write_event(XmlEvent::end_element().into(), writer);
        // end conditions statement
        write_event(XmlEvent::end_element().into(), writer);
    }

    /// This adds the data from an Assertion to a given EventWriter.
    ///
    /// If you specify to *sign* the assertion, it's going to:
    /// - generate a temporary EventWriter
    /// - generate the *unsigned* assertion
    /// - add the signature to the assertion
    /// - weep quietly
    /// - return the full pack
    ///
    /// That's the plan, anyway.
    ///
    /// ``` xml
    /// # Assertion Header
    /// - AttributeStatement
    /// - AuthnStatement
    /// - Conditions
    /// - Issuer
    /// - Signature
    /// - Subject
    /// # End Assertion
    /// ```
    ///
    pub fn add_assertion_to_xml<W: Write>(
        &self,
        writer: &mut EventWriter<W>,
    ) -> Result<(), String> {
        // start the assertion
        debug!("sign_assertion: {}", self.sign_assertion);

        write_event(
            XmlEvent::start_element(("saml", "Assertion"))
                .attr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
                .attr("ID", &self.assertion_id)
                .attr(
                    "IssueInstant",
                    &self
                        .issue_instant
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                )
                .attr("Version", "2.0") // yeah, not going to support anything but 2.0 here. 😅
                .into(),
            writer,
        );

        // do the issuer inside the assertion
        write_event(XmlEvent::start_element(("saml", "Issuer")).into(), writer);
        write_event(XmlEvent::characters(&self.issuer), writer);
        write_event(XmlEvent::end_element().into(), writer);

        // if the assertion needs to be signed, we need to generate the whole assertion as a string, sign that, then add it to this assertion.
        if self.sign_assertion {
            debug!("Signing assertion");
            let signing_key = match self.signing_key.as_ref() {
                SigningKey::Rsa(key) => SigningKey::Rsa(key.clone()),
                #[allow(clippy::unimplemented)]
                SigningKey::EcDsa192(_) => unimplemented!("ECDSA signing not implemented yet"),
                SigningKey::None => {
                    return Err("Cannot sign assertion without signing key".to_string());
                }
            };
            if self.signing_cert.is_none() {
                return Err("Cannot sign assertion without signing certificate".to_string());
            }

            let unsigned_assertion = &self.without_signature();
            let unsigned_xml = String::from_utf8(unsigned_assertion.try_to_xml_bytes()?)
                .map_err(|error| format!("Unsigned assertion was not utf8: {:?}", error))?;

            let canonical_assertion = self.canonicalization_method.canonicalize(&unsigned_xml)?;
            let digest_bytes = self
                .digest_algorithm
                .hash(canonical_assertion.as_bytes())
                .map_err(|error| format!("Failed to hash canonical assertion: {:?}", error))?;
            let base64_encoded_digest = BASE64_STANDARD.encode(digest_bytes);

            let signature_config = crate::xml::SignatureConfig {
                reference_id: self.assertion_id.clone(),
                signing_algorithm: self.signing_algorithm,
                digest_algorithm: self.digest_algorithm,
                canonicalization_method: self.canonicalization_method,
                signing_cert: self.signing_cert.clone(),
            };

            let mut signedinfo_buffer = Vec::new();
            let mut signedinfo_writer = EmitterConfig::new()
                .perform_indent(false)
                .write_document_declaration(false)
                .normalize_empty_elements(true)
                .pad_self_closing(false)
                .create_writer(&mut signedinfo_buffer);

            crate::xml::generate_signedinfo(
                &signature_config,
                &base64_encoded_digest,
                &mut signedinfo_writer,
            );
            let signedinfo_xml = String::from_utf8(signedinfo_buffer)
                .map_err(|error| format!("SignedInfo was not utf8: {:?}", error))?;
            let canonical_signedinfo =
                self.canonicalization_method.canonicalize(&signedinfo_xml)?;

            let signed_result = crate::sign::sign_data(
                self.signing_algorithm,
                &Arc::new(signing_key),
                canonical_signedinfo.as_bytes(),
            )?;
            if signed_result.is_empty() {
                return Err("Failed to generate signature bytes".to_string());
            }
            let base64_encoded_signature = BASE64_STANDARD.encode(&signed_result);
            crate::xml::add_signature(
                &signature_config,
                &base64_encoded_digest,
                &base64_encoded_signature,
                writer,
            )?;
        }

        // add the subject to the assertion
        add_subject(&self.subject_data, writer);

        self.add_conditions(writer);

        // To do an expiry in an hour, do this
        // let session_expiry = Utc::now().checked_add_signed(Duration::seconds(3600));

        // self.authnstatement.add_to_xmlevent(&mut writer);

        // start the AttributeStatement
        write_event(
            XmlEvent::start_element(("saml", "AttributeStatement")).into(),
            writer,
        );
        for attribute in &self.attributes.to_vec() {
            add_attribute(attribute, writer);
        }

        // end saml:AttributeStatement
        write_event(XmlEvent::end_element().into(), writer);

        // end the assertion
        write_event(XmlEvent::end_element().into(), writer);
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
/// Type of `saml:NameId` in a statement.
///
/// "There can be 0 or more of NameQualifier or SPNameQualifier."
///
/// I must have been reading the spec again.
///
/// They look like this:
/// ```xml
/// <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
/// ```
pub enum BaseIDAbstractType {
    /// Use the `NameQualifier` attribute in `<saml:NameID>`.
    NameQualifier,
    /// This'll be the one you normally use - TODO I think this comes from the metadata itself
    SPNameQualifier,
}

impl From<String> for BaseIDAbstractType {
    fn from(name: String) -> Self {
        let name = name.as_str();
        match name {
            "NameQualifier" => BaseIDAbstractType::NameQualifier,
            "SPNameQualifier" => BaseIDAbstractType::SPNameQualifier,
            _ => {
                error!("Unknown BaseIDAbstractType value: {}", name);
                BaseIDAbstractType::SPNameQualifier
            }
        }
    }
}

impl fmt::Display for BaseIDAbstractType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseIDAbstractType::NameQualifier => f.write_str("NameQualifier"),
            BaseIDAbstractType::SPNameQualifier => f.write_str("SPNameQualifier"),
        }
    }
}

// // use xml::name::Name;
// use std::convert::From;

// impl From<xml::name::Name> for BaseIDAbstractType{
//     fn from(name: Name) -> Self {
//         self.from_string(name.to_string())
//     }
// }

#[derive(Clone, Debug)]
/// Data type for passing subject data in because yeaaaaah, specs
///
/// TODO: Justify the existence of the elements of this struct ... more completely.
pub struct SubjectData {
    /// AuthnRequest ID used for InResponseTo correlation.
    pub in_response_to: String,
    /// Qualifier TODO: What's the qualifier again?
    pub qualifier: Option<BaseIDAbstractType>,
    /// Qualifier value TODO: I really should know what these are
    pub qualifier_value: Option<String>,
    /// [crate::sp::NameIdFormat], what kind of format you're... going TODO oh no I've done it again
    pub nameid_format: crate::sp::NameIdFormat,
    /// NameID value - I know this one, it's the reference to the user, like username or some rando noise if it's transient. Regret, if it's [crate::sp::NameIdFormat::Kerberos]
    pub nameid_value: String,
    /// The AssertionConsumerService - where we'll send the request.
    pub acs: String,
    /// The expiry of this Assertion. Woo, recovered there at the end.
    pub subject_not_on_or_after: DateTime<Utc>,
}

/// Adds the Subject statement to an assertion
fn add_subject<W: Write>(subjectdata: &SubjectData, writer: &mut EventWriter<W>) {
    // start subject statement
    write_event(XmlEvent::start_element(("saml", "Subject")).into(), writer);
    // start nameid statement
    // TODO: nameid can be 0 or more of NameQualifier or SPNameQualifier
    let nameid_format = subjectdata.nameid_format.to_string();
    let name_id_start = match (&subjectdata.qualifier, &subjectdata.qualifier_value) {
        (Some(BaseIDAbstractType::NameQualifier), Some(value)) => {
            XmlEvent::start_element(("saml", "NameID"))
                .attr("Format", nameid_format.as_ref())
                .attr("NameQualifier", value.as_str())
        }
        (Some(BaseIDAbstractType::SPNameQualifier), Some(value)) => {
            XmlEvent::start_element(("saml", "NameID"))
                .attr("Format", nameid_format.as_ref())
                .attr("SPNameQualifier", value.as_str())
        }
        _ => XmlEvent::start_element(("saml", "NameID")).attr("Format", nameid_format.as_ref()),
    };
    write_event(name_id_start.into(), writer);

    write_event(XmlEvent::characters(&subjectdata.nameid_value), writer);
    // end nameid statement
    write_event(XmlEvent::end_element().into(), writer);

    //start subjectconfirmation
    write_event(
        XmlEvent::start_element(("saml", "SubjectConfirmation"))
            .attr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
            .into(),
        writer,
    );

    //start subjectconfirmationdata
    write_event(
        XmlEvent::start_element(("saml", "SubjectConfirmationData"))
            .attr("InResponseTo", &subjectdata.in_response_to)
            .attr(
                "NotOnOrAfter",
                &subjectdata
                    .subject_not_on_or_after
                    .to_saml_datetime_string(),
            )
            .attr("Recipient", &subjectdata.acs)
            .into(),
        writer,
    );

    //end subjectconfirmationdata
    write_event(XmlEvent::end_element().into(), writer);
    //end subjectconfirmation
    write_event(XmlEvent::end_element().into(), writer);

    write_event(XmlEvent::end_element().into(), writer);
    // end subject statement
}
// let mut animals: [&str; 2] = ["bird", "frog"];
#[derive(Debug, Default, Serialize, Clone)]
/// Attributes for responses
pub struct AssertionAttribute {
    name: String,
    nameformat: String,
    values: Vec<&'static str>,
}

impl AssertionAttribute {
    /// new Response Attribute with `attrname-format:basic`
    pub fn basic(name: &str, values: Vec<&'static str>) -> AssertionAttribute {
        AssertionAttribute {
            name: name.to_string(),
            nameformat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string(),
            values,
        }
    }
}

/// add an attribute to the statement
pub fn add_attribute<W: Write>(attr: &AssertionAttribute, writer: &mut EventWriter<W>) {
    write_event(
        XmlEvent::start_element(("saml", "Attribute"))
            .attr("Name", attr.name.as_str())
            .attr("NameFormat", attr.nameformat.as_str())
            .into(),
        writer,
    );
    for value in &attr.values {
        write_event(
            XmlEvent::start_element(("saml", "AttributeValue")).into(),
            writer,
        );
        write_event(XmlEvent::characters(value), writer);
        write_event(XmlEvent::end_element().into(), writer);
    }
    // write_event(XmlEvent::end_element().into(), writer);
    write_event(XmlEvent::end_element().into(), writer);
}
