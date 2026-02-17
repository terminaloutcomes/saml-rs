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

use serde::Serialize;

use crate::utils::*;
use crate::xml::write_event;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use openssl::x509::X509;
use std::fmt;
use std::io::Write;
use std::str::from_utf8;
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

#[derive(Clone, Debug)]
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

    /// an openssl private key for signing
    pub signing_key: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    /// Certificate for signing/digest
    pub signing_cert: Option<X509>,
}

fn write_assertion_tmpdir(buffer: &[u8]) {
    let mut assertionpath = std::env::temp_dir();
    let mut assertionfilename: String = chrono::Utc::now().timestamp().to_string();
    assertionfilename.push_str("-assertionout.xml");
    assertionpath.set_file_name(assertionfilename);
    log::debug!("Assertion filename: {:?}", &assertionpath);
    let mut assertionfile = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        // either use ? or unwrap since it returns a Result
        .open(assertionpath.into_os_string())
    {
        Ok(value) => value,
        Err(e) => {
            log::error!("Failed to open assertionout {:?}", e);
            std::process::exit(1)
        }
    };

    match assertionfile.write_all(buffer) {
        Ok(value) => log::debug!("{:?}", value),
        Err(e) => log::error!("{:?}", e),
    };
}

/// Creates a String full of XML based on the ResponsElements
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Assertion {
    fn into(self) -> Vec<u8> {
        // TODO: implement into vec u8 for assertion so we can sign it

        let mut buffer = Vec::new();
        let mut writer = EmitterConfig::new()
            .perform_indent(true)
            .pad_self_closing(false)
            .write_document_declaration(false)
            .normalize_empty_elements(false)
            .create_writer(&mut buffer);

        self.add_assertion_to_xml(&mut writer);
        log::debug!("Assertion into vec result:");
        log::debug!("{}", from_utf8(&buffer).unwrap());

        write_assertion_tmpdir(&buffer);
        buffer
    }
}

impl Assertion {
    /// This exists so we can return a copy of an [Assertion] without the signature flags so we can trigger [Assertion.Into<Vec<u8>>] for signing
    pub fn without_signature(self) -> Self {
        Self {
            assertion_id: self.assertion_id,
            issuer: self.issuer,
            signing_algorithm: self.signing_algorithm,
            digest_algorithm: self.digest_algorithm,
            issue_instant: self.issue_instant,
            subject_data: self.subject_data,
            conditions_not_before: self.conditions_not_before,
            conditions_not_after: self.conditions_not_after,
            audience: self.audience,
            attributes: self.attributes,
            sign_assertion: false,
            signing_key: self.signing_key,
            signing_cert: self.signing_cert,
        }
    }

    /// Build an assertion based on the Assertion, returns a String of XML.
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
    pub fn add_assertion_to_xml<W: Write>(&self, writer: &mut EventWriter<W>) {
        // start the assertion
        log::debug!("sign_assertion: {}", self.sign_assertion);

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
            log::debug!("Signing assertion");
            if self.signing_key.is_none() {
                panic!("You tried to sign an assertion without setting a signing key...");
            }

            // 1. generate the assertion, a big lump of XML
            let unsigned_assertion = self.clone().without_signature();
            let xmldata: Vec<u8> = unsigned_assertion.into();

            // 2. take a hash of that.
            let digest_bytes = self.digest_algorithm.hash(&xmldata).unwrap();

            // 3. base64 encode #2
            let base64_encoded_digest = BASE64_STANDARD.encode(digest_bytes);

            // 4. you put #3 into ANOTHER chunk of XML.
            let mut signedinfo_buffer = Vec::new();
            let mut signedinfo_writer = EmitterConfig::new()
                .perform_indent(true)
                .write_document_declaration(false)
                .normalize_empty_elements(true)
                .pad_self_closing(false)
                .create_writer(&mut signedinfo_buffer);

            crate::xml::generate_signedinfo(self, &base64_encoded_digest, &mut signedinfo_writer);
            log::debug!("SignedInfo Element:");
            log::debug!("{}", from_utf8(&signedinfo_buffer).unwrap());

            // 5. you hash #4.
            let hashed_signedinfo = BASE64_STANDARD.encode(signedinfo_buffer);
            log::debug!("Hashed Signedinfo: {}", hashed_signedinfo);

            // 6. you sign #5
            let key = self.signing_key.as_ref().unwrap();
            let signed_result =
                crate::sign::sign_data(self.signing_algorithm, key, hashed_signedinfo.as_bytes());
            log::debug!("Signature result: {:?}", &signed_result);

            let base64_encoded_signature = BASE64_STANDARD.encode(&signed_result);
            log::debug!(
                "Base64 encoded signature result: {:?}",
                &base64_encoded_signature
            );

            // 7. then you put #4 and #6 inside some other xml inside #1.

            crate::xml::add_assertion_signature(
                self,
                base64_encoded_digest,
                base64_encoded_signature,
                writer,
            );
        } else {
            // add an extra newline to the thing before signing, per https://www.di-mgt.com.au/xmldsig2.html
            // the spaces indent the next tag...
            write_event(XmlEvent::characters("\n  \n  "), writer);

            log::warn!("Unsigned assertion was built, this seems bad!");
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
            _ => panic!("how did you even get here"),
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
    /// Relay state as provided by the [crate::AuthnRequest]
    pub relay_state: String,
    /// Qualifier TODO: What's the qualifier again?
    pub qualifier: Option<BaseIDAbstractType>,
    /// Qualifier value TODO: I really should know what these are
    pub qualifier_value: Option<String>,
    /// [crate::sp::NameIdFormat], what kind of format you're... going TODO oh no I've done it again
    pub nameid_format: crate::sp::NameIdFormat,
    /// NameID value - I know this one, it's the reference to the user, like username or some rando noise if it's transient. Regret, if it's [crate::sp::NameIdFormat::Kerberos]
    pub nameid_value: &'static str,
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
    write_event(
        XmlEvent::start_element(("saml", "NameID"))
            .attr("Format", &subjectdata.nameid_format.to_string())
            .attr(
                subjectdata.qualifier.unwrap().to_string().as_str(),
                subjectdata.qualifier_value.as_ref().unwrap(),
            )
            .into(),
        writer,
    );

    write_event(XmlEvent::characters(subjectdata.nameid_value), writer);
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
            .attr("InResponseTo", &subjectdata.relay_state)
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
            XmlEvent::start_element(("saml", "AttributeValue"))
                .attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance") // TODO: moved 2021-08-26 to make c14n work, is this valid, or is it going to bite me
                .attr("xsi:type", "xs:string")
                .into(),
            writer,
        );
        write_event(XmlEvent::characters(value), writer);
        write_event(XmlEvent::end_element().into(), writer);
    }
    // write_event(XmlEvent::end_element().into(), writer);
    write_event(XmlEvent::end_element().into(), writer);
}
