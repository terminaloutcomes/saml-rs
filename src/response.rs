//! Want to build a SAML response? Here's your module. 🥳

// #![deny(unsafe_code)]

use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};

use std::io::Write;

use crate::utils::*;
use crate::xml::{write_event, ResponseAttribute};
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

#[derive(Debug)]
/// Stores all the required elements of a SAML response... maybe?
pub struct ResponseElements {
    // #[serde(rename = "Issuer")]
    /// Issuer of the resposne?
    // TODO: Figure out if this is right :P
    pub issuer: String,
    // #[serde(rename = "ID")]
    /// ID of the response
    /// TODO: Figure out the rules for generating this
    pub response_id: String,
    // #[serde(rename = "IssueInstant")]
    /// Issue time of the response
    pub issue_instant: DateTime<Utc>,
    // #[serde(rename = "InResponseTo")]
    /// RelayState from the original AuthN request
    pub relay_state: String,

    // #[serde(rename = "Attributes")]
    /// A list of relevant [ResponseAttribute]s
    pub attributes: Vec<ResponseAttribute>,
    // #[serde(rename = "Destination")]
    /// Destination endpoint of the request
    // TODO just like with the authnrequest, find out if destination is the right name/referecne
    pub destination: String,

    /// The [AuthNStatement] itself
    pub authnstatement: AuthNStatement,

    /// ID Of the assertion
    pub assertion_id: String,
}

#[derive(Debug)]
/// An Authentication Statement for returning inside an assertion
///
/// The expiry's optional
pub struct AuthNStatement {
    /// Issue time of the response
    /// TODO Figure out if this is different to the authnresponse?
    pub instant: DateTime<Utc>,
    /// TODO document this
    pub session_index: String,
    /// TODO: do we need to respond with multiple context class refs?
    pub classref: String,
    /// Expiry of the statement,
    /// TODO: find out if this is optional
    pub expiry: Option<DateTime<Utc>>,
}

impl AuthNStatement {
    #[allow(clippy::inherent_to_string)]

    /// Used elsewhere in the API to add an AuthNStatement to the Response XML
    pub fn add_to_xmlevent<W: Write>(&self, writer: &mut EventWriter<W>) {
        // start authn statement
        let _ = match self.expiry {
            Some(expiry) => write_event(
                XmlEvent::start_element(("saml", "AuthnStatement"))
                    .attr(
                        "AuthnInstant",
                        &self.instant.to_rfc3339_opts(SecondsFormat::Secs, true),
                    )
                    .attr(
                        "SessionNotOnOrAfter",
                        &expiry.to_rfc3339_opts(SecondsFormat::Secs, true),
                    )
                    .attr("SessionIndex", self.session_index.as_str())
                    .into(),
                writer,
            ),
            None => write_event(
                XmlEvent::start_element(("saml", "AuthnStatement"))
                    .attr(
                        "AuthnInstant",
                        &self.instant.to_rfc3339_opts(SecondsFormat::Secs, true),
                    )
                    .attr("SessionIndex", self.session_index.as_str())
                    .into(),
                writer,
            ),
        };

        write_event(
            XmlEvent::start_element(("saml", "AuthnContext")).into(),
            writer,
        );
        write_event(
            XmlEvent::start_element(("saml", "AuthnContextClassRef")).into(),
            writer,
        );
        write_event(XmlEvent::characters(self.classref.as_str()), writer);
        write_event(XmlEvent::end_element().into(), writer);
        write_event(XmlEvent::end_element().into(), writer);

        // end authn statement
        write_event(XmlEvent::end_element().into(), writer);

        // start attribute statement
        write_event(
            XmlEvent::start_element(("saml", "AttributeStatement")).into(),
            writer,
        );
    }
}

/// Adds the issuer statement to a response
fn add_issuer<W: Write>(issuer: &str, writer: &mut EventWriter<W>) {
    write_event(XmlEvent::start_element(("saml", "Issuer")).into(), writer);
    write_event(XmlEvent::characters(&issuer), writer);
    write_event(XmlEvent::end_element().into(), writer);
}

#[derive(Debug, Copy, Clone)]
enum BaseIDAbstractType {
    NameQualifier,
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

impl ToString for BaseIDAbstractType {
    fn to_string(&self) -> String {
        match self {
            BaseIDAbstractType::NameQualifier => String::from("NameQualifier"),
            BaseIDAbstractType::SPNameQualifier => String::from("SPNameQualifier"),
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

#[derive(Debug)]
/// Data type for passing subject data in because yeaaaaah, specs
///
/// TODO: Justify this better
struct SubjectData {
    relay_state: String,
    qualifier: Option<BaseIDAbstractType>,
    qualifier_value: Option<String>,
    nameid_format: crate::sp::NameIdFormat,
    nameid_value: &'static str,
    acs: &'static str,
    subject_not_on_or_after: DateTime<Utc>,
}

/// Adds the Subject statement to an assertion
fn add_subject<W: Write>(subjectdata: &SubjectData, writer: &mut EventWriter<W>) {
    // start subject statement
    write_event(XmlEvent::start_element(("saml", "Subject")).into(), writer);
    // start nameid statement
    // TODO: nameid can be 0 or more of NameQualifier or SPNameQualifier
    write_event(
        XmlEvent::start_element(("saml", "NameID"))
            .attr(
                subjectdata.qualifier.unwrap().to_string().as_str(),
                subjectdata.qualifier_value.as_ref().unwrap(),
            )
            .attr("Format", &subjectdata.nameid_format.to_string())
            .into(),
        writer,
    );

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
            .attr(
                "NotOnOrAfter",
                &subjectdata
                    .subject_not_on_or_after
                    .to_saml_datetime_string(),
            )
            .attr("Recipient", &subjectdata.acs)
            .attr("InResponseTo", &subjectdata.relay_state)
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

/// Adds a set of status tags to a response
///
/// Using the command thusly: `add_status("Success", &mut writer);` Will add this:
///
/// ```html
/// <samlp:Status>
///   <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
/// </samlp:Status>
/// ```
fn add_status<W: Write>(status: &str, writer: &mut EventWriter<W>) {
    write_event(XmlEvent::start_element(("samlp", "Status")).into(), writer);
    write_event(
        XmlEvent::start_element(("samlp", "StatusCode"))
            .attr(
                "Value",
                format!("urn:oasis:names:tc:SAML:2.0:status:{}", status).as_str(),
            )
            .into(),
        writer,
    );
    write_event(XmlEvent::end_element().into(), writer);
    write_event(XmlEvent::end_element().into(), writer);
}

/// returns the base64 encoded version of [create_response]
pub fn base64_encoded_response(data: ResponseElements, signed: bool) -> Vec<u8> {
    if signed {
        unimplemented!("Still need to do this bit.");
    }
    let buffer = create_response(data);
    base64::encode(buffer).into()
}

/// Creates a `samlp:Response` objects based on the input data ([ResponseElements]) you provide
pub fn create_response(data: ResponseElements) -> Vec<u8> {
    // TODO set up all these values
    let audience = String::from("http://sp.example.com/demo1/metadata.php");

    let conditions_not_before = String::from("2014-07-17T01:01:18Z");
    let conditions_not_after = String::from("2024-01-18T06:21:48Z");

    let mut buffer = Vec::new();
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .write_document_declaration(false)
        .create_writer(&mut buffer);

    // start of the response
    write_event(
        XmlEvent::start_element(("samlp", "Response"))
            .attr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
            .attr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
            .attr("ID", &data.response_id)
            .attr("Version", "2.0")
            .attr(
                "IssueInstant",
                &data
                    .issue_instant
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            )
            .attr("Destination", &data.destination)
            .attr("InResponseTo", &data.relay_state)
            .into(),
        &mut writer,
    );

    // issuer
    add_issuer(&data.issuer, &mut writer);

    let subjectdata = SubjectData {
        relay_state: data.relay_state,
        qualifier: Some(BaseIDAbstractType::SPNameQualifier),
        qualifier_value: Some(String::from("http://sp.example.com/demo1/metadata.php")),
        nameid_format: crate::sp::NameIdFormat::Transient,
        // in the unsigned response example this was a transient value _ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7
        nameid_value: "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
        acs: "http://sp.example.com/demo1/index.php?acs",
        subject_not_on_or_after: DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd(2024, 1, 18).and_hms(6, 21, 48),
            Utc,
        ),
    };

    // status
    add_status("Success", &mut writer);

    // start the assertion
    write_event(
        XmlEvent::start_element(("saml", "Assertion"))
            .attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
            .attr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
            .attr("ID", &data.assertion_id)
            .attr("Version", "2.0") // yeah, not going to support anything but 2.0 here. 😅
            .attr(
                "IssueInstant",
                &data
                    .issue_instant
                    .to_rfc3339_opts(SecondsFormat::Secs, true),
            )
            .into(),
        &mut writer,
    );

    // do the issuer inside the assertion
    add_issuer(&data.issuer, &mut writer);
    add_subject(&subjectdata, &mut writer);

    // start conditions statement
    write_event(
        XmlEvent::start_element(("saml", "Conditions"))
            // TODO: conditions_not_before
            .attr("NotBefore", &conditions_not_before)
            // TODO: conditions_not_after
            .attr("NotOnOrAfter", &conditions_not_after)
            .into(),
        &mut writer,
    );

    write_event(
        XmlEvent::start_element(("saml", "AudienceRestriction")).into(),
        &mut writer,
    );
    write_event(
        XmlEvent::start_element(("saml", "Audience")).into(),
        &mut writer,
    );
    write_event(XmlEvent::characters(&audience), &mut writer);
    write_event(XmlEvent::end_element().into(), &mut writer);
    write_event(XmlEvent::end_element().into(), &mut writer);
    // end conditions statement
    write_event(XmlEvent::end_element().into(), &mut writer);

    // To do an expiry in an hour, do this
    // let session_expiry = Utc::now().checked_add_signed(Duration::seconds(3600));

    data.authnstatement.add_to_xmlevent(&mut writer);

    for attribute in data.attributes {
        crate::xml::add_attribute(attribute, &mut writer);
    }

    // end attribute statement
    write_event(XmlEvent::end_element().into(), &mut writer);

    // end the assertion
    write_event(XmlEvent::end_element().into(), &mut writer);

    // end the response
    write_event(XmlEvent::end_element().into(), &mut writer);

    // finally we return the response
    buffer
}
