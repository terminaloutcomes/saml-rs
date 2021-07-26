//! Want to build a SAML response? Here's your module. 🥳

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use std::io::Write;

use crate::xmlutils::write_event;
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

#[derive(Debug)]
/// Stores all the required elements of a SAML response... maybe?
pub struct ResponseElements {
    // #[serde(rename = "Issuer")]
    pub issuer: String,
    // #[serde(rename = "ID")]
    pub response_id: String,
    // #[serde(rename = "IssueInstant")]
    pub issue_instant: DateTime<Utc>,
    // #[serde(rename = "InResponseTo")]
    pub request_id: String,

    // #[serde(rename = "Attributes")]
    pub attributes: Vec<ResponseAttribute>,
    // #[serde(rename = "Destination")]
    pub destination: String,

    pub authnstatement: AuthNStatement,

    pub assertion_id: String,
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

#[derive(Debug)]
/// An Authentication Statement for returning inside an assertion
///
/// The expiry's optional
pub struct AuthNStatement {
    pub instant: DateTime<Utc>,
    pub session_index: String,
    // TODO: do we need to respond with multiple context class refs?
    pub classref: String,
    pub expiry: Option<DateTime<Utc>>,
}

impl AuthNStatement {
    #[allow(clippy::inherent_to_string)]
    /// Formats it all pretty-like, in XML
    pub fn to_string(&self) -> String {
        // TODO: change this to a display thing, or remove it?
        let expiry: String = match self.expiry {
            Some(value) => format!(" SessionNotOnOrAfter=\"{}\"", value),
            _ => "".to_string(),
        };
        format!(
            r#"<saml:AuthnStatement
    AuthnInstant="{}"
    SessionIndex="{}"{}>
  <saml:AuthnContext>
    <saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>
  </saml:AuthnContext>
</saml:AuthnStatement>"#,
            self.instant, self.session_index, expiry, self.classref
        )
    }

    /// Used elsewhere in the API to add it to the Response XML
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

/// add an attribute to the statement
fn add_attribute<W: Write>(attr: ResponseAttribute, writer: &mut EventWriter<W>) {
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
            .attr("InResponseTo", &data.request_id)
            .into(),
        &mut writer,
    );

    // issuer
    add_issuer(&data.issuer, &mut writer);

    // status
    add_status("Success", &mut writer);

    // start the assertion
    write_event(
        XmlEvent::start_element(("saml", "Assertion"))
            .attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
            .attr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
            .attr("ID", &data.assertion_id)
            .attr("Version", "2.0")
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

    // start subject statement
    write_event(
        XmlEvent::start_element(("saml", "Subject")).into(),
        &mut writer,
    );
    // start nameid statement
    write_event(
        XmlEvent::start_element(("saml", "NameID"))
            .attr(
                "SPNameQualifier",
                "http://sp.example.com/demo1/metadata.php",
            )
            .attr(
                "Format",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            )
            .into(),
        &mut writer,
    );

    write_event(
        XmlEvent::characters("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"),
        &mut writer,
    );
    // end nameid statement
    write_event(XmlEvent::end_element().into(), &mut writer);

    //start subjectconfirmation
    write_event(
        XmlEvent::start_element(("saml", "SubjectConfirmation"))
            .attr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
            .into(),
        &mut writer,
    );

    //start subjectconfirmationdata
    write_event(
        XmlEvent::start_element(("saml", "SubjectConfirmationData"))
            .attr("NotOnOrAfter", "2024-01-18T06:21:48Z")
            .attr("Recipient", "http://sp.example.com/demo1/index.php?acs")
            .attr("InResponseTo", &data.request_id)
            .into(),
        &mut writer,
    );

    //end subjectconfirmationdata
    write_event(XmlEvent::end_element().into(), &mut writer);
    //end subjectconfirmation
    write_event(XmlEvent::end_element().into(), &mut writer);

    write_event(XmlEvent::end_element().into(), &mut writer);
    // end subject statement

    // start conditions statement
    write_event(
        XmlEvent::start_element(("saml", "Conditions"))
            // TODO: conditions_not_before
            .attr("NotBefore", "2014-07-17T01:01:18Z")
            // TODO: conditions_not_after
            .attr("NotOnOrAfter", "2024-01-18T06:21:48Z")
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
    write_event(
        XmlEvent::characters("http://sp.example.com/demo1/metadata.php"),
        &mut writer,
    );
    write_event(XmlEvent::end_element().into(), &mut writer);
    write_event(XmlEvent::end_element().into(), &mut writer);
    // end conditions statement
    write_event(XmlEvent::end_element().into(), &mut writer);

    // To do an expiry in an hour, do this
    // let session_expiry = Utc::now().checked_add_signed(Duration::seconds(3600));

    data.authnstatement.add_to_xmlevent(&mut writer);

    for attribute in data.attributes {
        add_attribute(attribute, &mut writer);
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
