//! Want to build a SAML response? Here's your module. 🥳

// #![deny(unsafe_code)]

use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use std::io::Write;
use std::str::from_utf8;
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

use crate::assertion::{Assertion, AssertionAttribute, BaseIDAbstractType, SubjectData};
use crate::sign::{DigestAlgorithm, SigningAlgorithm};
use crate::sp::*;
use crate::xml::write_event;

#[derive(Debug)]
/// Stores all the required elements of a SAML response... maybe?
pub struct ResponseElements {
    //TODO: why do I have a response_id and an assertion_id?

    // #[serde(rename = "ID")]
    /// ID of the response
    /// TODO: Figure out the rules for generating this
    pub response_id: String,

    // #[serde(rename = "IssueInstant")]
    /// Issue time of the response
    pub issue_instant: DateTime<Utc>,

    // #[serde(rename = "Destination")]
    /// Destination endpoint of the request
    // TODO just like with the authnrequest, find out if destination is the right name/referecne
    pub destination: String,

    // #[serde(rename = "InResponseTo")]
    /// RelayState from the original AuthN request
    pub relay_state: String,

    // #[serde(rename = "Issuer")]
    /// Issuer of the resposne?
    // TODO: Figure out if this is right :P
    pub issuer: String,

    // #[serde(rename = "Attributes")]
    /// A list of relevant [AssertionAttribute]s
    pub attributes: Vec<AssertionAttribute>,

    /// The [AuthNStatement] itself
    pub authnstatement: AuthNStatement,

    /// ID Of the assertion
    pub assertion_id: String,

    /// [crate::sp::ServiceProvider]
    pub service_provider: ServiceProvider,

    /// TODO: Decide if we can just pick it from the SP
    pub assertion_consumer_service: Option<String>,

    /// Session length in seconds, 4294967295 should be enough for anyone! The default value is 60.
    pub session_length_seconds: u32,

    /// [crate::constants::StatusCode] of the response
    pub status: crate::constants::StatusCode,

    /// Should we sign the assertion?
    pub sign_assertion: bool,

    /// Should we sign the message?
    pub sign_message: bool,

    // TODO: remove the option for signing_key, it should always be set
    /// an openssl private key for signing
    pub signing_key: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    /// The signing certificate
    pub signing_cert: Option<openssl::x509::X509>,
}

use uuid::Uuid;

impl ResponseElements {
    /// returns the base64 encoded version of a [ResponseElements]
    pub fn base64_encoded_response(self) -> Vec<u8> {
        let buffer: Vec<u8> = self.into();
        base64::encode(buffer).into()
    }

    /// Default values, mostly so I can pull out a default assertion ID somewhere else, for now
    /// TODO: ResponseElements::default, yes.
    pub fn default() -> Self {
        let placeholder_authn_statement = AuthNStatement {
            instant: Utc::now(),
            session_index: String::from(
                "This is totally a placeholder session_index, why is this here?",
            ),
            classref: String::from("This is totally a placeholder classref, why is this here?"),
            expiry: None,
        };

        Self {
            assertion_id: Uuid::new_v4().to_string(),
            attributes: vec![],
            authnstatement: placeholder_authn_statement,
            destination: String::from("This should have been set"),
            issuer: String::from("This should have been set"),
            relay_state: String::from("This should have been set"),
            issue_instant: Utc::now(),
            service_provider: ServiceProvider::test_generic("foo"),
            response_id: Uuid::new_v4().to_string(),
            assertion_consumer_service: None,
            session_length_seconds: 60, // a minute is plenty to be able to consume the assertion
            status: crate::constants::StatusCode::AuthnFailed,
            sign_assertion: true,
            sign_message: false,
            signing_key: None,
            signing_cert: None,
        }
    }

    /// generate a response ID, which will be the issuer and uuid concatentated
    pub fn regenerate_response_id(self) -> Self {
        let response_id = format!("{}-{}", self.issuer, Uuid::new_v4().to_string());
        Self {
            assertion_id: self.assertion_id,
            attributes: self.attributes,
            authnstatement: self.authnstatement,
            destination: self.destination,
            issuer: self.issuer.to_string(),
            relay_state: self.relay_state,
            issue_instant: self.issue_instant,
            service_provider: self.service_provider,
            response_id,
            assertion_consumer_service: self.assertion_consumer_service,
            session_length_seconds: self.session_length_seconds,
            status: self.status,
            sign_assertion: self.sign_assertion,
            sign_message: self.sign_message,
            signing_key: self.signing_key,
            signing_cert: self.signing_cert,
        }
    }
}

// TODO: for signing, implement a "return this without signing flagged" fn so we can ... just get an unsigned version

/// Creates a String full of XML based on the ResponsElements
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for ResponseElements {
    fn into(self) -> Vec<u8> {
        // TODO set up all these values

        let conditions_not_before = Utc::now();

        let session_time = chrono::Duration::minutes(5);
        let conditions_not_after: DateTime<Utc> = conditions_not_before + session_time;

        let mut buffer = Vec::new();
        let mut writer = EmitterConfig::new()
            .perform_indent(true)
            .pad_self_closing(false)
            .write_document_declaration(false)
            .normalize_empty_elements(false)
            .create_writer(&mut buffer);

        let acs = match self.assertion_consumer_service {
            None => {
                match self.service_provider.find_first_acs() {
                    Ok(value) => value.location,
                    Err(error) => {
                        eprintln!("{:?}, falling back to https://example.com", error);
                        ServiceBinding::default().location
                    } // TODO work out how to set an ACS if we fall through a) not setting it b) not finding one
                }
            }
            Some(value) => value,
        };

        let subject_data = SubjectData {
            relay_state: self.relay_state.clone(),
            qualifier: Some(BaseIDAbstractType::SPNameQualifier),
            qualifier_value: Some(self.service_provider.entity_id.to_string()),
            nameid_format: NameIdFormat::Transient,
            // in the unsigned response example this was a transient value _ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7
            // TODO: nameid_valud for SubjectData should... be actually set from somewhere
            nameid_value: "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
            // TODO acs should come from somewhere, figure out where
            acs,
            // TODO: set the response not_on_or_after properly
            subject_not_on_or_after: DateTime::<Utc>::from_utc(
                NaiveDate::from_ymd(2024, 1, 18).and_hms(6, 21, 48),
                Utc,
            ),
        };

        let assertion_data = Assertion {
            assertion_id: self.assertion_id.to_string(),
            issuer: self.issuer.to_string(),
            signing_algorithm: SigningAlgorithm::Sha256,
            digest_algorithm: DigestAlgorithm::Sha256,
            issue_instant: self.issue_instant,
            subject_data,

            attributes: self.attributes,
            audience: self.service_provider.entity_id.to_string(),
            conditions_not_after,
            conditions_not_before,
            sign_assertion: self.sign_assertion,
            signing_key: self.signing_key,
            signing_cert: self.signing_cert,
        };

        // start of the response
        write_event(
            XmlEvent::start_element(("samlp", "Response"))
                .attr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
                .attr("Destination", &self.destination)
                .attr("ID", &self.response_id)
                .attr("InResponseTo", &self.relay_state)
                .attr(
                    "IssueInstant",
                    &self
                        .issue_instant
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                )
                .attr("Version", "2.0")
                .into(),
            &mut writer,
        );

        // do the issuer inside the assertion
        // add_issuer(&self.issuer, &mut writer);

        // If we're signing the MESSAGE, we'd add the signing block here.
        //
        // Signatures for assertions go \/ down there in the assertion statement.
        //
        // crate::xml::add_signature(assertion_data, &mut writer);

        // status
        let status = crate::constants::StatusCode::Success.to_string();
        add_status(&status, &mut writer);

        // assertion goes here

        assertion_data.add_assertion_to_xml(&mut writer);

        // end the response
        write_event(XmlEvent::end_element().into(), &mut writer);

        // finally we return the response
        log::debug!("OUTPUT RESPONSE");
        log::debug!("{}", from_utf8(&buffer).unwrap());
        buffer
    }
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
    }
}

/// Adds the issuer statement to a response
pub fn add_issuer<W: Write>(issuer: &str, writer: &mut EventWriter<W>) {
    write_event(XmlEvent::start_element(("saml", "Issuer")).into(), writer);
    write_event(XmlEvent::characters(&issuer), writer);
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
