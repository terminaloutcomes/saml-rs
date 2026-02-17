//! Want to build a SAML response? Here's your module. 🥳

// #![deny(unsafe_code)]

use crate::assertion::{Assertion, AssertionAttribute, BaseIDAbstractType, SubjectData};
use crate::sign::{DigestAlgorithm, SigningAlgorithm};
use crate::sp::*;
use crate::xml::write_event;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use log::{debug, error};
use std::io::Write;
use std::str::from_utf8;
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

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

/// A builder for [ResponseElements] that validates required fields before creation.
#[derive(Debug)]
pub struct ResponseElementsBuilder {
    response_id: Option<String>,
    issue_instant: Option<DateTime<Utc>>,
    destination: Option<String>,
    relay_state: Option<String>,
    issuer: Option<String>,
    attributes: Vec<AssertionAttribute>,
    authnstatement: Option<AuthNStatement>,
    assertion_id: Option<String>,
    service_provider: Option<ServiceProvider>,
    assertion_consumer_service: Option<String>,
    session_length_seconds: u32,
    status: crate::constants::StatusCode,
    sign_assertion: bool,
    sign_message: bool,
    signing_key: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    signing_cert: Option<openssl::x509::X509>,
}

impl ResponseElementsBuilder {
    /// Creates an empty builder.
    pub fn new() -> Self {
        Self {
            response_id: None,
            issue_instant: None,
            destination: None,
            relay_state: None,
            issuer: None,
            attributes: vec![],
            authnstatement: None,
            assertion_id: None,
            service_provider: None,
            assertion_consumer_service: None,
            session_length_seconds: 60,
            status: crate::constants::StatusCode::AuthnFailed,
            sign_assertion: true,
            sign_message: false,
            signing_key: None,
            signing_cert: None,
        }
    }

    /// Sets the response ID.
    pub fn response_id(mut self, response_id: impl Into<String>) -> Self {
        self.response_id = Some(response_id.into());
        self
    }

    /// Sets the issue instant.
    pub fn issue_instant(mut self, issue_instant: DateTime<Utc>) -> Self {
        self.issue_instant = Some(issue_instant);
        self
    }

    /// Sets the destination URL.
    pub fn destination(mut self, destination: impl Into<String>) -> Self {
        self.destination = Some(destination.into());
        self
    }

    /// Sets the relay state.
    pub fn relay_state(mut self, relay_state: impl Into<String>) -> Self {
        self.relay_state = Some(relay_state.into());
        self
    }

    /// Sets the response issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Sets assertion attributes.
    pub fn attributes(mut self, attributes: Vec<AssertionAttribute>) -> Self {
        self.attributes = attributes;
        self
    }

    /// Sets the authn statement.
    pub fn authnstatement(mut self, authnstatement: AuthNStatement) -> Self {
        self.authnstatement = Some(authnstatement);
        self
    }

    /// Sets the assertion ID.
    pub fn assertion_id(mut self, assertion_id: impl Into<String>) -> Self {
        self.assertion_id = Some(assertion_id.into());
        self
    }

    /// Sets the service provider.
    pub fn service_provider(mut self, service_provider: ServiceProvider) -> Self {
        self.service_provider = Some(service_provider);
        self
    }

    /// Sets the assertion consumer service URL.
    pub fn assertion_consumer_service(
        mut self,
        assertion_consumer_service: Option<String>,
    ) -> Self {
        self.assertion_consumer_service = assertion_consumer_service;
        self
    }

    /// Sets the session length in seconds.
    pub fn session_length_seconds(mut self, session_length_seconds: u32) -> Self {
        self.session_length_seconds = session_length_seconds;
        self
    }

    /// Sets the SAML status code.
    pub fn status(mut self, status: crate::constants::StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Enables or disables assertion signing.
    pub fn sign_assertion(mut self, sign_assertion: bool) -> Self {
        self.sign_assertion = sign_assertion;
        self
    }

    /// Enables or disables message signing.
    pub fn sign_message(mut self, sign_message: bool) -> Self {
        self.sign_message = sign_message;
        self
    }

    /// Sets the private key used for signing.
    pub fn signing_key(
        mut self,
        signing_key: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    ) -> Self {
        self.signing_key = signing_key;
        self
    }

    /// Sets the X509 certificate used for signing.
    pub fn signing_cert(mut self, signing_cert: Option<openssl::x509::X509>) -> Self {
        self.signing_cert = signing_cert;
        self
    }

    /// Builds [ResponseElements] after validating required values.
    pub fn build(self) -> Result<ResponseElements, &'static str> {
        let issuer = required_non_empty(self.issuer, "issuer")?;
        let destination = required_non_empty(self.destination, "destination")?;
        let relay_state = required_non_empty(self.relay_state, "relay_state")?;
        let authnstatement = required(self.authnstatement, "authnstatement")?;
        let service_provider = required(self.service_provider, "service_provider")?;

        if self.session_length_seconds == 0 {
            return Err("session_length_seconds must be greater than 0");
        }

        if self.sign_assertion || self.sign_message {
            if self.signing_key.is_none() {
                return Err("signing_key must be set when signing is enabled");
            }
            if self.signing_cert.is_none() {
                return Err("signing_cert must be set when signing is enabled");
            }
        }

        let assertion_id = match self.assertion_id {
            Some(value) if !value.trim().is_empty() => value,
            Some(_) => return Err("assertion_id must not be empty"),
            None => ResponseElements::new_assertion_id(),
        };
        let response_id = match self.response_id {
            Some(value) if !value.trim().is_empty() => value,
            Some(_) => return Err("response_id must not be empty"),
            None => ResponseElements::new_response_id(),
        };

        Ok(ResponseElements {
            response_id,
            issue_instant: self.issue_instant.unwrap_or_else(Utc::now),
            destination,
            relay_state,
            issuer,
            attributes: self.attributes,
            authnstatement,
            assertion_id,
            service_provider,
            assertion_consumer_service: self.assertion_consumer_service,
            session_length_seconds: self.session_length_seconds,
            status: self.status,
            sign_assertion: self.sign_assertion,
            sign_message: self.sign_message,
            signing_key: self.signing_key,
            signing_cert: self.signing_cert,
        })
    }
}

impl Default for ResponseElementsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, &'static str> {
    match value {
        Some(value) => Ok(value),
        None => Err(field),
    }
}

fn required_non_empty(value: Option<String>, field: &'static str) -> Result<String, &'static str> {
    let value = required(value, field)?;
    if value.trim().is_empty() {
        return Err(field);
    }
    Ok(value)
}

use uuid::Uuid;

impl ResponseElements {
    /// Creates a new [ResponseElementsBuilder].
    pub fn builder() -> ResponseElementsBuilder {
        ResponseElementsBuilder::new()
    }

    /// Creates a random assertion ID.
    pub fn new_assertion_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// Creates a random SAML-safe response ID.
    pub fn new_response_id() -> String {
        format!("_{}", Uuid::new_v4())
    }

    /// returns the base64 encoded version of a [ResponseElements]
    pub fn base64_encoded_response(self) -> Vec<u8> {
        let buffer: Vec<u8> = self.into();
        BASE64_STANDARD.encode(buffer).into()
    }

    /// Generates a new random response ID.
    pub fn regenerate_response_id(self) -> Self {
        let response_id = Self::new_response_id();
        Self {
            response_id,
            ..self
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
                        error!("{:?}, falling back to https://example.com", error);
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
            subject_not_on_or_after: Utc
                .with_ymd_and_hms(2024, 1, 18, 6, 21, 48)
                .single()
                .unwrap_or_else(Utc::now),
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
        debug!("OUTPUT RESPONSE");
        match from_utf8(&buffer) {
            Ok(value) => debug!("{}", value),
            Err(error) => error!("Failed to decode response as utf8: {:?}", error),
        }
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
    write_event(XmlEvent::characters(issuer), writer);
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
