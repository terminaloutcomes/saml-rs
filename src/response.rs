//! Want to build a SAML response? Here's your module. 🥳

// #![deny(unsafe_code)]

use crate::assertion::{Assertion, AssertionAttribute, BaseIDAbstractType, SubjectData};
use crate::sign::{CanonicalizationMethod, DigestAlgorithm, SigningAlgorithm};
use crate::sp::*;
use crate::xml::write_event;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use log::error;
use std::io::Write;
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

    /// an openssl private key for signing
    pub signing_key: openssl::pkey::PKey<openssl::pkey::Private>,
    /// The signing certificate
    pub signing_cert: Option<openssl::x509::X509>,
    /// Signature algorithm for assertion/message signing.
    pub signing_algorithm: SigningAlgorithm,
    /// Digest algorithm for assertion/message signing.
    pub digest_algorithm: DigestAlgorithm,
    /// Canonicalization method for assertion/message signing.
    pub canonicalization_method: CanonicalizationMethod,
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
    signing_algorithm: SigningAlgorithm,
    digest_algorithm: DigestAlgorithm,
    canonicalization_method: CanonicalizationMethod,
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
            sign_message: true,
            signing_key: None,
            signing_cert: None,
            signing_algorithm: SigningAlgorithm::Sha256,
            digest_algorithm: DigestAlgorithm::Sha256,
            canonicalization_method: CanonicalizationMethod::ExclusiveCanonical10,
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

    /// Sets the signature algorithm.
    pub fn signing_algorithm(mut self, signing_algorithm: SigningAlgorithm) -> Self {
        self.signing_algorithm = signing_algorithm;
        self
    }

    /// Sets the digest algorithm.
    pub fn digest_algorithm(mut self, digest_algorithm: DigestAlgorithm) -> Self {
        self.digest_algorithm = digest_algorithm;
        self
    }

    /// Sets canonicalization method.
    pub fn canonicalization_method(
        mut self,
        canonicalization_method: CanonicalizationMethod,
    ) -> Self {
        self.canonicalization_method = canonicalization_method;
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
        let Some(signing_key) = self.signing_key else {
            return Err("signing_key must be set when signing is enabled");
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
            signing_key,
            signing_cert: self.signing_cert,
            signing_algorithm: self.signing_algorithm,
            digest_algorithm: self.digest_algorithm,
            canonicalization_method: self.canonicalization_method,
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
        match self.try_base64_encoded_response() {
            Ok(value) => value,
            Err(error) => {
                error!("Failed to encode SAML response: {}", error);
                Vec::new()
            }
        }
    }

    /// Returns the base64 encoded version of [ResponseElements] or an error.
    pub fn try_base64_encoded_response(self) -> Result<Vec<u8>, String> {
        let buffer = self.try_into_xml_bytes()?;
        Ok(BASE64_STANDARD.encode(buffer).into())
    }

    /// Generates a new random response ID.
    pub fn regenerate_response_id(self) -> Self {
        let response_id = Self::new_response_id();
        Self {
            response_id,
            ..self
        }
    }

    fn build_assertion(&self) -> Assertion {
        let conditions_not_before = Utc::now();
        let session_time = chrono::Duration::minutes(5);
        let conditions_not_after: DateTime<Utc> = conditions_not_before + session_time;
        let acs = match self.assertion_consumer_service.clone() {
            None => match self.service_provider.find_first_acs() {
                Ok(value) => value.location,
                Err(error) => {
                    error!("{:?}, falling back to https://example.com", error);
                    ServiceBinding::default().location
                }
            },
            Some(value) => value,
        };

        let subject_data = SubjectData {
            relay_state: self.relay_state.clone(),
            qualifier: Some(BaseIDAbstractType::SPNameQualifier),
            qualifier_value: Some(self.service_provider.entity_id.to_string()),
            nameid_format: NameIdFormat::Transient,
            nameid_value: "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
            acs,
            subject_not_on_or_after: Utc
                .with_ymd_and_hms(2024, 1, 18, 6, 21, 48)
                .single()
                .unwrap_or_else(Utc::now),
        };

        Assertion {
            assertion_id: self.assertion_id.to_string(),
            issuer: self.issuer.to_string(),
            signing_algorithm: self.signing_algorithm,
            digest_algorithm: self.digest_algorithm,
            canonicalization_method: self.canonicalization_method,
            issue_instant: self.issue_instant,
            subject_data,
            attributes: self.attributes.clone(),
            audience: self.service_provider.entity_id.to_string(),
            conditions_not_after,
            conditions_not_before,
            sign_assertion: self.sign_assertion,
            signing_key: Some(self.signing_key.clone()),
            signing_cert: self.signing_cert.clone(),
        }
    }

    fn build_response_xml(
        &self,
        assertion_data: &Assertion,
        message_signature: Option<(&str, &str)>,
    ) -> Result<Vec<u8>, String> {
        let mut buffer = Vec::new();
        let mut writer = EmitterConfig::new()
            .perform_indent(false)
            .pad_self_closing(false)
            .write_document_declaration(false)
            .normalize_empty_elements(false)
            .create_writer(&mut buffer);

        let response_issue_instant = self
            .issue_instant
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        write_event(
            XmlEvent::start_element(("samlp", "Response"))
                .attr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
                .attr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
                .attr("Destination", &self.destination)
                .attr("ID", &self.response_id)
                .attr("InResponseTo", &self.relay_state)
                .attr("IssueInstant", &response_issue_instant)
                .attr("Version", "2.0")
                .into(),
            &mut writer,
        );
        add_issuer(&self.issuer, &mut writer);

        if let Some((digest_value, signature_value)) = message_signature {
            let signature_config = crate::xml::SignatureConfig {
                reference_id: self.response_id.clone(),
                signing_algorithm: self.signing_algorithm,
                digest_algorithm: self.digest_algorithm,
                canonicalization_method: self.canonicalization_method,
                signing_cert: self.signing_cert.clone(),
            };
            crate::xml::add_signature(
                &signature_config,
                digest_value,
                signature_value,
                &mut writer,
            )?;
        }

        let status = self.status.to_string();
        add_status(&status, &mut writer);
        assertion_data.add_assertion_to_xml(&mut writer)?;
        write_event(XmlEvent::end_element().into(), &mut writer);

        Ok(buffer)
    }

    /// Render response XML bytes.
    pub fn try_into_xml_bytes(self) -> Result<Vec<u8>, String> {
        let assertion_data = self.build_assertion();
        let unsigned_response = self.build_response_xml(&assertion_data, None)?;
        if !self.sign_message {
            return Ok(unsigned_response);
        }

        let signing_key = &self.signing_key;
        if self.signing_cert.is_none() {
            return Err("signing_cert must be set when signing is enabled".to_string());
        }

        let unsigned_xml = String::from_utf8(unsigned_response)
            .map_err(|error| format!("Response XML was not utf8: {:?}", error))?;
        let canonical_response = self.canonicalization_method.canonicalize(&unsigned_xml)?;
        let digest_bytes = self
            .digest_algorithm
            .hash(canonical_response.as_bytes())
            .map_err(|error| format!("Failed to hash canonical response: {:?}", error))?;
        let base64_digest = BASE64_STANDARD.encode(digest_bytes);

        let signature_config = crate::xml::SignatureConfig {
            reference_id: self.response_id.clone(),
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
        crate::xml::generate_signedinfo(&signature_config, &base64_digest, &mut signedinfo_writer);
        let signedinfo_xml = String::from_utf8(signedinfo_buffer)
            .map_err(|error| format!("SignedInfo was not utf8: {:?}", error))?;
        let canonical_signedinfo = self.canonicalization_method.canonicalize(&signedinfo_xml)?;
        let signed = crate::sign::sign_data(
            self.signing_algorithm,
            signing_key,
            canonical_signedinfo.as_bytes(),
        );
        if signed.is_empty() {
            return Err("Failed to generate message signature bytes".to_string());
        }
        let base64_signature = BASE64_STANDARD.encode(&signed);

        self.build_response_xml(&assertion_data, Some((&base64_digest, &base64_signature)))
    }
}

// TODO: for signing, implement a "return this without signing flagged" fn so we can ... just get an unsigned version

/// Creates a String full of XML based on the ResponsElements
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for ResponseElements {
    fn into(self) -> Vec<u8> {
        match self.try_into_xml_bytes() {
            Ok(value) => value,
            Err(error) => {
                error!("Failed to render response XML: {}", error);
                Vec::new()
            }
        }
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
