//! Want to build a SAML response? Here's your module. 🥳

// #![deny(unsafe_code)]

use crate::assertion::{Assertion, AssertionAttribute, BaseIDAbstractType, SubjectData};
use crate::error::SamlError;
use crate::sign::{CanonicalizationMethod, DigestAlgorithm, SamlSigningKey, SigningAlgorithm};
use crate::sp::*;
use crate::xml::write_event;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, SecondsFormat, Utc};
use log::error;
use std::io::Write;
use std::sync::Arc;
use x509_cert::Certificate;
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};
use xmlparser::{ElementEnd, Token};

/// Stores all the required elements of a SAML response... maybe?
pub struct ResponseElements {
    // TODO why do I have a response_id and an assertion_id?

    // #[serde(rename = "ID")]
    /// ID of the response
    /// TODO Figure out the rules for generating this
    pub response_id: String,

    // #[serde(rename = "IssueInstant")]
    /// Issue time of the response
    pub issue_instant: DateTime<Utc>,

    // #[serde(rename = "Destination")]
    /// Destination endpoint of the request
    // TODO just like with the authnrequest, find out if destination is the right name/reference
    pub destination: String,

    // #[serde(rename = "InResponseTo")]
    /// AuthnRequest ID from the original request, serialized as InResponseTo.
    pub in_response_to: String,

    // #[serde(rename = "Issuer")]
    /// Issuer of the response?
    // TODO Figure out if this is right :P
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

    /// Value to place in Subject/NameID.
    pub nameid_value: String,

    /// TODO Decide if we can just pick it from the SP
    pub assertion_consumer_service: Option<String>,

    /// Session length in seconds, 4294967295 should be enough for anyone! The default value is 60.
    pub session_length_seconds: u32,

    /// [crate::constants::StatusCode] of the response
    pub status: crate::constants::StatusCode,

    /// Should we sign the assertion?
    pub sign_assertion: bool,

    /// Should we sign the message?
    pub sign_message: bool,
    /// a private key for signing
    signing_key: Arc<SamlSigningKey>,
    /// The signing certificate
    signing_cert: Option<Certificate>,
    /// Signature algorithm for assertion/message signing.
    pub signing_algorithm: SigningAlgorithm,
    /// Digest algorithm for assertion/message signing.
    pub digest_algorithm: DigestAlgorithm,
    /// Canonicalization method for assertion/message signing.
    pub canonicalization_method: CanonicalizationMethod,
}

/// Parsed core fields from an incoming SAML Response XML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedResponse {
    /// `Response/@ID`
    pub response_id: String,
    /// `Response/@InResponseTo`
    pub in_response_to: String,
    /// `Response/@Destination`
    pub destination: String,
    /// `Issuer` text content
    pub issuer: String,
    /// `StatusCode/@Value`
    pub status_code: String,
}

/// Parses a SAML Response XML payload and extracts core response fields.
pub fn parse_response_xml(response_xml: &str) -> Result<ParsedResponse, SamlError> {
    if let Err(error) = crate::security::inspect_xml_payload(
        response_xml,
        crate::security::SecurityPolicy::default()
            .effective()
            .xml_limits,
    ) {
        return Err(SamlError::Security(error));
    }

    let mut depth = 0usize;
    let mut current_element = String::new();
    let mut response_depth: Option<usize> = None;

    let mut response_id: Option<String> = None;
    let mut in_response_to: Option<String> = None;
    let mut destination: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut status_code: Option<String> = None;

    for token in xmlparser::Tokenizer::from(response_xml) {
        match token {
            Ok(Token::ElementStart { local, .. }) => {
                depth = depth.saturating_add(1);
                current_element = local.as_str().to_string();
                if current_element.eq_ignore_ascii_case("Response") {
                    if response_depth.is_some() {
                        return Err(SamlError::XmlParsing(
                            "Response XML contains duplicate or nested Response roots".to_string(),
                        ));
                    }
                    response_depth = Some(depth);
                }
            }
            Ok(Token::Attribute { local, value, .. }) => {
                let in_response_root = response_depth == Some(depth)
                    && current_element.eq_ignore_ascii_case("Response");
                if in_response_root {
                    if local.as_str().eq_ignore_ascii_case("ID") {
                        if response_id.is_some() {
                            return Err(SamlError::XmlParsing(
                                "Response XML contains duplicate ID attribute".to_string(),
                            ));
                        }
                        response_id = Some(value.as_str().to_string());
                    } else if local.as_str().eq_ignore_ascii_case("InResponseTo") {
                        if in_response_to.is_some() {
                            return Err(SamlError::XmlParsing(
                                "Response XML contains duplicate InResponseTo attribute"
                                    .to_string(),
                            ));
                        }
                        in_response_to = Some(value.as_str().to_string());
                    } else if local.as_str().eq_ignore_ascii_case("Destination") {
                        if destination.is_some() {
                            return Err(SamlError::XmlParsing(
                                "Response XML contains duplicate Destination attribute".to_string(),
                            ));
                        }
                        destination = Some(value.as_str().to_string());
                    }
                }

                if current_element.eq_ignore_ascii_case("StatusCode")
                    && local.as_str().eq_ignore_ascii_case("Value")
                {
                    if status_code.is_some() {
                        return Err(SamlError::XmlParsing(
                            "Response XML contains duplicate StatusCode values".to_string(),
                        ));
                    }
                    status_code = Some(value.as_str().to_string());
                }
            }
            Ok(Token::Text { text }) => {
                let in_response_issuer = response_depth.is_some()
                    && depth == response_depth.unwrap_or_default() + 1
                    && current_element.eq_ignore_ascii_case("Issuer");
                if in_response_issuer {
                    let trimmed = text.as_str().trim();
                    if !trimmed.is_empty() {
                        if issuer.is_some() {
                            return Err(SamlError::XmlParsing(
                                "Response XML contains duplicate Issuer values".to_string(),
                            ));
                        }
                        issuer = Some(trimmed.to_string());
                    }
                }
            }
            Ok(Token::ElementEnd { end, .. }) => {
                let mut closed_response = false;
                match end {
                    ElementEnd::Open => {}
                    ElementEnd::Empty | ElementEnd::Close(_, _) => {
                        if response_depth == Some(depth)
                            && current_element.eq_ignore_ascii_case("Response")
                        {
                            closed_response = true;
                        }
                        depth = depth.saturating_sub(1);
                        current_element.clear();
                    }
                }
                if closed_response {
                    response_depth = None;
                }
            }
            Ok(_) => {}
            Err(error) => {
                return Err(SamlError::XmlParsing(format!(
                    "Failed to parse response XML: {}",
                    error
                )));
            }
        }
    }

    Ok(ParsedResponse {
        response_id: response_id
            .ok_or_else(|| SamlError::XmlParsing("Response/@ID missing".to_string()))?,
        in_response_to: in_response_to
            .ok_or_else(|| SamlError::XmlParsing("Response/@InResponseTo missing".to_string()))?,
        destination: destination
            .ok_or_else(|| SamlError::XmlParsing("Response/@Destination missing".to_string()))?,
        issuer: issuer.ok_or_else(|| SamlError::XmlParsing("Issuer missing".to_string()))?,
        status_code: status_code
            .ok_or_else(|| SamlError::XmlParsing("StatusCode/@Value missing".to_string()))?,
    })
}

impl std::fmt::Debug for ResponseElements {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseElements")
            .field("response_id", &self.response_id)
            .field("issue_instant", &self.issue_instant)
            .field("destination", &self.destination)
            .field("in_response_to", &self.in_response_to)
            .field("issuer", &self.issuer)
            .field("attributes", &self.attributes)
            .field("authnstatement", &self.authnstatement)
            .field("assertion_id", &self.assertion_id)
            .field("service_provider", &self.service_provider)
            .field("nameid_value", &self.nameid_value)
            .field(
                "assertion_consumer_service",
                &self.assertion_consumer_service,
            )
            .field("session_length_seconds", &self.session_length_seconds)
            .field("status", &self.status)
            .field("sign_assertion", &self.sign_assertion)
            .field("sign_message", &self.sign_message)
            // skipping signing_key and signing_cert for debug output since they can be large and not very informative
            .finish()
    }
}

/// A builder for [ResponseElements] that validates required fields before creation.
pub struct ResponseElementsBuilder {
    response_id: Option<String>,
    issue_instant: Option<DateTime<Utc>>,
    destination: Option<String>,
    in_response_to: Option<String>,
    issuer: Option<String>,
    attributes: Vec<AssertionAttribute>,
    authnstatement: Option<AuthNStatement>,
    assertion_id: Option<String>,
    service_provider: Option<ServiceProvider>,
    nameid_value: Option<String>,
    assertion_consumer_service: Option<String>,
    session_length_seconds: u32,
    status: crate::constants::StatusCode,
    sign_assertion: bool,
    sign_message: bool,
    signing_key: Arc<SamlSigningKey>,
    signing_cert: Option<x509_cert::Certificate>,
    signing_algorithm: SigningAlgorithm,
    digest_algorithm: DigestAlgorithm,
    canonicalization_method: CanonicalizationMethod,
}

impl std::fmt::Debug for ResponseElementsBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseElementsBuilder")
            .field("response_id", &self.response_id)
            .field("issue_instant", &self.issue_instant)
            .field("destination", &self.destination)
            .field("in_response_to", &self.in_response_to)
            .field("issuer", &self.issuer)
            .field("attributes", &self.attributes)
            .field("authnstatement", &self.authnstatement)
            .field("assertion_id", &self.assertion_id)
            .field("service_provider", &self.service_provider)
            .field("nameid_value", &self.nameid_value)
            .field(
                "assertion_consumer_service",
                &self.assertion_consumer_service,
            )
            .field("session_length_seconds", &self.session_length_seconds)
            .field("status", &self.status)
            .field("sign_assertion", &self.sign_assertion)
            .field("sign_message", &self.sign_message)
            // skipping signing_key and signing_cert for debug output since they can be large and not very informative
            .finish()
    }
}

impl ResponseElementsBuilder {
    /// Creates an empty builder.
    pub fn new() -> Self {
        Self {
            response_id: None,
            issue_instant: None,
            destination: None,
            in_response_to: None,
            issuer: None,
            attributes: vec![],
            authnstatement: None,
            assertion_id: None,
            service_provider: None,
            nameid_value: None,
            assertion_consumer_service: None,
            session_length_seconds: 60,
            status: crate::constants::StatusCode::AuthnFailed,
            sign_assertion: true,
            sign_message: true,
            signing_key: SamlSigningKey::None.into(),
            signing_cert: None,
            signing_algorithm: SigningAlgorithm::RsaSha256,
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

    /// Sets the AuthnRequest ID this response corresponds to.
    pub fn in_response_to(mut self, in_response_to: impl Into<String>) -> Self {
        self.in_response_to = Some(in_response_to.into());
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
    pub fn authnstatement(self, authnstatement: AuthNStatement) -> Self {
        Self {
            authnstatement: Some(authnstatement),
            ..self
        }
    }

    /// Sets the assertion ID.
    pub fn assertion_id(self, assertion_id: impl Into<String>) -> Self {
        Self {
            assertion_id: Some(assertion_id.into()),
            ..self
        }
    }

    /// Sets the service provider.
    pub fn service_provider(self, service_provider: ServiceProvider) -> Self {
        Self {
            service_provider: Some(service_provider),
            ..self
        }
    }

    /// Sets the NameID value to place in Subject.
    pub fn nameid_value(self, nameid_value: impl Into<String>) -> Self {
        Self {
            nameid_value: Some(nameid_value.into()),
            ..self
        }
    }

    /// Sets the assertion consumer service URL.
    pub fn assertion_consumer_service(self, assertion_consumer_service: Option<String>) -> Self {
        Self {
            assertion_consumer_service,
            ..self
        }
    }

    /// Sets the session length in seconds.
    pub fn session_length_seconds(self, session_length_seconds: u32) -> Self {
        Self {
            session_length_seconds,
            ..self
        }
    }

    /// Sets the SAML status code.
    pub fn status(self, status: crate::constants::StatusCode) -> Self {
        Self { status, ..self }
    }

    /// Enables or disables assertion signing.
    pub fn sign_assertion(self, sign_assertion: bool) -> Self {
        Self {
            sign_assertion,
            ..self
        }
    }

    /// Enables or disables message signing.
    pub fn sign_message(self, sign_message: bool) -> Self {
        Self {
            sign_message,
            ..self
        }
    }

    /// Sets the private key used for signing.
    pub fn signing_key(self, signing_key: Arc<SamlSigningKey>) -> Self {
        Self {
            signing_key,
            ..self
        }
    }

    /// Sets the X509 certificate used for signing.
    pub fn signing_cert(self, signing_cert: Option<x509_cert::Certificate>) -> Self {
        Self {
            signing_cert,
            ..self
        }
    }

    /// Sets the signature algorithm.
    pub fn signing_algorithm(self, signing_algorithm: SigningAlgorithm) -> Self {
        Self {
            signing_algorithm,
            ..self
        }
    }

    /// Sets the digest algorithm.
    pub fn digest_algorithm(self, digest_algorithm: DigestAlgorithm) -> Self {
        Self {
            digest_algorithm,
            ..self
        }
    }

    /// Sets canonicalization method.
    pub fn canonicalization_method(self, canonicalization_method: CanonicalizationMethod) -> Self {
        Self {
            canonicalization_method,
            ..self
        }
    }

    /// Builds [ResponseElements] after validating required values.
    pub fn build(self) -> Result<ResponseElements, &'static str> {
        let issuer = required_non_empty(self.issuer, "issuer")?;
        let destination = required_non_empty(self.destination, "destination")?;
        let in_response_to = required_non_empty(self.in_response_to, "in_response_to")?;
        let authnstatement = required(self.authnstatement, "authnstatement")?;
        let service_provider = required(self.service_provider, "service_provider")?;
        let nameid_value = required_non_empty(self.nameid_value, "nameid_value")?;

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
            Some(value) if value.trim().is_empty() => return Err("assertion_id must not be empty"),
            Some(value) if !saml_id_is_valid(&value) => {
                return Err("assertion_id must begin with '_' and contain only [A-Za-z0-9_.-]");
            }
            Some(value) => value,
            None => ResponseElements::new_assertion_id(),
        };
        let response_id = match self.response_id {
            Some(value) if value.trim().is_empty() => return Err("response_id must not be empty"),
            Some(value) if !saml_id_is_valid(&value) => {
                return Err("response_id must begin with '_' and contain only [A-Za-z0-9_.-]");
            }
            Some(value) => value,
            None => ResponseElements::new_response_id(),
        };

        Ok(ResponseElements {
            response_id,
            issue_instant: self.issue_instant.unwrap_or_else(Utc::now),
            destination,
            in_response_to,
            issuer,
            attributes: self.attributes,
            authnstatement,
            assertion_id,
            service_provider,
            nameid_value,
            assertion_consumer_service: self.assertion_consumer_service,
            session_length_seconds: self.session_length_seconds,
            status: self.status,
            sign_assertion: self.sign_assertion,
            sign_message: self.sign_message,
            signing_key: self.signing_key,
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

fn saml_id_is_valid(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some('_'))
        && chars.all(|char| char.is_ascii_alphanumeric() || matches!(char, '_' | '-' | '.'))
}

use uuid::Uuid;

impl ResponseElements {
    /// Creates a new [ResponseElementsBuilder].
    pub fn builder() -> ResponseElementsBuilder {
        ResponseElementsBuilder::new()
    }

    /// Creates a random assertion ID.
    pub fn new_assertion_id() -> String {
        format!("_{}", Uuid::new_v4())
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
    pub fn try_base64_encoded_response(self) -> Result<Vec<u8>, SamlError> {
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

    fn build_response_xml(
        &self,
        assertion_data: &Assertion,
        message_signature: Option<(String, String)>,
    ) -> Result<Vec<u8>, SamlError> {
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
                .attr("InResponseTo", &self.in_response_to)
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
                &digest_value,
                &signature_value,
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
    pub fn try_into_xml_bytes(self) -> Result<Vec<u8>, SamlError> {
        let assertion_data: Assertion = (&self).try_into()?;
        let unsigned_response = self.build_response_xml(&assertion_data, None)?;
        if !self.sign_message {
            return Ok(unsigned_response);
        }

        let unsigned_xml = String::from_utf8(unsigned_response)?;
        let canonical_response = self.canonicalization_method.canonicalize(&unsigned_xml)?;
        let digest_bytes = self.digest_algorithm.hash(canonical_response.as_bytes())?;

        let mut message_signature = None;

        if !self.signing_key.is_none() {
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
            crate::xml::generate_signedinfo(
                &signature_config,
                &base64_digest,
                &mut signedinfo_writer,
            );
            let signedinfo_xml = String::from_utf8(signedinfo_buffer)?;
            let canonical_signedinfo =
                self.canonicalization_method.canonicalize(&signedinfo_xml)?;

            let signed = crate::sign::sign_data(
                self.signing_algorithm,
                &self.signing_key,
                canonical_signedinfo.as_bytes(),
            )?;
            let base64_signature = BASE64_STANDARD.encode(&signed);
            message_signature = Some((base64_digest, base64_signature));
        }

        self.build_response_xml(&assertion_data, message_signature)
    }
}

impl TryInto<Assertion> for &ResponseElements {
    type Error = SamlError;

    fn try_into(self) -> Result<Assertion, Self::Error> {
        let conditions_not_before = self.issue_instant;
        let session_time = chrono::Duration::seconds(i64::from(self.session_length_seconds));
        let conditions_not_after = conditions_not_before
            .checked_add_signed(session_time)
            .ok_or_else(|| SamlError::other("Failed to compute assertion expiry timestamp"))?;
        let acs = match self.assertion_consumer_service.clone() {
            None => self
                .service_provider
                .find_first_acs()
                .map(|value| value.location)?,
            Some(value) => value,
        };

        let subject_data = SubjectData {
            in_response_to: self.in_response_to.clone(),
            qualifier: Some(BaseIDAbstractType::SPNameQualifier),
            qualifier_value: Some(self.service_provider.entity_id.to_string()),
            nameid_format: NameIdFormat::Transient,
            nameid_value: self.nameid_value.clone(),
            acs,
            subject_not_on_or_after: conditions_not_after,
        };

        Ok(Assertion {
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
            signing_key: self.signing_key.clone(),
            signing_cert: self.signing_cert.clone(),
        })
    }
}

// TODO for signing, implement a "return this without signing flagged" fn so we can ... just get an unsigned version

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

#[derive(Debug, Clone)]
/// An Authentication Statement for returning inside an assertion
///
/// The expiry's optional
pub struct AuthNStatement {
    /// Issue time of the response
    /// TODO Figure out if this is different to the authnresponse?
    pub instant: DateTime<Utc>,
    /// TODO document this
    pub session_index: String,
    /// TODO do we need to respond with multiple context class refs?
    pub classref: String,
    /// Expiry of the statement,
    /// TODO make this non-optional
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

#[derive(Debug)]
struct ParsedSignedInfo {
    canonicalization_method: CanonicalizationMethod,
    signing_algorithm: SigningAlgorithm,
    digest_algorithm: DigestAlgorithm,
    reference_uri: String,
    transforms: Vec<String>,
    digest_value: String,
}

fn signature_block_bounds(xml: &str) -> Option<(usize, usize)> {
    let start = xml.find("<ds:Signature")?;
    let end_relative = xml[start..].find("</ds:Signature>")?;
    let end = start + end_relative + "</ds:Signature>".len();
    Some((start, end))
}

fn first_tag_bounds(xml: &str, tag_name: &str) -> Option<(usize, usize)> {
    let start_marker = format!("<{}", tag_name);
    let end_marker = format!("</{}>", tag_name);
    let start = xml.find(&start_marker)?;
    let start_close_relative = xml[start..].find('>')?;
    let end_relative = xml[start..].find(&end_marker)?;
    let end = start + end_relative + end_marker.len();
    let _ = start_close_relative;
    Some((start, end))
}

fn signature_element_count(xml: &str) -> Result<usize, SamlError> {
    let mut count = 0usize;
    for token in xmlparser::Tokenizer::from(xml) {
        match token {
            Ok(Token::ElementStart { local, .. }) => {
                if local.as_str().eq_ignore_ascii_case("Signature") {
                    count += 1;
                }
            }
            Ok(_) => {}
            Err(error) => {
                return Err(SamlError::XmlParsing(format!(
                    "Failed to count Signature elements: {}",
                    error
                )));
            }
        }
    }
    Ok(count)
}

fn parse_response_id(response_xml: &str) -> Result<String, SamlError> {
    let mut inside_response = false;
    let mut response_id: Option<String> = None;

    for token in xmlparser::Tokenizer::from(response_xml) {
        match token {
            Ok(Token::ElementStart { local, .. }) => {
                if local.as_str().eq_ignore_ascii_case("Response") {
                    inside_response = true;
                }
            }
            Ok(Token::Attribute { local, value, .. }) if inside_response => {
                if local.as_str().eq_ignore_ascii_case("ID") {
                    response_id = Some(value.as_str().to_string());
                }
            }
            Ok(Token::ElementEnd {
                end: ElementEnd::Open,
                ..
            }) if inside_response => {
                break;
            }
            Ok(_) => {}
            Err(err) => {
                return Err(SamlError::XmlParsing(format!(
                    "Failed to parse response root element: {}",
                    err
                )));
            }
        }
    }

    response_id.ok_or_else(|| SamlError::XmlParsing("Response ID attribute not found".to_string()))
}

fn parse_signedinfo(signedinfo_xml: &str) -> Result<ParsedSignedInfo, SamlError> {
    let mut current_element = String::new();

    let mut c14n_uri: Option<String> = None;
    let mut signing_uri: Option<String> = None;
    let mut digest_uri: Option<String> = None;
    let mut reference_uri: Option<String> = None;
    let mut transforms: Vec<String> = Vec::new();
    let mut digest_value = String::new();
    let mut reference_count = 0usize;
    let mut canonicalization_count = 0usize;
    let mut signature_method_count = 0usize;
    let mut digest_method_count = 0usize;

    for token in xmlparser::Tokenizer::from(signedinfo_xml) {
        match token {
            Ok(Token::ElementStart { local, .. }) => {
                current_element = local.as_str().to_string();
                if current_element.eq_ignore_ascii_case("Reference") {
                    reference_count += 1;
                } else if current_element.eq_ignore_ascii_case("CanonicalizationMethod") {
                    canonicalization_count += 1;
                } else if current_element.eq_ignore_ascii_case("SignatureMethod") {
                    signature_method_count += 1;
                } else if current_element.eq_ignore_ascii_case("DigestMethod") {
                    digest_method_count += 1;
                }
            }
            Ok(Token::Attribute { local, value, .. }) => {
                if !local.as_str().eq_ignore_ascii_case("Algorithm")
                    && !local.as_str().eq_ignore_ascii_case("URI")
                {
                    continue;
                }

                if current_element.eq_ignore_ascii_case("CanonicalizationMethod")
                    && local.as_str().eq_ignore_ascii_case("Algorithm")
                {
                    c14n_uri = Some(value.as_str().to_string());
                } else if current_element.eq_ignore_ascii_case("SignatureMethod")
                    && local.as_str().eq_ignore_ascii_case("Algorithm")
                {
                    signing_uri = Some(value.as_str().to_string());
                } else if current_element.eq_ignore_ascii_case("Reference")
                    && local.as_str().eq_ignore_ascii_case("URI")
                {
                    reference_uri = Some(value.as_str().to_string());
                } else if current_element.eq_ignore_ascii_case("Transform")
                    && local.as_str().eq_ignore_ascii_case("Algorithm")
                {
                    transforms.push(value.as_str().to_string());
                } else if current_element.eq_ignore_ascii_case("DigestMethod")
                    && local.as_str().eq_ignore_ascii_case("Algorithm")
                {
                    digest_uri = Some(value.as_str().to_string());
                }
            }
            Ok(Token::Text { text }) => {
                if current_element.eq_ignore_ascii_case("DigestValue") {
                    let trimmed = text.as_str().trim();
                    if !trimmed.is_empty() {
                        digest_value.push_str(trimmed);
                    }
                }
            }
            Ok(Token::ElementEnd { end, .. }) => match end {
                ElementEnd::Open => {}
                ElementEnd::Empty | ElementEnd::Close(_, _) => {
                    current_element.clear();
                }
            },
            Ok(_) => {}
            Err(err) => {
                return Err(SamlError::XmlParsing(format!(
                    "Failed to parse SignedInfo: {}",
                    err
                )));
            }
        }
    }

    if reference_count != 1
        || canonicalization_count != 1
        || signature_method_count != 1
        || digest_method_count != 1
    {
        return Err(SamlError::XmlParsing(
            "SignedInfo contains duplicate or missing critical elements".to_string(),
        ));
    }

    let c14n_uri = c14n_uri.ok_or_else(|| {
        SamlError::XmlParsing("SignedInfo missing CanonicalizationMethod".to_string())
    })?;
    let c14n_method = CanonicalizationMethod::from(c14n_uri.clone());

    let signing_algorithm =
        SigningAlgorithm::from(signing_uri.ok_or_else(|| {
            SamlError::XmlParsing("SignedInfo missing SignatureMethod".to_string())
        })?);
    if matches!(signing_algorithm, SigningAlgorithm::InvalidAlgorithm) {
        return Err(SamlError::UnsupportedAlgorithm(
            "SignedInfo contains unsupported SignatureMethod".to_string(),
        ));
    }

    let digest_algorithm = DigestAlgorithm::from(
        digest_uri
            .ok_or_else(|| SamlError::XmlParsing("SignedInfo missing DigestMethod".to_string()))?,
    );
    if matches!(digest_algorithm, DigestAlgorithm::InvalidAlgorithm) {
        return Err(SamlError::UnsupportedAlgorithm(
            "SignedInfo contains unsupported DigestMethod".to_string(),
        ));
    }

    Ok(ParsedSignedInfo {
        canonicalization_method: c14n_method,
        signing_algorithm,
        digest_algorithm,
        reference_uri: reference_uri
            .ok_or_else(|| SamlError::XmlParsing("SignedInfo missing Reference URI".to_string()))?,
        transforms,
        digest_value: if digest_value.is_empty() {
            return Err(SamlError::XmlParsing(
                "SignedInfo missing DigestValue".to_string(),
            ));
        } else {
            digest_value
        },
    })
}

fn parse_signature_value(signature_xml: &str) -> Result<String, SamlError> {
    let mut current_element = String::new();
    let mut signature_value = String::new();
    let mut signature_value_count = 0usize;

    for token in xmlparser::Tokenizer::from(signature_xml) {
        match token {
            Ok(Token::ElementStart { local, .. }) => {
                current_element = local.as_str().to_string();
                if current_element.eq_ignore_ascii_case("SignatureValue") {
                    signature_value_count += 1;
                }
            }
            Ok(Token::Text { text }) => {
                if current_element.eq_ignore_ascii_case("SignatureValue") {
                    let trimmed = text.as_str().trim();
                    if !trimmed.is_empty() {
                        signature_value.push_str(trimmed);
                    }
                }
            }
            Ok(Token::ElementEnd { end, .. }) => match end {
                ElementEnd::Open => {}
                ElementEnd::Empty | ElementEnd::Close(_, _) => {
                    current_element.clear();
                }
            },
            Ok(_) => {}
            Err(err) => {
                return Err(SamlError::XmlParsing(format!(
                    "Failed to parse SignatureValue: {}",
                    err
                )));
            }
        }
    }

    if signature_value_count != 1 {
        return Err(SamlError::XmlParsing(
            "Signature contains duplicate or missing SignatureValue".to_string(),
        ));
    }

    if signature_value.is_empty() {
        return Err(SamlError::XmlParsing(
            "SignatureValue not found".to_string(),
        ));
    }
    Ok(signature_value)
}

fn verify_signedinfo_with_options(
    signing_algorithm: SigningAlgorithm,
    bytes: &[u8],
    signature: &[u8],
    key_service: Option<&crate::key_provider::KeyService>,
    verification_cert: Option<&Certificate>,
    verification_key: Option<&Arc<SamlSigningKey>>,
    key_id: Option<&str>,
) -> Result<bool, SamlError> {
    if let Some(service) = key_service {
        return service.verify(key_id, signing_algorithm, bytes, signature);
    }
    if let Some(cert) = verification_cert {
        return crate::sign::verify_data_with_cert(signing_algorithm, cert, bytes, signature);
    }
    if let Some(key) = verification_key {
        return crate::sign::verify_data(signing_algorithm, key, bytes, signature);
    }
    Err(SamlError::NoKeyAvailable)
}

fn verify_response_signature_and_references_impl(
    response_xml: &str,
    key_service: Option<&crate::key_provider::KeyService>,
    verification_cert: Option<&Certificate>,
    verification_key: Option<&Arc<SamlSigningKey>>,
    key_id: Option<&str>,
) -> Result<bool, SamlError> {
    if let Err(error) = crate::security::inspect_xml_payload(
        response_xml,
        crate::security::SecurityPolicy::default()
            .effective()
            .xml_limits,
    ) {
        return Err(SamlError::Security(error));
    }

    let (signature_start, signature_end) = match signature_block_bounds(response_xml) {
        Some(bounds) => bounds,
        None => return Ok(false),
    };
    if signature_element_count(response_xml)? != 1 {
        return Ok(false);
    }

    let signature_xml = &response_xml[signature_start..signature_end];
    let (signedinfo_start, signedinfo_end) = match first_tag_bounds(signature_xml, "ds:SignedInfo")
    {
        Some(bounds) => bounds,
        None => return Ok(false),
    };
    let signedinfo_xml = &signature_xml[signedinfo_start..signedinfo_end];
    let signedinfo = match parse_signedinfo(signedinfo_xml) {
        Ok(value) => value,
        Err(SamlError::XmlParsing(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    let signature_value = match parse_signature_value(signature_xml) {
        Ok(value) => value,
        Err(SamlError::XmlParsing(_)) => return Ok(false),
        Err(error) => return Err(error),
    };

    let response_id = parse_response_id(response_xml)?;
    let expected_reference_uri = format!("#{}", response_id);
    if signedinfo.reference_uri != expected_reference_uri {
        return Ok(false);
    }

    let has_enveloped_transform = signedinfo
        .transforms
        .iter()
        .any(|value| value == "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
    if !has_enveloped_transform {
        return Ok(false);
    }

    let c14n_uri: String = signedinfo.canonicalization_method.into();
    let has_c14n_transform = signedinfo.transforms.iter().any(|value| value == &c14n_uri);
    if !has_c14n_transform {
        return Ok(false);
    }

    if signedinfo.transforms.len() != 2 {
        return Ok(false);
    }
    let transforms_are_allowed = signedinfo.transforms.iter().all(|value| {
        value == "http://www.w3.org/2000/09/xmldsig#enveloped-signature" || value == &c14n_uri
    });
    if !transforms_are_allowed {
        return Ok(false);
    }

    let mut unsigned_response = String::with_capacity(response_xml.len());
    unsigned_response.push_str(&response_xml[..signature_start]);
    unsigned_response.push_str(&response_xml[signature_end..]);

    let canonical_response = signedinfo
        .canonicalization_method
        .canonicalize(&unsigned_response)?;
    let digest_bytes = signedinfo
        .digest_algorithm
        .hash(canonical_response.as_bytes())?;
    let recomputed_digest = BASE64_STANDARD.encode(digest_bytes);
    if recomputed_digest != signedinfo.digest_value {
        return Ok(false);
    }

    let canonical_signedinfo = signedinfo
        .canonicalization_method
        .canonicalize(signedinfo_xml)?;
    let signature_bytes = BASE64_STANDARD.decode(signature_value)?;
    let canonical_verified = verify_signedinfo_with_options(
        signedinfo.signing_algorithm,
        canonical_signedinfo.as_bytes(),
        &signature_bytes,
        key_service,
        verification_cert,
        verification_key,
        key_id,
    )?;
    if canonical_verified {
        return Ok(true);
    }
    let raw_verified = verify_signedinfo_with_options(
        signedinfo.signing_algorithm,
        signedinfo_xml.as_bytes(),
        &signature_bytes,
        key_service,
        verification_cert,
        verification_key,
        key_id,
    )?;
    Ok(raw_verified)
}

/// Verifies response-level signature and references using one of:
/// - `key_service` + optional `key_id`
/// - `verification_cert`
/// - `verification_key`
pub fn verify_response_signature_and_references(
    response_xml: &str,
    key_service: Option<&crate::key_provider::KeyService>,
    verification_cert: Option<&Certificate>,
    verification_key: Option<&Arc<SamlSigningKey>>,
    key_id: Option<&str>,
) -> Result<bool, SamlError> {
    verify_response_signature_and_references_impl(
        response_xml,
        key_service,
        verification_cert,
        verification_key,
        key_id,
    )
}

/// Verifies a signed response XML payload and returns parsed core fields.
pub fn parse_and_verify_response_xml_with_key(
    response_xml: &str,
    verification_key: &Arc<SamlSigningKey>,
) -> Result<ParsedResponse, SamlError> {
    let verified = verify_response_signature_and_references(
        response_xml,
        None,
        None,
        Some(verification_key),
        None,
    )?;
    if !verified {
        return Err(SamlError::XmlParsing(
            "Response signature verification failed".to_string(),
        ));
    }
    parse_response_xml(response_xml)
}

/// Verifies a signed response XML payload with a key provider and returns parsed core fields.
pub fn parse_and_verify_response_xml_with_key_provider(
    response_xml: &str,
    key_provider: &crate::key_provider::KeyService,
    key_id: Option<&str>,
) -> Result<ParsedResponse, SamlError> {
    let verified = verify_response_signature_and_references(
        response_xml,
        Some(key_provider),
        None,
        None,
        key_id,
    )?;
    if !verified {
        return Err(SamlError::XmlParsing(
            "Response signature verification failed".to_string(),
        ));
    }
    parse_response_xml(response_xml)
}
