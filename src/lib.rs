//! A library for doing SAML things, terribly, in rust.
//!
//! My main aim at the moment is to provide IdP capabilities for the [Kanidm](https://github.com/kanidm/kanidm) project.
//!
//! `#![deny(unsafe_code)]` is used everywhere to avoid unsafe code tricks. This is why we're using rust, after all! 🦀
//! //!
//! If you would like to help - please log PRs/Issues against [terminaloutcomes/saml-rs](https://github.com/terminaloutcomes/saml-rs).
//!
//! There's a test application [saml_test_server](../saml_test_server/index.html) based on [tide](https://docs.rs/tide/) to allow one to test functionality.
//!
//! # Current progress:
//!
//! - Compiles, most of the time
//! - `saml_test_server` runs on HTTP and HTTPS, parses Redirect requests as-needed. Doesn't parse them well... or validate them if they're signed, but it's a start!
//! - Parses and ... seems to handle SP XML data so we can store a representation of it and match them up later
//!
//! # Next steps:
//!
//! - Support the SAML 2.0 Web Browser SSO (SP Redirect Bind/ IdP POST Response) flow
//! - Sign responses
//! - Support Signed AuthN Redirect Requests
//!
//! # SAML 2.0 Web Browser SSO (SP Redirect Bind/ IdP POST Response) flow
//!
//! 1. User attempts to access the SP resource (eg https://example.com/application)
//! 2. User is HTTP 302 redirected to the IdP (that's us!)
//!    - The URL is provided in the SAML2.0 metadata from the IdP
//!    - There should be two query parameters, [SAMLRequest](SamlQuery::SAMLRequest) and [RelayState](SamlQuery::RelayState) details about them are available in [SamlQuery]
//! 3. The SSO Service validates the request and responds with a document containing an XHTML form:
//!
//!       NOTE: POSTed assertions MUST be signed
//!
//! ```html
//! <form method="post" action="https://example.com/SAML2/SSO/POST" ...>
//!   <input type="hidden" name="SAMLResponse" value="response" />
//!   <input type="hidden" name="RelayState" value="token" />
//! etc etc...
//! <input type="submit" value="Submit" />
//! </form>
//! ```
//! 4. Request the Assertion Consumer Service at the SP. The user agent issues a POST request to the Assertion Consumer Service at the service provider:
//!
//! ```html
//! POST /SAML2/SSO/POST HTTP/1.1
//! Host: sp.example.com
//! Content-Type: application/x-www-form-urlencoded
//! Content-Length: nnn
//! SAMLResponse=response&RelayState=token
//! ```
//!
//! To automate the submission of the form, the following line of JavaScript may appear anywhere on the XHTML page:
//!
//! ```javascript
//! window.onload = function () { document.forms[0].submit(); }
//! ```
//!
//! # Testing tools:
//!
//! * Idp/SP online tester - <https://samltest.id/>
//! * Parser for requests and responses: <https://samltool.io>

#![deny(unsafe_code)]

#[macro_use]
extern crate log;

// use xmlparser;
use serde::Serialize;
use std::fmt;
use xmlparser::{StrSpan, Token};

use inflate::inflate_bytes;
use std::str::from_utf8;

pub mod cert;
pub mod metadata;
pub mod response;
pub mod sign;
pub mod sp;
pub mod test_samples;
// #[cfg(feature = "enable_tide")]
// pub mod tide_helpers;
mod xmlutils;
use serde::Deserialize;

use chrono::{DateTime, SecondsFormat, Utc};

/// Stores the values one would expect in an AuthN Request
#[derive(Debug, Serialize)]
pub struct SamlAuthnRequest {
    #[serde(rename = "ID")]
    pub request_id: String,
    #[serde(rename = "IssueInstant")]
    // TODO: change this to a datetime
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "AssertionConsumerServiceURL")]
    pub consumer_service_url: String,
    // this is a nested element inside a <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    pub issuer: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Destination")]
    pub destination: String,

    // Example value http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256
    #[serde(rename = "SigAlg")]
    pub sigalg: Option<String>,

    // Example signature value Signature=HlQbshvUcfvRY1DYo3B8PJfu%2F32pkFnKNkVtQ%2Fjn%2Bl9DurSUa4DrZH76StCwH1qgJ34v%2FXEfXBPy%2BK79ryojzUs5JR7R1KvlMR%2Fzfvgz7LFGv1fGUIFA9vnbbMsn7G%2FI0%2FXSaFkWiXp9%2BmqTmiBBBhFLsd9A8shXIEjnLVWZNUGR73HwUhEiURhGGAmVkPPGDRW1gU%2BwVdy4YUcsGusqTNEcKvUHZeOe0FC%2BggZ%2BRmCCjr2lTVrAxlXMeNU4NkgBk9VimMFCLA2A6LZ9mtLDn20CHaMEkCbSIessWKfXfz7aXd1VaY6lO1K0aSZ0h3%2BAYRcXcNVl3uvZQUslxh48Nw%3D%3D
    #[serde(rename = "Signature")]
    pub signature: Option<String>,
}

impl SamlAuthnRequest {
    /// Allows one to turn a [SamlAuthnRequestParser] into a Request object
    #[allow(clippy::or_fun_call)]
    pub fn from(parser: SamlAuthnRequestParser) -> Self {
        SamlAuthnRequest {
            request_id: parser.request_id.unwrap(),
            // TODO: make a default response for this at the current time
            // issue_instant: parser.issue_instant.unwrap_or(String::from("unset")),
            issue_instant: parser.issue_instant.unwrap_or(Utc::now()),
            // TODO: make a default response for this at the current time
            consumer_service_url: parser.consumer_service_url.unwrap_or(String::from("unset")),
            issuer: parser.issuer.unwrap(),
            version: parser.version,
            // TODO: make a default response for this at the current time
            destination: parser.destination.unwrap_or(String::from("unset")),
            sigalg: parser.sigalg,
            signature: parser.signature,
        }
    }

    pub fn issue_instant_string(&self) -> String {
        self.issue_instant
            .to_rfc3339_opts(SecondsFormat::Secs, true)
    }
}

/// Used to pull apart a SAML AuthN Request and build a [SamlAuthnRequest]
#[derive(Debug, Default)]
pub struct SamlAuthnRequestParser {
    pub request_id: Option<String>,
    pub issue_instant: Option<DateTime<Utc>>,
    pub consumer_service_url: Option<String>,
    pub issuer: Option<String>,
    pub error: bool,
    pub version: String,
    pub issuer_state: i8,
    pub destination: Option<String>,
    // need to ull this     <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>
    pub sigalg: Option<String>,
    // we leave this as the string while returning from the parser, so the [SamlAuthnRequest] can verify it.
    pub signature: Option<String>,
}

impl SamlAuthnRequestParser {
    pub fn new() -> Self {
        SamlAuthnRequestParser {
            request_id: None,
            issue_instant: None,
            consumer_service_url: None,
            issuer: None,
            error: false,
            version: String::from("2.0"),
            issuer_state: 0,
            destination: None,
            sigalg: None,
            signature: None,
        }
    }
}

pub struct AuthnDecodeError {
    pub message: String,
}

impl AuthnDecodeError {
    pub fn new(message: String) -> AuthnDecodeError {
        AuthnDecodeError { message }
    }
}

// A unique format for dubugging output
impl fmt::Debug for AuthnDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AuthnDecodeError {{ message: {} }}", self.message)
    }
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
/// Used in the SAML Redirect GET request to pull out the query values
///
/// Snake case is needed to allow the fields to be pulled out correctly
pub struct SamlQuery {
    /// The value of the SAMLRequest parameter is a deflated, base64-encoded and URL-encoded value of an `<samlp:[AuthnRequest]>` element. The SAMLRequest *may* be signed using the SP signing key.
    pub SAMLRequest: Option<String>,
    /// The RelayState token is an opaque reference to state information maintained at the service provider.
    pub RelayState: Option<String>,
    // Stores a base64-encoded signature... maybe?
    pub Signature: Option<String>,
    // Stores the signature type - this should be URL-decoded by the web frontend
    // TODO: uhh... signature enums?
    pub SigAlg: Option<String>,
}

// this does the decoding to hand the signature to the verifier??
// TODO: is string the best retval
pub fn decode_authn_request_signature(signature: String) -> String {
    debug!("signature: {:?}", signature);
    signature
}

pub fn decode_authn_request_base64_encoded(req: String) -> Result<String, AuthnDecodeError> {
    let base64_decoded_samlrequest: Vec<u8> = match base64::decode(req) {
        Ok(value) => {
            debug!("Successfully Base64 Decoded the SAMLRequest");
            value
        }
        Err(err) => {
            return Err(AuthnDecodeError::new(format!(
                "Failed to base64 decode SAMLRequest in saml_redirect_get {:?}",
                err
            )));
        }
    };
    // here we try and use libflate to deflate the base64-decoded bytes because compression is used
    let inflated_result = match inflate_bytes(&base64_decoded_samlrequest) {
        Ok(value) => {
            debug!(
                "Successfully inflated the base64-decoded bytes: {:?}",
                from_utf8(&value).unwrap_or("Couldn't utf-8 decode this mess")
            );
            value
        }
        // if it fails, it's probably fine to return the bare bytes as they're already a string?
        Err(error) => {
            debug!("Failed to inflate bytes ({:?})", error);
            base64_decoded_samlrequest
        }
    };
    match from_utf8(&inflated_result) {
        Ok(value) => Ok(value.to_string()),
        _ => Err(AuthnDecodeError::new(format!(
            "Failed to utf-8 encode the result: {:?}",
            inflated_result
        ))),
    }
}

/// Used inside SamlAuthnRequestParser to help parse the AuthN request
fn parse_authn_tokenizer_attribute(
    local: StrSpan,
    value: StrSpan,
    mut req: SamlAuthnRequestParser,
) -> SamlAuthnRequestParser {
    match local.to_lowercase().as_str() {
        "destination" => {
            req.destination = Some(value.to_string());
        }
        "id" => {
            req.request_id = Some(value.to_string());
        }
        "issueinstant" => {
            debug!("Found issueinstant: {}", value.to_string());

            // Date parsing... 2021-07-19T12:06:25Z
            let parsed_datetime = DateTime::parse_from_rfc3339(&value);
            debug!("parsed_datetime: {:?}", parsed_datetime);
            match parsed_datetime {
                Ok(value) => {
                    debug!("Setting issue_instant");
                    let result: DateTime<Utc> = value.into();
                    req.issue_instant = Some(result);
                }
                Err(error) => {
                    eprintln!(
                        "Failed to cast datetime source={:?}, error=\"{}\"",
                        value.to_string(),
                        error
                    );
                }
            };
        }
        "assertionconsumerserviceurl" => {
            req.consumer_service_url = Some(value.to_string());
        }
        "version" => {
            if value.to_string() != "2.0" {
                eprintln!(
                    "SAML Request where version!=2.0 ({}), this is bad.",
                    value.to_string()
                );
                req.version = value.to_string();
                req.error = true;
            } else {
                req.version = value.to_string();
            }
        }
        _ => debug!(
            "Found tokenizer attribute={}, value={}",
            local.to_lowercase().as_str(),
            value.to_string()
        ),
    }

    //eprintln!("after block {:?}", req.issue_instant);
    req
}

/// Used inside SamlAuthnRequestParser to help parse the AuthN request
fn parse_authn_tokenizer_element_start(
    local: StrSpan,
    mut req: SamlAuthnRequestParser,
) -> SamlAuthnRequestParser {
    debug!(
        "parse_authn_tokenizer_element_start: {}",
        local.to_lowercase().as_str()
    );
    if local.to_lowercase().as_str() == "issuer" {
        if req.issuer_state == 0 {
            req.issuer_state = 1;
            debug!("Found a text tag called issuer, moving to issuer-finding state machine state 1")
        } else {
            debug!(
                "Found issuer tag and not at issuer_state==0 {}",
                req.issuer_state
            );
            // TODO: throw an error?
        }
    } else {
        debug!("Found elementStart text={}", local.to_lowercase().as_str());
    }
    req
}

/// Give it a string full of XML and it'll give you back a [SamlAuthnRequest] object which has the details
pub fn parse_authn_request(request_data: &str) -> Result<SamlAuthnRequest, &'static str> {
    // more examples here
    // https://developers.onelogin.com/saml/examples/authnrequest

    let mut saml_request = SamlAuthnRequestParser::new();
    let tokenizer = xmlparser::Tokenizer::from(request_data);
    for token in tokenizer {
        saml_request = match token.unwrap() {
            Token::Attribute {
                prefix: _,
                local,
                value,
                span: _,
            } => parse_authn_tokenizer_attribute(local, value, saml_request),
            Token::ElementStart {
                prefix: _,
                local,
                span: _,
            } => parse_authn_tokenizer_element_start(local, saml_request),
            Token::Text { text } => {
                // if issuer_state == -1 { continue }
                if saml_request.issuer_state == 1 {
                    let issuer = text.as_str();
                    debug!("Found issuer: {}", issuer);
                    saml_request.issuer = Some(issuer.to_string());
                    saml_request.issuer_state = -1; // reset the state machine so we don't try and do this again
                } else {
                    debug!(
                        "Found issuer text and not at issuer_state==1 ({}) text={:?}",
                        saml_request.issuer_state, text
                    );
                }
                saml_request
            }
            _ => saml_request,
        };
    }
    if saml_request.error {
        eprintln!("There was an error parsing the request");
        Err("Failed to parse SAML request")
    } else {
        println!("found request_id={:?}", &saml_request.request_id);
        Ok(SamlAuthnRequest::from(saml_request))
    }
}

// TODO: This has some interesting code for parsing and handling assertions etc
// https://docs.rs/crate/saml2aws-auto/1.10.1/source/src/saml/mod.rs
// use crate::prelude::*;

fn _get_private_key() {
    println!("Generating private key");
    // let rsa = Rsa::generate(2048).unwrap()
    // println!("Dumping RSA Cert {:?}", rsa.private_key_to_der());
    // let data = b"foobar";
    // let mut buf = vec![0; rsa.size() as usize];
    // let encrypted_result = rsa.public_encrypt(data, &mut buf, Padding::PKCS1);
    // println!("Dumping encrypted thing: {:?}", &encrypted_result);
    // let encrypted_len = &encrypted_result.unwrap();

    // println!("Length of encrypted thing: {:?}", encrypted_len);
}
// use std::fs::File;
// use std::io::Read;
// use reqwest::Certificate;

// fn get_public_cert_base64(cert_path: std::string::String) -> Result<Certificate, ()> {
//     let mut buf = Vec::new();
//     let file = match File::open("certpath") {
//         Ok(file) => file,
//         Err(_) => Err
//     }
//     .read_to_end(&mut buf)?;
//     let cert = Certificate::from_der(&buf)?;
//     // cert.to_string()?
//     // .read_to_end(&mut buf)?;

//     // let mut encoded_cert = String::from("hello world");
//     // encoded_cert.push_str(&cert_path);
//     // return encoded_cert

// }

// fn encode_cert_as_base64_der() -> std::string::String{

//     use std::io::Write;
//     let mut buf = String::new();

//     let mut base64_encoder = base64::write::EncoderStringWriter::from(&mut buf, base64::STANDARD);

//     // enc.write_all(b"asdf").unwrap();
//     base64_encoder.write_all(generate_cert("www.example.com")).unwrap();

//     // release the &mut reference on buf
//     let _ = base64_encoder.into_inner();
//     buf
//     // assert_eq!("base64: YXNkZg==", &buf);
//     /*
//     pub fn Rsa.private_key_to_der(&self) -> Result<Vec<u8>, ErrorStack>
// Serializes the private key to a DER-encoded PKCS#1 RSAPrivateKey structure.

// This corresponds to i2d_RSAPrivateKey.
// */
// }
