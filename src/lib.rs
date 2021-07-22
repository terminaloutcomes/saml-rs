//! A library for doing SAML things, terribly, in rust.
//!
//! My main aim at the moment is to provide IdP capabilities for the [Kanidm](https://github.com/kanidm/kanidm) project.
//!
//! If you would like to help - please log PRs/Issues against [terminaloutcomes/saml-rs](https://github.com/terminaloutcomes/saml-rs).

#[macro_use]
extern crate log;

// use xmlparser;
use serde::Serialize;
use xmlparser::{StrSpan, Token};

use inflate::inflate_bytes;
use std::str::from_utf8;

pub mod metadata;
pub mod response;
pub mod test_samples;
pub mod tide_helpers;

/// Stores the values one would expect in an AuthN Request
#[derive(Debug, Default, Serialize)]
pub struct SamlAuthnRequest {
    #[serde(rename = "ID")]
    pub request_id: String,
    #[serde(rename = "IssueInstant")]
    pub issue_instant: String,
    #[serde(rename = "AssertionConsumerServiceURL")]
    pub consumer_service_url: String,
    // this is a nested element inside a <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    pub issuer: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Destination")]
    pub destination: String,
}

impl SamlAuthnRequest {
    /// Allows one to turn a [SamlAuthnRequestParser] into a Request object
    pub fn from(parser: SamlAuthnRequestParser) -> Self {
        SamlAuthnRequest {
            request_id: parser.request_id.unwrap(),
            issue_instant: parser.issue_instant.unwrap(),
            consumer_service_url: parser.consumer_service_url.unwrap(),
            issuer: parser.issuer.unwrap(),
            version: parser.version,
            destination: parser.destination.unwrap(),
        }
    }
}

/// Used to pull apart a SAML AuthN Request and build a [SamlAuthnRequest]
#[derive(Debug, Default)]
pub struct SamlAuthnRequestParser {
    pub request_id: Option<String>,
    pub issue_instant: Option<String>,
    pub consumer_service_url: Option<String>,
    pub issuer: Option<String>,
    pub error: bool,
    pub version: String,
    pub issuer_state: i8,
    pub destination: Option<String>,
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
        }
    }
}

pub fn decode_authn_request_base64_encoded(req: String) -> Result<String, &'static str> {
    let base64_decoded_samlrequest: Vec<u8> = match base64::decode(req) {
        Ok(val) => {
            debug!("Succcesfully Base64 Decoded the SAMLRequest");
            val
        }
        Err(err) => {
            error!(
                "Failed to base64 decode SAMLRequest in saml_redirect_get {:?}",
                err
            );
            return Err("Failed to base64 decode input data");
        }
    };
    // here we try and use libflate to deflate the base64-decoded bytes because compression is used
    let inflated_result = match inflate_bytes(&base64_decoded_samlrequest) {
        Ok(value) => value,
        // if it fails, it's probably fine to return the bare bytes as they're already a string?
        Err(_) => base64_decoded_samlrequest,
    };
    // Vec<u8> -> String
    Ok(from_utf8(&inflated_result).unwrap_err().to_string())
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
            req.issue_instant = Some(value.to_string());
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
                    println!("Found issuer: {}", issuer);
                    saml_request.issuer = Some(issuer.to_string());
                    saml_request.issuer_state = -1; // reset the state machine so we don't try and do this again
                } else {
                    println!(
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
//     let file = match File::open("/Users/yaleman/Nextcloud/dotfiles/letsencrypt/live/m1.housenet.yaleman.org/fullchain.pem") {
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
