//! A test server for running as a SAML IdP
//!
//! Example configuration file:
//!
//! ```json
//! {
//! "bind_address" : "0.0.0.0",
//! "hostname" : "example.com",
//! "tls_cert_path" : "~/certs/fullchain.pem",
//! "tls_key_path" : "~/certs/privkey.pem",
//! }
//!

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

use log::{debug, error, info};
use saml_rs::SamlQuery;
use saml_rs::assertion::AssertionAttribute;
use saml_rs::metadata::{SamlMetadata, generate_metadata_xml};
use saml_rs::response::{AuthNStatement, ResponseElements};
use saml_rs::sign::SigningAlgorithm;
use saml_rs::sp::{BindingMethod, ServiceProvider};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Duration, NaiveDate, Utc};

use tide::log;
use tide::utils::After;
use tide::{Request, Response};
use tide_openssl::TlsListener;

use std::io::ErrorKind;
use std::str::{FromStr, from_utf8};
use tokio::fs::File;

use http_types::Mime;

pub mod util;

use util::*;
// use util::do_nothing;

#[tokio::main]
/// Spins up a test server
///
/// This uses HTTPS if you specify `TIDE_CERT_PATH` and `TIDE_KEY_PATH` environment variables.
async fn main() -> tide::Result<()> {
    let config_path = match std::env::var("SAML_CONFIG_PATH") {
        Ok(path) => path,
        Err(_) => shellexpand::tilde("~/.config/saml_test_server").into_owned(),
    };

    let server_config = util::ServerConfig::from_filename_and_env(config_path).await;

    let app_state: AppState = server_config.clone().into();

    let mut app = tide::with_state(app_state);

    tide::log::with_level(tide::log::LevelFilter::Debug);

    // driftwood adds simple Apache-Style logs
    app.with(driftwood::ApacheCombinedLogger);

    app.with(After(|mut res: Response| async {
        if let Some(err) = res.downcast_error::<std::io::Error>() {
            debug!("asdfadsfadsf {:?}", err);
            let msg = match err.kind() {
                ErrorKind::NotFound => {
                    format!("Error, Not Found: {:?}", err)
                }
                _ => "Unknown Error".to_string(),
            };
            res.set_body(msg);
        }

        Ok(res)
    }));

    let mut saml_process = app.at("/SAML");
    // TODO: implement support for SAML Artifact
    // saml_process.at("/Artifact").get(do_nothing);
    saml_process.at("/Metadata").get(saml_metadata_get);
    // saml_process.at("/sign").get(test_sign);
    // TODO: implement SAML Logout
    // saml_process.at("/Logout").get(do_nothing);
    // TODO: implement SAML idp, used the entityID
    // saml_process.at("/idp").post(do_nothing);
    // TODO: implement SAML POST endpoint
    // saml_process.at("/POST").post(saml_post_binding);

    saml_process.at("/Redirect").get(saml_redirect_get);

    let bind_target = format!(
        "{}:{}",
        &server_config.bind_address, server_config.bind_port
    );

    match server_config.listen_scheme.as_str() {
        "https" => {
            let tls_cert: String =
                shellexpand::tilde(&server_config.tls_cert_path.as_str()).into_owned();
            let tls_key: String =
                shellexpand::tilde(&server_config.tls_key_path.as_str()).into_owned();
            match File::open(&tls_cert).await {
                Ok(_) => info!("Successfully loaded cert from {:?}", tls_cert),
                Err(error) => {
                    error!(
                        "Failed to load cert from {:?}, bailing: {:?}",
                        tls_cert, error
                    );
                    std::process::exit(1);
                }
            }
            match File::open(&tls_key).await {
                Ok(_) => info!("Successfully loaded key from {:?}", tls_key),
                Err(error) => {
                    error!(
                        "Failed to load key from {:?}, bailing: {:?}",
                        tls_key, error
                    );
                    std::process::exit(1);
                }
            }
            info!("Starting up HTTPS server on {:?}", bind_target);
            debug!("Server config: {:?}", server_config);
            app.listen(
                TlsListener::build()
                    .addrs(bind_target)
                    .cert(tls_cert)
                    .key(tls_key),
            )
            .await?;
        }
        "http" => {
            info!("Starting up HTTP server on {:?}", bind_target);
            debug!("Server config: {:?}", server_config);
            app.listen(bind_target).await?;
        }
        unknown_scheme => {
            error!(
                "Unknown listen scheme {:?}, expected http or https",
                unknown_scheme
            );
            std::process::exit(1);
        }
    };
    Ok(())
}

// use saml_rs::cert::strip_cert_headers;
/// Provides a GET response for the metadata URL
async fn saml_metadata_get(req: Request<AppState>) -> tide::Result {
    let certificate = req.state().saml_signing_cert.to_owned();

    let entity_id = req.state().issuer.to_string();

    let metadata = SamlMetadata::new(
        &req.state().hostname,
        Some(req.state().public_base_url.to_string()),
        Some(entity_id),
        None,
        None,
        None,
        Some(certificate),
    );
    Ok(generate_metadata_xml(&metadata).into())
}

/// Handles a POST binding
/// ```html
/// <form method="post" action="https://idp.example.org/SAML2/SSO/POST" ...>
///     <input type="hidden" name="SAMLRequest" value="''request''" />
///     ... other input parameter....
/// </form>
/// ```
pub async fn saml_post_binding(req: tide::Request<AppState>) -> tide::Result {
    Ok(tide::Response::builder(203)
        .body(format!("SAMLRequest: {:?}", req))
        .content_type(Mime::from_str("text/html;charset=utf-8").unwrap())
        // .header("custom-header", "value")
        .build())
}

fn raw_query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for part in query.split('&') {
        let mut kv = part.splitn(2, '=');
        let Some(current_key) = kv.next() else {
            continue;
        };
        if current_key == key {
            return Some(kv.next().unwrap_or(""));
        }
    }
    None
}

fn build_redirect_signed_payload(raw_query: &str) -> Result<String, String> {
    let saml_request = raw_query_value(raw_query, "SAMLRequest")
        .ok_or_else(|| "Missing SAMLRequest in redirect query".to_string())?;
    let sig_alg = raw_query_value(raw_query, "SigAlg")
        .ok_or_else(|| "Missing SigAlg in redirect query".to_string())?;
    let relay_state = raw_query_value(raw_query, "RelayState");

    Ok(match relay_state {
        Some(relay_state_value) => format!(
            "SAMLRequest={}&RelayState={}&SigAlg={}",
            saml_request, relay_state_value, sig_alg
        ),
        None => format!("SAMLRequest={}&SigAlg={}", saml_request, sig_alg),
    })
}

/// SAML requests or responses transmitted via HTTP Redirect have a SAMLRequest or SAMLResponse query string parameter, respectively. Before it's sent, the message is deflated (without header and checksum), base64-encoded, and URL-encoded, in that order. Upon receipt, the process is reversed to recover the original message.
pub async fn saml_redirect_get(req: tide::Request<AppState>) -> tide::Result {
    let query: SamlQuery = match req.query() {
        Ok(val) => val,
        Err(e) => {
            error!("Missing SAMLRequest request in saml_redirect_get {:?}", e);
            return Err(tide::Error::from_str(
                tide::StatusCode::BadRequest,
                "Missing SAMLRequest",
            ));
        }
    };

    let mut response_body = String::from(
        r#"<!DOCTYPE html>
        <html lang="en"><head><title>saml_redirect_get</title></head><body>"#,
    );
    let samlrequest = query.SAMLRequest.unwrap();

    let base64_decoded_samlrequest =
        match saml_rs::decode_authn_request_base64_encoded(samlrequest.to_string()) {
            Ok(val) => val,
            Err(error) => {
                return Err(tide::Error::from_str(
                    tide::StatusCode::BadRequest,
                    error.message,
                ));
            }
        };
    debug!(
        "about to parse authn request: {:?}",
        base64_decoded_samlrequest
    );

    let parsed_saml_request: saml_rs::AuthnRequest =
        match saml_rs::parse_authn_request(&base64_decoded_samlrequest) {
            Ok(val) => val,
            Err(err) => {
                error!("{:?}", err);
                return Err(tide::Error::from_str(
                    tide::StatusCode::BadRequest,
                    format!("{:?}", err),
                ));
            }
        };

    let service_provider = match req
        .state()
        .service_providers
        .get(&parsed_saml_request.issuer)
    {
        Some(value) => value.to_owned(),
        None => {
            if req.state().allow_unknown_sp {
                info!(
                    "SP {:?} was not in configured metadata; using generated fallback profile.",
                    &parsed_saml_request.issuer
                );
                ServiceProvider::test_generic(&parsed_saml_request.issuer)
            } else {
                return Err(tide::Error::from_str(
                    tide::StatusCode::BadRequest,
                    "Unable to find SP for request.".to_string(),
                ));
            }
        }
    };

    let signed_request_required =
        req.state().require_signed_authn_requests || service_provider.authn_requests_signed;
    match query.Signature {
        Some(ref signature_value) => {
            let sigalg = match query.SigAlg.clone() {
                Some(value) => value,
                None => {
                    return Err(tide::Error::from_str(
                        tide::StatusCode::BadRequest,
                        "Found signature without SigAlg in redirect authn request.",
                    ));
                }
            };
            let signing_algorithm = SigningAlgorithm::from(sigalg.clone());
            if matches!(signing_algorithm, SigningAlgorithm::InvalidAlgorithm) {
                return Err(tide::Error::from_str(
                    tide::StatusCode::BadRequest,
                    format!("Unsupported redirect signature algorithm: {}", sigalg),
                ));
            }
            let cert = match service_provider.x509_certificate.as_ref() {
                Some(cert) => cert,
                None => {
                    return Err(tide::Error::from_str(
                        tide::StatusCode::BadRequest,
                        "Signed request cannot be verified because SP metadata has no certificate",
                    ));
                }
            };

            let raw_query = req.url().query().unwrap_or("");
            let signed_payload = match build_redirect_signed_payload(raw_query) {
                Ok(value) => value,
                Err(error) => {
                    return Err(tide::Error::from_str(tide::StatusCode::BadRequest, error));
                }
            };
            let normalized_signature = signature_value.replace(' ', "+");
            let signature_bytes = match BASE64_STANDARD.decode(normalized_signature) {
                Ok(value) => value,
                Err(error) => {
                    return Err(tide::Error::from_str(
                        tide::StatusCode::BadRequest,
                        format!("Failed to base64 decode Signature query value: {:?}", error),
                    ));
                }
            };
            let signature_valid = match saml_rs::sign::verify_data_with_cert(
                signing_algorithm,
                cert,
                signed_payload.as_bytes(),
                &signature_bytes,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Err(tide::Error::from_str(
                        tide::StatusCode::BadRequest,
                        format!("Failed to verify redirect signature: {}", error),
                    ));
                }
            };

            if !signature_valid {
                return Err(tide::Error::from_str(
                    tide::StatusCode::BadRequest,
                    "Redirect signature verification failed",
                ));
            }
        }
        None => {
            if signed_request_required {
                return Err(tide::Error::from_str(
                    tide::StatusCode::BadRequest,
                    "Signed AuthnRequest is required for this SP",
                ));
            }
            debug!("No redirect signature present; proceeding for unsigned request policy.");
        }
    }

    let mut _form_target = String::new();

    response_body.push_str("<p style='color: darkgreen'>found SP in state!</p>");
    response_body.push_str(&format!("<p>{:?}</p>", &service_provider));
    // find the consumer
    for service in &service_provider.services {
        match service.servicetype {
            saml_rs::sp::SamlBindingType::AssertionConsumerService => {
                debug!("acs: {:?}", service);
                match &service.binding {
                    BindingMethod::HttpRedirect | BindingMethod::HttpPost => {
                        debug!(
                            "Found form target, type is {:?}, destination is: {}",
                            &service.binding, service.location
                        );
                        _form_target = service.location.to_string();
                    } // _ => {
                      //     debug!("not it!");
                      // }
                }
            }
            saml_rs::sp::SamlBindingType::SingleLogoutService => {
                debug!("sso");
            }
        }
    }

    response_body.push_str("<h2>Known issuers</h2><ul>");
    for issuer in req.state().service_providers.keys() {
        response_body.push_str(&format!("<li>{}</li>", issuer));
    }
    response_body.push_str("</ul>");

    response_body.push_str(&format!(
        "<p>relay_state: {:?}</p>",
        parsed_saml_request.relay_state
    ));
    response_body.push_str(&format!(
        "<p>issue_instant: {:?}</p>",
        parsed_saml_request.issue_instant
    ));
    response_body.push_str(&format!(
        "consumer_service_url: {:?}<br />",
        parsed_saml_request.consumer_service_url
    ));
    let unset_value = String::from("unset");
    response_body.push_str(&format!("issuer: {:?}<br />", parsed_saml_request.issuer));

    if let Some(value) = query.Signature {
        response_body.push_str(&format!("<p>Original Signature field: <br />{}</p>", value))
    };
    if let Some(value) = query.SigAlg {
        response_body.push_str(&format!("<p>Original SigAlg field: <br />{}</p>", value))
    };

    // response_body.push_str(&format!("Referer: {:?}<br />", referer));
    response_body.push_str(&format!(
        "<p>Original SAMLRequest field: <br />{}</p>",
        samlrequest
    ));
    // #[allow(clippy::or_fun_call)]
    let relay_state = match query.RelayState {
        Some(value) => value,
        None => unset_value,
    };
    response_body.push_str(&format!("RelayState: {}<br />", relay_state));

    // start building the actual response

    let authn_instant = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2014, 7, 17)
            .unwrap()
            .and_hms_opt(1, 1, 48)
            .unwrap(),
        Utc,
    );
    // 2024-07-17T09:01:48Z
    // adding three years including skip years
    let session_expiry = match DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDate::from_ymd_opt(2014, 7, 17)
            .unwrap()
            .and_hms_opt(9, 1, 48)
            .unwrap(),
        Utc,
    )
    .checked_add_signed(Duration::days(3653))
    {
        Some(value) => value,
        _ => Utc::now(),
    };

    // TODO: work out where the AuthNStatement goes
    let authnstatement = AuthNStatement {
        instant: authn_instant,
        session_index: String::from("_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"),
        classref: String::from("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"),
        expiry: Some(session_expiry),
    };

    let responseattributes = [
        AssertionAttribute::basic("uid", ["yaleman"].to_vec()),
        AssertionAttribute::basic("mail", ["yaleman@ricetek.net"].to_vec()),
        AssertionAttribute::basic(
            "eduPersonAffiliation",
            ["users", "examplerole1", "admin"].to_vec(),
        ),
    ]
    .to_vec();

    let signing_key = req.state().saml_signing_key.to_owned();
    let response = ResponseElements {
        issuer: req.state().hostname.to_string(),
        response_id: ResponseElements::new_response_id(),
        issue_instant: Utc::now(),
        relay_state: parsed_saml_request.relay_state,
        attributes: responseattributes,
        // TODO: figure out if this should be the ACS found in _form_target above or the parsed_saml_request.consumer_service_url
        // destination: form_target,
        destination: parsed_saml_request.consumer_service_url.to_string(),
        authnstatement,
        assertion_id: ResponseElements::new_assertion_id(),
        service_provider: service_provider.to_owned(),
        assertion_consumer_service: Some(parsed_saml_request.consumer_service_url),

        session_length_seconds: 30,
        status: saml_rs::constants::StatusCode::Success,
        sign_assertion: req.state().sign_assertion,
        sign_message: req.state().sign_message,
        signing_key,
        signing_cert: Some(req.state().saml_signing_cert.to_owned()),
        signing_algorithm: saml_rs::sign::SigningAlgorithm::Sha256,
        digest_algorithm: saml_rs::sign::DigestAlgorithm::Sha256,
        canonicalization_method: req.state().canonicalization_method,
    };

    response_body.push_str(&generate_login_form(response, relay_state));
    // res.set_body(response_body);

    response_body.push_str("</html>");
    Ok(tide::Response::builder(203)
        .body(response_body)
        .content_type(Mime::from_str("text/html;charset=utf-8").unwrap())
        // .header("custom-header", "value")
        .build())
}

/// Generate a fake login form for the user to interact with
///
/// TODO: These responses have to be signed
pub fn generate_login_form(response: ResponseElements, relay_state: String) -> String {
    let mut context = tera::Context::new();

    context.insert("form_action", &response.destination);
    let response_data = match response.try_base64_encoded_response() {
        Ok(value) => value,
        Err(error) => {
            return format!(
                "<p>Failed to generate SAML response signature/canonicalization output: {}</p>",
                error
            );
        }
    };
    let saml_response = from_utf8(&response_data).unwrap().to_string();
    context.insert("SAMLResponse", &saml_response);
    context.insert("RelayState", &relay_state);

    let template = String::from(
        r#"<p>{{SAMLResponse | safe}}</p>
<form method="post" action="{{form_action | safe}}">
    <input type="hidden" name="SAMLResponse" value="{{SAMLResponse | safe}}" />
    <input type="hidden" name="RelayState" value="{{RelayState}}" />
    <h1>Fancy example login form</h1>
    <p>Username: <input type='text' name='username' /></p>
    <p>Password: <input type='password' name='password' /></p>
    <p><input type="submit" value="Submit" /></p>
</form>"#,
    );

    tera::Tera::one_off(&template, &context, true)
        .unwrap_or_else(|_| String::from("Couldn't generate login form"))
}

// TODO: reimplement test_sign
// pub async fn test_sign(req: Request<AppState>) -> tide::Result {
//     saml_rs::sign::sign_data(
//         req.state().tls_cert_path.to_string(),
//         req.state().tls_key_path.to_string(),
//         "hello world".as_bytes(),
//     );
//     Ok(tide::Response::builder(200)
//         .body("Signing things")
//         .content_type(Mime::from_str("text/html;charset=utf-8").unwrap())
//         // .header("custom-header", "value")
//         .build())
// }
