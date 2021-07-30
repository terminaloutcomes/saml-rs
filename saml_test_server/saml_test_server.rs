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

use saml_rs::metadata::{generate_metadata_xml, SamlMetadata};
use saml_rs::response::{AuthNStatement, ResponseElements};

use saml_rs::xml::ResponseAttribute;
use saml_rs::SamlQuery;

use chrono::{DateTime, Duration, NaiveDate, Utc};

use tide::log;
use tide::utils::After;
use tide::{Request, Response};
use tide_rustls::TlsListener;

use std::fs::File;
use std::io::ErrorKind;
use std::str::{from_utf8, FromStr};

use http_types::Mime;

pub mod util;

use util::*;
// use util::do_nothing;

#[async_std::main]
/// Spins up a test server
///
/// This uses HTTPS if you specify `TIDE_CERT_PATH` and `TIDE_KEY_PATH` environment variables.
async fn main() -> tide::Result<()> {
    let config_path: String = shellexpand::tilde("~/.config/saml_test_server").into_owned();

    let server_config = util::ServerConfig::from_filename_and_env(config_path);

    let app_state: AppState = server_config.clone().into();

    let mut app = tide::with_state(app_state);

    tide::log::with_level(tide::log::LevelFilter::Debug);

    // driftwood adds simple Apache-Style logs
    app.with(driftwood::ApacheCombinedLogger);

    app.with(After(|mut res: Response| async {
        if let Some(err) = res.downcast_error::<async_std::io::Error>() {
            log::debug!("asdfadsfadsf {:?}", err);
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

    let _app = {
        let tls_cert: String =
            shellexpand::tilde(&server_config.tls_cert_path.as_str()).into_owned();
        let tls_key: String = shellexpand::tilde(&server_config.tls_key_path.as_str()).into_owned();
        match File::open(&tls_cert) {
            Ok(_) => log::info!("Successfully loaded cert from {:?}", tls_cert),
            Err(error) => {
                log::error!(
                    "Failed to load cert from {:?}, bailing: {:?}",
                    tls_cert,
                    error
                );
                std::process::exit(1);
            }
        }
        match File::open(&tls_key) {
            Ok(_) => log::info!("Successfully loaded key from {:?}", tls_key),
            Err(error) => {
                log::error!(
                    "Failed to load key from {:?}, bailing: {:?}",
                    tls_key,
                    error
                );
                std::process::exit(1);
            }
        }
        log::info!("Starting up server");
        log::debug!("Server config: {:?}", server_config);
        app.listen(
            TlsListener::build()
                .addrs(format!("{}:443", &server_config.bind_address))
                .cert(tls_cert)
                .key(tls_key),
        )
        .await?
    };
    Ok(())
}

// use saml_rs::cert::strip_cert_headers;
/// Provides a GET response for the metadata URL
async fn saml_metadata_get(req: Request<AppState>) -> tide::Result {
    let cert_path = &req.state().tls_cert_path;
    let certificate = saml_rs::sign::load_public_cert_from_filename(&cert_path).unwrap();

    Ok(generate_metadata_xml(SamlMetadata::new(
        &req.state().hostname,
        None,
        None,
        None,
        None,
        None,
        certificate,
    ))
    .into())
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

/// SAML requests or responses transmitted via HTTP Redirect have a SAMLRequest or SAMLResponse query string parameter, respectively. Before it's sent, the message is deflated (without header and checksum), base64-encoded, and URL-encoded, in that order. Upon receipt, the process is reversed to recover the original message.
pub async fn saml_redirect_get(req: tide::Request<AppState>) -> tide::Result {
    let query: SamlQuery = match req.query() {
        Ok(val) => val,
        Err(e) => {
            log::error!("Missing SAMLRequest request in saml_redirect_get {:?}", e);
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
    // I'm not sure why this is here but I better not lose it
    // https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd#rsa-sha1

    match query.Signature {
        Some(ref value) => {
            log::debug!("Found a signature! {:?}", value);
            let sigalg = match query.SigAlg {
                Some(ref value) => String::from(value),
                None => {
                    // we should probably bail on this request if we got a signature without an algorithm...
                    // or maybe there's a way to specify it in the SP metadata???

                    return Err(tide::Error::from_str(
                        tide::StatusCode::BadRequest,
                        "Found signature without a sigalg in a redirect authn request.",
                    ));
                }
            };
            log::debug!("SigAlg found: {:?}", &sigalg);
        }
        _ => {
            log::debug!("Didn't find a signature in this request.");
        }
    }

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
    log::debug!(
        "about to parse authn request: {:?}",
        base64_decoded_samlrequest
    );

    let parsed_saml_request: saml_rs::SamlAuthnRequest =
        match saml_rs::parse_authn_request(&base64_decoded_samlrequest) {
            Ok(val) => val,
            Err(err) => {
                eprintln!("{:?}", err);
                return Err(tide::Error::from_str(tide::StatusCode::BadRequest, err));
            }
        };

    let service_provider = match req
        .state()
        .service_providers
        .contains_key(&parsed_saml_request.issuer)
    {
        true => {
            let value = req
                .state()
                .service_providers
                .get(&parsed_saml_request.issuer);
            value
        }
        false => {
            return Err(tide::Error::from_str(
                tide::StatusCode::BadRequest,
                "Unable to find SP for request.".to_string(),
            ))
        }
    };

    let mut form_target = String::new();

    response_body.push_str("<p style='color: darkgreen'>found SP in state!</p>");
    response_body.push_str(&format!("<p>{:?}</p>", service_provider));
    // find the consumer
    for service in &service_provider.unwrap().services {
        match service.servicetype {
            saml_rs::sp::SamlBindingType::AssertionConsumerService => {
                log::debug!("acs: {:?}", service);
                match &service.binding {
                    saml_rs::sp::SamlBinding::HttpRedirect => {
                        log::debug!("Found it!");
                        form_target = service.location.to_string();
                    }
                    _ => {
                        log::debug!("not it!");
                    }
                }
            }
            saml_rs::sp::SamlBindingType::SingleLogoutService => {
                log::debug!("sso");
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

    let authn_instant =
        DateTime::<Utc>::from_utc(NaiveDate::from_ymd(2014, 7, 17).and_hms(1, 1, 48), Utc);
    // 2024-07-17T09:01:48Z
    // adding three years including skip years
    let session_expiry =
        match DateTime::<Utc>::from_utc(NaiveDate::from_ymd(2014, 7, 17).and_hms(9, 1, 48), Utc)
            .checked_add_signed(Duration::days(3653))
        {
            Some(value) => value,
            _ => Utc::now(),
        };

    let authnstatement = AuthNStatement {
        instant: authn_instant,
        session_index: String::from("_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"),
        classref: String::from("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"),
        expiry: Some(session_expiry),
    };

    let responseattributes = [
        ResponseAttribute::basic("uid", ["yaleman".to_string()].to_vec()),
        ResponseAttribute::basic("mail", ["yaleman@ricetek.net".to_string()].to_vec()),
        ResponseAttribute::basic(
            "eduPersonAffiliation",
            [
                "users".to_string(),
                "examplerole1".to_string(),
                "admin".to_string(),
            ]
            .to_vec(),
        ),
    ]
    .to_vec();

    let response = ResponseElements {
        issuer: req.state().hostname.to_string(),
        response_id: String::from("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"),
        issue_instant: DateTime::<Utc>::from_utc(
            NaiveDate::from_ymd(2014, 7, 17).and_hms(1, 1, 48),
            Utc,
        ),
        relay_state: parsed_saml_request.relay_state,
        attributes: responseattributes,
        destination: form_target,
        authnstatement,
        assertion_id: String::from("_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"),
        service_provider: service_provider.unwrap().to_owned(),
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
    let response_data = response.base64_encoded_response(false);
    let saml_response = from_utf8(&response_data).unwrap().to_string();
    context.insert("SAMLResponse", &saml_response);
    context.insert("RelayState", &relay_state);

    let template = String::from(
        r#"<p>{{SAMLResponse | safe}}</p>
<form method="post" action="{{form_action}}">
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

pub async fn test_sign(req: Request<AppState>) -> tide::Result {
    saml_rs::sign::sign_data(
        req.state().tls_cert_path.to_string(),
        req.state().tls_key_path.to_string(),
        "hello world".as_bytes(),
    );
    Ok(tide::Response::builder(200)
        .body("Signing things")
        .content_type(Mime::from_str("text/html;charset=utf-8").unwrap())
        // .header("custom-header", "value")
        .build())
}
