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

#![deny(unsafe_code)]

// use saml_rs::AuthnDecodeError;
use saml_rs::metadata::{generate_metadata_xml, SamlMetadata};
use saml_rs::response::ResponseElements;
use saml_rs::response::{AuthNStatement, ResponseAttribute};
use saml_rs::SamlQuery;

use chrono::Duration;
use chrono::{DateTime, NaiveDate, Utc};

use tide::log;
use tide::utils::{After, Before};
use tide::{Request, Response};
use tide_rustls::TlsListener;

use std::fs::File;
use std::io::ErrorKind;
use std::str::from_utf8;

use http_types::Mime;
use std::str::FromStr;

mod util;
use util::do_nothing;

#[derive(Clone, Debug)]
pub struct AppState {
    pub hostname: String,
    pub issuer: String,
}

#[async_std::main]
/// Spins up a test server
///
/// This uses HTTPS if you specify `TIDE_CERT_PATH` and `TIDE_KEY_PATH` environment variables.
async fn main() -> tide::Result<()> {
    let config_path: String = shellexpand::tilde("~/.config/saml_test_server").into_owned();

    let server_config = util::ServerConfig::from_filename_and_env(config_path);

    let app_state = AppState {
        hostname: server_config.public_hostname,
        issuer: server_config.entity_id,
    };

    let mut app = tide::with_state(app_state);

    tide::log::with_level(tide::log::LevelFilter::Debug);

    // driftwood adds simple Apache-Style logs
    app.with(driftwood::ApacheCombinedLogger);

    app.with(Before(|request: Request<AppState>| async move {
        // request.set_ext(Instant::now());

        // if you want to log all the things use this
        // log::debug!("{:?}", request);

        // my very terrible way of doing logs
        // log::debug!("client={:?} url={} method={} length={}",
        //     request.remote().unwrap_or("-"),
        //     request.url(),
        //     request.method(),
        //     request.len().unwrap_or(0));
        request
    }));

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
    saml_process.at("/Metadata").get(saml_metadata_get);
    saml_process.at("/Metadata/SP").get(saml_metadata_get_sp);
    // TODO: SAML Logout
    saml_process.at("/Logout").get(do_nothing);
    // TODO: SAML idp, used the entityID
    saml_process.at("/idp").post(do_nothing);
    // TODO: SAML POST
    saml_process.at("/POST").post(saml_post_binding);
    // TODO: SAML Redirect
    saml_process.at("/Redirect").get(saml_redirect_get);
    // TODO: SAML Artifact
    saml_process.at("/Artifact").get(do_nothing);

    let _app = match &server_config.tls_cert_path {
        Some(value) => {
            let tls_cert: String = shellexpand::tilde(value).into_owned();
            let tls_key: String =
                shellexpand::tilde(&server_config.tls_key_path.unwrap()).into_owned();
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
                Ok(_) => log::info!("Successfully loaded cert from {:?}", tls_key),
                Err(error) => {
                    log::error!(
                        "Failed to load cert from {:?}, bailing: {:?}",
                        tls_key,
                        error
                    );
                    std::process::exit(1);
                }
            }
            app.listen(
                TlsListener::build()
                    .addrs(format!("{}:443", server_config.bind_address))
                    .cert(tls_cert)
                    .key(tls_key),
            )
            .await?
        }
        _ => {
            app.listen(format!("{}:8080", server_config.bind_address))
                .await?
        }
    };
    Ok(())
}

/// Provides a GET response for the metadata URL
async fn saml_metadata_get(req: Request<AppState>) -> tide::Result {
    Ok(generate_metadata_xml(SamlMetadata::new(
        &req.state().hostname,
        None,
        None,
        None,
        None,
        None,
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
    let mut response_body =
        String::from("<html><head><title>saml_redirect_get</title></head><body>\n\n");

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

    response_body.push_str(&format!(
        "request_id: {:?}<br />",
        parsed_saml_request.request_id
    ));
    response_body.push_str(&format!(
        "issue_instant: {:?}<br />",
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
        ResponseAttribute::basic("uid", ["test".to_string()].to_vec()),
        ResponseAttribute::basic("mail", ["test@example.com".to_string()].to_vec()),
        ResponseAttribute::basic(
            "eduPersonAffiliation",
            ["users".to_string(), "examplerole1".to_string()].to_vec(),
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
        request_id: String::from("ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"),
        attributes: responseattributes,
        destination: String::from("http://sp.example.com/demo1/index.php?acs"),
        authnstatement,
        assertion_id: String::from("_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"),
    };

    response_body.push_str(&generate_login_form(response, relay_state));
    // res.set_body(response_body);

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
    format!(
        r#"<form method="post" action="https://example.com/SAML2/SSO/POST" ...>
    <input type="hidden" name="SAMLResponse" value="{:?}" />
    <input type="hidden" name="RelayState" value="{}" />
        <h1>Fancy example login form</h1>
        <p>Username: <input type='text' name='username' /></p>
        <p>Password: <input type='password' name='password' /></p>
        <p><input type="submit" value="Submit" /></p>
</form>"#,
        from_utf8(&saml_rs::response::base64_encoded_response(response, false)).unwrap(),
        relay_state,
    )
}

async fn saml_metadata_get_sp(_req: tide::Request<AppState>) -> tide::Result {
    let sample_sp_xml = r#"<md:EntityDescriptor entityID="splunkEntityId" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true"><md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
    MIIDMjCCAhoCCQChiuJkNICB8TANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJV
    UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoM
    BlNwbHVuazEXMBUGA1UEAwwOU3BsdW5rQ29tbW9uQ0ExITAfBgkqhkiG9w0BCQEW
    EnN1cHBvcnRAc3BsdW5rLmNvbTAeFw0yMTA3MjUwMDE3NTNaFw0yNDA3MjQwMDE3
    NTNaMDcxIDAeBgNVBAMMF1NwbHVua1NlcnZlckRlZmF1bHRDZXJ0MRMwEQYDVQQK
    DApTcGx1bmtVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5tK
    Py7I7Ql/mIFyXQHussS3tW7DI01TiaPN6QsmcQWheqrBVEX1QDMRMB1wrFRsJdT0
    FJp6fmM5MG9xo7XGiSrmzX+4s74/Q1wKsoi0D7mopYGE7pDaqSSimaNigcII+Hba
    HxvhMPDRFSGBA8evcmOGiZjumfkEvAtPDodx2oFqrpwHXnrGObrxkSBtjjVfUr24
    xbC94CfeQh5iB7Ngzsv8FYSHO8rCwfvmx+G11Tm2kxs+7yvV5KHugrM8iopNe2JJ
    2srF0imIN79NIpKEoBx9wgkRCkrsq0g83Y+2fIekpvZfL6s87EKYZim2Vzfm7QzO
    QXnwMmfJrrSCha6S7wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCoXiQsmWduliVS
    FoGVKi/i6kIkP6jen3WOBa2mlNOyP+LnBjA3v5AZ7zsipoYK+C/TfBhcDPKf/ZXH
    WXHOVGV6A/pivvOskOCOOG94wce0sSyiUjV6zxNqWQj7rKcm9IZHf3eGFLnelF4Z
    4Kyprztntylg4PNPdXeyPANHGVwhv9JB6DVdpR8GTVbvPiCsQ5qxQFFeZrHYq3r2
    K5B5H7EYJkXltnhnsal35az9+BJdAceP59BqURVvFwUVP5q1A44WZPNDXv96Jd2i
    EyoXhw7tNjlhuD6V6u7z7n5YZsGNmIPj7BxGhxowWIkgAbQQN57p4xCl6Kckq2w3
    EAwd90N5
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://15d49b9c30a5:8000/saml/logout" index="0"></md:SingleLogoutService>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://15d49b9c30a5:8000/saml/acs" index="0"></md:AssertionConsumerService>
    </md:SPSSODescriptor></md:EntityDescriptor>"#;

    // SpMetadata::from_xml(sample_sp_xml);

    let meta_example = SpMetadata::from_xml(sample_sp_xml);
    // SpMetadata {
    //     entity_id: "splunkEntityId".to_string(),
    //     authn_requests_signed: true,
    //     want_assertions_signed: true,
    //     x509_certificate: Some("blah".to_string()),
    //     services: [
    //         ServiceBinding {
    //             servicetype: SamlBindingType::AssertionConsumerService,
    //             binding: SamlBinding::HttpPost,
    //             location: "http://15d49b9c30a5:8000/saml/acs".to_string(),
    //             index: 0
    //         },
    //         ServiceBinding {
    //             servicetype: SamlBindingType::SingleLogoutService,
    //             binding: SamlBinding::HttpPost,
    //             location: "http://15d49b9c30a5:8000/saml/logout".to_string(),
    //             index: 0
    //         },
    //     ].to_vec()
    // };

    use saml_rs::sp::*;

    Ok(tide::Response::builder(203)
        .body(format!("{:?}", meta_example,))
        .content_type(Mime::from_str("text/html;charset=utf-8").unwrap())
        // .header("custom-header", "value")
        .build())
}
