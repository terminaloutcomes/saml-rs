//! A test server for running as a SAML IdP
//!
//! Example configuration file:
//!
//! ```json
//! {
//! "bind_address" : "0.0.0.0",
//! "hostname" : "example.com"
//! }
//!

// use saml_rs::AuthnDecodeError;
use saml_rs::metadata::{generate_metadata_xml, SamlMetadata};
use saml_rs::SamlQuery;

use tide::log;
use tide::utils::{After, Before};
use tide::{Request, Response};
use tide_rustls::TlsListener;

use serde::Deserialize as serde_deserialize;
use std::fs::File;
use std::io::ErrorKind;


#[derive(serde_deserialize, Debug)]
struct ServerConfig {
    pub bind_address: String,
    pub public_hostname: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

impl ServerConfig {
    pub fn default() -> Self {
        ServerConfig {
            bind_address: String::from("127.0.0.1"),
            public_hostname: String::from("example.com"),
            tls_cert_path: None,
            tls_key_path: None,
        }
    }

    /// Pass this a filename (with or without extension) and it'll choose from JSON/YAML/TOML etc and also check
    /// environment variables starting with SAML_
    pub fn from_filename_and_env(path: String) -> Self {
        let mut settings = config::Config::default();
        settings
            .merge(config::File::with_name(&path)).unwrap()
            .merge(config::Environment::with_prefix("SAML")).unwrap();

        eprintln!("{:?}",settings);
        Self {
            public_hostname: settings.get("public_hostname").unwrap_or(ServerConfig::default().public_hostname),
            bind_address: settings.get("bind_address").unwrap_or(ServerConfig::default().bind_address),
            tls_cert_path: settings.get("tls_cert_path").unwrap_or(None),
            tls_key_path: settings.get("tls_key_path").unwrap_or(None),
        }
    }
}


#[derive(Clone, Debug)]
pub struct AppState {
    pub hostname: String,
}


#[async_std::main]
/// Spins up a test server
///
/// This uses HTTPS if you specify `TIDE_CERT_PATH` and `TIDE_KEY_PATH` environment variables.
async fn main() -> tide::Result<()> {

    let config_path: String = shellexpand::tilde("~/.config/saml_test_server.json").into_owned();

    let server_config = ServerConfig::from_filename_and_env(config_path);

    let app_state = AppState {
        hostname: server_config.public_hostname,
    };

    let mut app = tide::with_state(app_state);

    // app.with(tide::log::LogMiddleware::new());

    tide::log::with_level(tide::log::LevelFilter::Debug);
    app.with(Before(|request: Request<AppState>| async move {
        // request.set_ext(Instant::now());
        log::debug!("{:?}", request);
        request
    }));

    app.with(After(|mut res: Response| async {
        match res.downcast_error::<async_std::io::Error>() {
            Some(err) => {
                log::debug!("{:?}", err);
                let msg = match err.kind() {
                    ErrorKind::NotFound => {
                        // res.set_status(StatusCode::NotFound);
                        format!("Error: {:?}", err)
                    }
                    _ => "Unknown error".to_string(),
                };
                // NOTE: You may want to avoid sending error messages in a production server.
                res.set_body(msg);
            }
            _ => {
                log::debug!("{:?}", res)
            }
        }
        Ok(res)
    }));

    let mut saml_process = app.at("/SAML");
    saml_process.at("/Metadata").get(saml_metadata_get);
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

/// Placeholder function for development purposes, just returns a "Doing nothing" 200 response.
async fn do_nothing(mut _req: Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);
    res.set_body("Doing nothing");
    Ok(res)
}

/// Handles a POST binding
/// ```html
/// <form method="post" action="https://idp.example.org/SAML2/SSO/POST" ...>
///     <input type="hidden" name="SAMLRequest" value="''request''" />
///     ... other input parameter....
/// </form>
/// ```
pub async fn saml_post_binding(req: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);
    res.set_body(format!("SAMLRequest: {:?}", req));

    Ok(res)
}

/// SAML requests or responses transmitted via HTTP Redirect have a SAMLRequest or SAMLResponse query string parameter, respectively. Before it's sent, the message is deflated (without header and checksum), base64-encoded, and URL-encoded, in that order. Upon receipt, the process is reversed to recover the original message.
pub async fn saml_redirect_get(req: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);

    let mut response_body = String::from("saml_redirect_get\n\n");

    // let referer = req
    //     .header("Referer")
    //     .and_then(|hv| hv.get(0))
    //     .map(|h| h.as_str())
    //     .ok_or(&"");
    //     // #.ok_or_else(|| {
    //     // #    log::error!("Missing Header: Referer in saml_redirect_get");
    //         // tide::Error::from_str(tide::StatusCode::BadRequest, "Missing Referer header")
    //     // })?;

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
    log::debug!("about to parse authn request");

    let parsed_saml_request: saml_rs::SamlAuthnRequest =
        match saml_rs::parse_authn_request(&base64_decoded_samlrequest) {
            Ok(val) => val,
            Err(err) => {
                eprintln!("{:?}", err);
                return Err(tide::Error::from_str(tide::StatusCode::BadRequest, err));
            }
        };

    response_body.push_str(&format!(
        "request_id: {:?}\n",
        parsed_saml_request.request_id
    ));
    response_body.push_str(&format!(
        "issue_instant: {:?}\n",
        parsed_saml_request.issue_instant
    ));
    response_body.push_str(&format!(
        "consumer_service_url: {:?}\n",
        parsed_saml_request.consumer_service_url
    ));
    response_body.push_str(&format!("issuer: {:?}\n", parsed_saml_request.issuer));
    // response_body.push_str(&format!("Referer: {:?}\n", referer));
    response_body.push_str(&format!("SAMLRequest: {}\n", samlrequest));
    // #[allow(clippy::or_fun_call)]
    // response_body.push_str(&format!("RelayState: {}\n", query.RelayState.unwrap_or("unset".to_string())));

    res.set_body(response_body);

    Ok(res)
}
