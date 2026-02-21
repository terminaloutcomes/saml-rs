use http_types::Mime;
use log::{debug, error};
use saml_rs::error::SamlError;
use saml_rs::sign::{CanonicalizationMethod, SamlSigningKey};
use saml_rs::sp::ServiceProvider;
use saml_test_server::cli::CliOpts;
use std::collections::HashMap;
use std::convert::From;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tide::Request;
use tokio::fs::{self, read_to_string};

/// Placeholder function for development purposes, just returns a "Doing nothing" 200 response.
pub async fn do_nothing(mut _req: Request<AppState>) -> tide::Result {
    Ok(tide::Response::builder(418)
        .body("Doing nothing")
        .content_type(
            Mime::from_str("text/html;charset=utf-8")
                .expect("Failed to parse MIME type for do_nothing response"),
        )
        // .header("custom-header", "value")
        .build())
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind_address: IpAddr,
    pub bind_port: NonZeroU16,

    pub public_hostname: String,
    pub public_base_url: String,
    pub entity_id: String,

    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,

    pub sp_metadata: HashMap<String, ServiceProvider>,
    pub allow_unknown_sp: bool,
    // Default session lifetime across SPs
    pub session_lifetime: Duration,

    pub saml_cert_path: Option<PathBuf>,
    pub saml_key_path: Option<PathBuf>,
    pub sign_assertion: bool,
    pub sign_message: bool,
    pub require_signed_authn_requests: bool,
    pub canonicalization_method: CanonicalizationMethod,

    pub saml_signing_key: Arc<SamlSigningKey>,
    pub saml_signing_cert: Option<x509_cert::Certificate>,
}

impl ServerConfig {
    pub async fn try_from_opts(opts: CliOpts) -> Result<Self, SamlError> {
        let frontend_scheme = if opts.tls_cert_path.is_some() && opts.tls_key_path.is_some() {
            "https"
        } else {
            "http"
        };

        let public_hostname = opts
            .frontend_hostname
            .unwrap_or(opts.bind_address.to_string());

        let public_base_url = format!(
            "{}://{}:{}",
            frontend_scheme,
            public_hostname,
            opts.frontend_port.unwrap_or(opts.bind_port).get()
        );

        let entity_id = opts
            .entity_id
            .unwrap_or(format!("{}/Metadata", &public_hostname));

        let canonicalization_method = opts.canonicalization_method.unwrap_or_default();

        let saml_signing_key = match opts.saml_key_path {
            Some(ref path) => match fs::read_to_string(path).await {
                Ok(value) => SamlSigningKey::try_from(value.as_ref())?,
                Err(error) => {
                    return Err(SamlError::Key(error.to_string()));
                }
            },
            None => SamlSigningKey::None,
        };

        let saml_signing_cert = match opts.saml_cert_path {
            Some(ref path) => match saml_rs::sign::load_public_cert_from_filename(path).await {
                Ok(cert) => Some(cert),
                Err(error) => {
                    return Err(SamlError::Key(format!(
                        "Failed to load SAML signing cert from {}: {:?}",
                        path.display(),
                        error
                    )));
                }
            },
            None => None,
        };

        Ok(ServerConfig {
            bind_port: opts.bind_port,
            bind_address: opts.bind_address,
            public_hostname,

            public_base_url,

            entity_id,
            tls_cert_path: opts.tls_cert_path,
            tls_key_path: opts.tls_key_path,

            saml_cert_path: opts.saml_cert_path,
            saml_key_path: opts.saml_key_path,

            sign_assertion: !opts.disable_assertion_signing,
            sign_message: !opts.disable_message_signing,

            require_signed_authn_requests: !opts.disable_required_signed_authn_requests,

            canonicalization_method,
            saml_signing_key: saml_signing_key.into(),
            saml_signing_cert,

            sp_metadata: load_sp_metadata(opts.sp_metadata_files.unwrap_or_default()).await,
            allow_unknown_sp: opts.allow_unknown_sp,
            session_lifetime: Duration::from_hours(opts.session_lifetime),
        })
    }
}

async fn load_sp_metadata(filenames: Vec<String>) -> HashMap<String, ServiceProvider> {
    // load the SP metadata files

    let mut sp_metadata = HashMap::new();
    debug!("Configuration has SP metadata filenames: {:?}", filenames);
    for filename in filenames {
        let expanded_filename: String = shellexpand::tilde(&filename).into_owned();
        if Path::new(&expanded_filename).exists() {
            debug!("Found SP metadata file: {:?}", expanded_filename);
            let filecontents = match read_to_string(&expanded_filename).await {
                Err(error) => {
                    error!(
                        "Couldn't load SP Metadata file {} for some reason: {:?}",
                        &expanded_filename, error
                    );
                    continue;
                }
                Ok(value) => value,
            };
            // parse the XML
            let parsed_sp = saml_rs::sp::ServiceProvider::from_str(&filecontents)
                .expect("Failed to parse SP metadata XML from file");
            debug!("SP Metadata loaded: {:?}", parsed_sp);
            sp_metadata.insert(parsed_sp.entity_id.to_string(), parsed_sp);
        } else {
            error!(
                "Couldn't find file {:?}, not loading metadata.",
                expanded_filename
            );
        }
    }
    sp_metadata
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub hostname: String,
    pub public_base_url: String,
    pub issuer: String,
    pub service_providers: HashMap<String, ServiceProvider>,
    pub allow_unknown_sp: bool,
    pub saml_cert_path: Option<PathBuf>,
    pub saml_key_path: Option<PathBuf>,
    pub sign_assertion: bool,
    pub sign_message: bool,
    pub require_signed_authn_requests: bool,
    pub canonicalization_method: CanonicalizationMethod,

    pub saml_signing_key: Arc<SamlSigningKey>,
    pub saml_signing_cert: Option<x509_cert::Certificate>,
}

impl From<ServerConfig> for AppState {
    fn from(server_config: ServerConfig) -> AppState {
        AppState {
            hostname: server_config.public_hostname.to_string(),
            public_base_url: server_config.public_base_url.to_string(),
            issuer: server_config.entity_id.to_string(),
            service_providers: server_config.sp_metadata,
            allow_unknown_sp: server_config.allow_unknown_sp,

            saml_cert_path: server_config.saml_cert_path,
            saml_key_path: server_config.saml_key_path,
            sign_assertion: server_config.sign_assertion,
            sign_message: server_config.sign_message,
            require_signed_authn_requests: server_config.require_signed_authn_requests,
            canonicalization_method: server_config.canonicalization_method,
            saml_signing_key: server_config.saml_signing_key,
            saml_signing_cert: server_config.saml_signing_cert,
        }
    }
}
