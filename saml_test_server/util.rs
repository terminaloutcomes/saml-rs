use log::{debug, error};
use tide::Request;

use http_types::Mime;
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use saml_rs::sp::ServiceProvider;
use std::fs::read_to_string;
use std::path::Path;

/// Placeholder function for development purposes, just returns a "Doing nothing" 200 response.
pub async fn do_nothing(mut _req: Request<AppState>) -> tide::Result {
    Ok(tide::Response::builder(418)
        .body("Doing nothing")
        .content_type(Mime::from_str("text/html;charset=utf-8").unwrap())
        // .header("custom-header", "value")
        .build())
}

use openssl::x509::X509;

// #[derive(serde_deserialize, Debug)]
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub public_hostname: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub entity_id: String,
    pub sp_metadata_files: Option<Vec<&'static str>>,
    pub sp_metadata: HashMap<String, ServiceProvider>,
    // Default session lifetime across SPs
    pub session_lifetime: Duration,

    pub saml_cert_path: String,
    pub saml_key_path: String,

    pub saml_signing_key: Option<openssl::pkey::PKey<openssl::pkey::Private>>,
    pub saml_signing_cert: Option<X509>,
}

fn load_sp_metadata(filenames: Vec<String>) -> HashMap<String, ServiceProvider> {
    // load the SP metadata files

    let mut sp_metadata = HashMap::new();
    debug!("Configuration has SP metadata filenames: {:?}", filenames);
    for filename in filenames {
        let expanded_filename: String = shellexpand::tilde(&filename).into_owned();
        if Path::new(&expanded_filename).exists() {
            debug!("Found SP metadata file: {:?}", expanded_filename);
            let filecontents = match read_to_string(&expanded_filename) {
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
            let parsed_sp = saml_rs::sp::ServiceProvider::from_str(&filecontents).unwrap();
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

impl ServerConfig {
    /// Pass this a filename (with or without extension) and it'll choose from JSON/YAML/TOML etc and also check
    /// environment variables starting with SAML_
    pub fn from_filename_and_env(path: String) -> Self {
        let settings = config::Config::builder()
            .add_source(config::File::with_name(&path))
            .add_source(config::Environment::with_prefix("SAML"))
            .build()
            .unwrap();

        let filenames: Vec<String> = settings.get("sp_metadata_files").unwrap_or_default();

        debug!("Loading SP Metadata from config.");

        let sp_metadata = load_sp_metadata(filenames);
        debug!("Done loading SP Metadata from config.");

        let tilde_cert_path: String = settings.get("tls_cert_path").unwrap_or_else(|error| {
            error!(
                "You need to specify 'tls_cert_path' in configuration, quitting. ({:?})",
                error
            );
            std::process::exit(1)
        });
        let tilde_key_path: String = settings.get("tls_key_path").unwrap_or_else(|error| {
            error!(
                "You need to specify 'tls_key_path' in configuration, quitting. ({:?})",
                error
            );
            std::process::exit(1)
        });

        let tilde_saml_cert_path: String = settings.get("saml_cert_path").unwrap_or_else(|error| {
            error!(
                "You need to specify 'saml_cert_path' in configuration, quitting. ({:?})",
                error
            );
            std::process::exit(1)
        });
        let tilde_saml_key_path: String = settings.get("saml_key_path").unwrap_or_else(|error| {
            error!(
                "You need to specify 'saml_key_path' in configuration, quitting. ({:?})",
                error
            );
            std::process::exit(1)
        });
        let bind_address: String = settings.get("bind_address").unwrap_or_else(|error| {
            error!(
                "You need to specify 'bind_address' in configuration, quitting. ({:?})",
                error
            );
            std::process::exit(1)
        });
        let tls_cert_path = shellexpand::tilde(&tilde_cert_path).into_owned();
        let tls_key_path = shellexpand::tilde(&tilde_key_path).into_owned();
        let saml_cert_path = shellexpand::tilde(&tilde_saml_cert_path).into_owned();
        let saml_key_path = shellexpand::tilde(&tilde_saml_key_path).into_owned();

        use saml_rs::sign::load_key_from_filename;
        let saml_signing_key = match load_key_from_filename(&saml_key_path) {
            Ok(value) => value,
            Err(error) => {
                error!(
                    "Failed to load SAML signing key from {}: {:?}",
                    &saml_key_path, error
                );
                std::process::exit(1);
            }
        };
        let saml_signing_cert = match saml_rs::sign::load_public_cert_from_filename(&saml_cert_path)
        {
            Ok(value) => value,
            Err(error) => {
                error!(
                    "Failed to load SAML signing cert from {}: {:?}",
                    &saml_key_path, error
                );
                std::process::exit(1);
            }
        };

        debug!("SETTINGS\n{:?}", settings);
        ServerConfig {
            public_hostname: settings
                .get("public_hostname")
                .unwrap_or(ServerConfig::default().public_hostname),
            bind_address,
            tls_cert_path,
            tls_key_path,
            entity_id: settings
                .get("entity_id")
                .unwrap_or(ServerConfig::default().entity_id),
            sp_metadata_files: settings
                .get("sp_metadata_files")
                .unwrap_or(ServerConfig::default().sp_metadata_files),
            sp_metadata,
            session_lifetime: settings
                .get("default_session_lifetime")
                .unwrap_or(ServerConfig::default().session_lifetime),
            saml_cert_path,
            saml_key_path,

            saml_signing_key: Some(saml_signing_key),
            saml_signing_cert: Some(saml_signing_cert),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            bind_address: "127.0.0.1".to_string(),
            public_hostname: "example.com".to_string(),
            tls_cert_path: "Need to set this".to_string(),
            tls_key_path: "Need to set this".to_string(),

            entity_id: "https://example.com/idp/".to_string(),
            sp_metadata_files: None,
            sp_metadata: HashMap::new(),
            session_lifetime: Duration::from_hours(12), // 12 hours

            // TODO: possibly remove saml_cert_path from [ServerConfig.default]
            saml_cert_path: "Need to set this".to_string(),
            // TODO: possibly remove saml_key_path from [ServerConfig.default]
            saml_key_path: "Need to set this".to_string(),

            saml_signing_key: None,
            saml_signing_cert: None,
        }
    }
}

use openssl::pkey;

#[derive(Clone, Debug)]
pub struct AppState {
    pub hostname: String,
    pub issuer: String,
    pub service_providers: HashMap<String, ServiceProvider>,
    pub tls_cert_path: String,
    pub tls_key_path: String,

    pub saml_cert_path: String,
    pub saml_key_path: String,

    pub saml_signing_key: pkey::PKey<pkey::Private>,
    pub saml_signing_cert: X509,
}

use std::convert::From;

impl From<ServerConfig> for AppState {
    fn from(server_config: ServerConfig) -> AppState {
        AppState {
            hostname: server_config.public_hostname.to_string(),
            issuer: server_config.entity_id.to_string(),
            service_providers: server_config.sp_metadata,
            tls_cert_path: server_config.tls_cert_path.to_string(),
            tls_key_path: server_config.tls_key_path.to_string(),

            saml_cert_path: server_config.saml_cert_path,
            saml_key_path: server_config.saml_key_path,
            saml_signing_key: server_config.saml_signing_key.unwrap(),
            saml_signing_cert: server_config.saml_signing_cert.unwrap(),
        }
    }
}
