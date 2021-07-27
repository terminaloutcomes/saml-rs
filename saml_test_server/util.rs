// use tide::log;
use tide::Request;

use crate::AppState;
use http_types::Mime;
use std::collections::HashMap;
use std::str::FromStr;

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

// #[derive(serde_deserialize, Debug)]
#[derive(Debug)]
pub struct ServerConfig {
    pub bind_address: String,
    pub public_hostname: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub entity_id: String,
    pub sp_metadata_files: Option<Vec<String>>,
    pub sp_metadata: HashMap<String, ServiceProvider>,
}

fn load_sp_metadata(filenames: Vec<String>) -> HashMap<String, ServiceProvider> {
    // load the SP metadata files

    let mut sp_metadata = HashMap::new();
    eprintln!("Configuration has SP metadata filenames: {:?}", filenames);
    for filename in filenames {
        let expanded_filename: String = shellexpand::tilde(&filename).into_owned();
        if Path::new(&expanded_filename).exists() {
            log::debug!("Found SP metadata file: {:?}", expanded_filename);
            let filecontents = match read_to_string(&expanded_filename) {
                Err(error) => {
                    eprintln!(
                        "Couldn't load SP Metadata file {} for some reason: {:?}",
                        &expanded_filename, error
                    );
                    continue;
                }
                Ok(value) => value,
            };
            // parse the XML
            let parsed_sp = saml_rs::sp::ServiceProvider::from_xml(&filecontents);
            eprintln!("SP Metadata loaded: {:?}", parsed_sp);
            sp_metadata.insert(parsed_sp.entity_id.to_string(), parsed_sp);
        } else {
            eprintln!(
                "Couldn't find file {:?}, not loading metadata.",
                expanded_filename
            );
        }
    }
    sp_metadata
}

impl ServerConfig {
    pub fn default() -> Self {
        ServerConfig {
            bind_address: String::from("127.0.0.1"),
            public_hostname: String::from("example.com"),
            tls_cert_path: String::from("Need to set this"),
            tls_key_path: String::from("Need to set this"),
            entity_id: String::from("https://example.com/idp/"),
            sp_metadata_files: None,
            sp_metadata: HashMap::new(),
        }
    }

    /// Pass this a filename (with or without extension) and it'll choose from JSON/YAML/TOML etc and also check
    /// environment variables starting with SAML_
    pub fn from_filename_and_env(path: String) -> Self {
        let mut settings = config::Config::default();
        settings
            .merge(config::File::with_name(&path))
            .unwrap()
            .merge(config::Environment::with_prefix("SAML"))
            .unwrap();

        let filenames: Vec<String> = match settings.get("sp_metadata_files") {
            Ok(filenames) => filenames,
            _ => Vec::<String>::new(),
        };

        let sp_metadata = load_sp_metadata(filenames);

        let tilde_cert_path: String = settings.get("tls_cert_path").unwrap();
        let tilde_key_path: String = settings.get("tls_key_path").unwrap();
        eprintln!("tilde_cert_path: {}", tilde_key_path);
        eprintln!("tilde_key_path: {}", tilde_key_path);

        let tls_cert_path: String = shellexpand::tilde(&tilde_cert_path).into();
        let tls_key_path: String = shellexpand::tilde(&tilde_key_path).into();

        eprintln!("{:?}", settings);
        Self {
            public_hostname: settings
                .get("public_hostname")
                .unwrap_or(ServerConfig::default().public_hostname),
            bind_address: settings
                .get("bind_address")
                .unwrap_or(ServerConfig::default().bind_address),
            tls_cert_path,
            tls_key_path,
            entity_id: settings
                .get("entity_id")
                .unwrap_or(ServerConfig::default().entity_id),
            sp_metadata_files: settings
                .get("sp_metadata_files")
                .unwrap_or(ServerConfig::default().sp_metadata_files),
            sp_metadata,
        }
    }
}
