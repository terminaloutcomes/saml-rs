// use tide::log;
use tide::Request;

use crate::AppState;
use http_types::Mime;
use serde::Deserialize as serde_deserialize;
use std::str::FromStr;

/// Placeholder function for development purposes, just returns a "Doing nothing" 200 response.
pub async fn do_nothing(mut _req: Request<AppState>) -> tide::Result {
    Ok(tide::Response::builder(203)
        .body("Doing nothing")
        .content_type(Mime::from_str("text/html;charset=utf-8").unwrap())
        // .header("custom-header", "value")
        .build())
}

#[derive(serde_deserialize, Debug)]
pub struct ServerConfig {
    pub bind_address: String,
    pub public_hostname: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub entity_id: String,
}

impl ServerConfig {
    pub fn default() -> Self {
        ServerConfig {
            bind_address: String::from("127.0.0.1"),
            public_hostname: String::from("example.com"),
            tls_cert_path: None,
            tls_key_path: None,
            entity_id: String::from("https://example.com/idp/"),
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

        eprintln!("{:?}", settings);
        Self {
            public_hostname: settings
                .get("public_hostname")
                .unwrap_or(ServerConfig::default().public_hostname),
            bind_address: settings
                .get("bind_address")
                .unwrap_or(ServerConfig::default().bind_address),
            tls_cert_path: settings.get("tls_cert_path").unwrap_or(None),
            tls_key_path: settings.get("tls_key_path").unwrap_or(None),
            entity_id: settings
                .get("entity_id")
                .unwrap_or(ServerConfig::default().entity_id),
        }
    }
}
