use std::{net::IpAddr, num::NonZeroU16, path::PathBuf};

use clap::Parser;
use saml_rs::sign::CanonicalizationMethod;

#[derive(Parser)]
pub struct CliOpts {
    #[clap(
        long,
        default_value = "localhost",
        env = "SAML_TEST_SERVER_FRONTEND_HOSTNAME"
    )]
    pub frontend_hostname: Option<String>,

    #[clap(long, default_value=None, env = "SAML_TEST_SERVER_FRONTEND_PORT", help="Set if different to the bind port")]
    pub frontend_port: Option<NonZeroU16>,

    #[clap(
        long,
        default_value = "127.0.0.1",
        env = "SAML_TEST_SERVER_BIND_ADDRESS"
    )]
    pub bind_address: IpAddr,
    #[clap(long, default_value = "9000", env = "SAML_TEST_SERVER_BIND_PORT")]
    pub bind_port: NonZeroU16,

    #[clap(long, env = "SAML_TEST_SERVER_ENTITY_ID")]
    pub entity_id: Option<String>,

    #[clap(long, env = "SAML_TEST_SERVER_PUBLIC_BASE_URL")]
    pub public_base_url: Option<String>,
    #[clap(long, env = "SAML_TEST_SERVER_TLS_CERT_PATH")]
    pub tls_cert_path: Option<PathBuf>,
    #[clap(long, env = "SAML_TEST_SERVER_TLS_KEY_PATH")]
    pub tls_key_path: Option<PathBuf>,

    #[clap(long, env = "SAML_TEST_SERVER_DISABLE_ASSERTION_SIGNING")]
    pub disable_assertion_signing: bool,

    #[clap(long, env = "SAML_TEST_SERVER_DISABLE_MESSAGE_SIGNING")]
    pub disable_message_signing: bool,

    #[clap(long, env = "SAML_TEST_SERVER_DISABLE_REQUIRED_SIGNED_AUTHN_REQUESTS")]
    pub disable_required_signed_authn_requests: bool,

    #[clap(long, env = "SAML_TEST_SERVER_CANONICALIZATION_METHOD")]
    pub canonicalization_method: Option<CanonicalizationMethod>,

    #[clap(long, env = "SAML_TEST_SERVER_SAML_CERT_PATH")]
    pub saml_cert_path: Option<PathBuf>,

    #[clap(long, env = "SAML_TEST_SERVER_SAML_KEY_PATH")]
    pub saml_key_path: Option<PathBuf>,

    #[clap(long, env = "SAML_TEST_SERVER_SP_METADATA_FILES")]
    pub sp_metadata_files: Option<Vec<String>>,

    #[clap(long, env = "SAML_TEST_SERVER_ALLOW_UNKNOWN_SP")]
    pub allow_unknown_sp: bool,

    #[clap(
        long,
        default_value = "1",
        env = "SAML_TEST_SERVER_SESSION_LIFETIME_HOURS",
        help = "Default session lifetime in hours across SPs, can be overridden by SP metadata, default 1 hour"
    )]
    pub session_lifetime: u64,
}
