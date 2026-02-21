//! Security policy and XML hardening helpers.

use std::fmt;
use xmlparser::{ElementEnd, Token, Tokenizer};

/// Security defaults applied across parsing and signature validation paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityPolicy {
    /// XML parser limits and structural restrictions.
    pub xml_limits: XmlSecurityLimits,
    /// Whether weak algorithms (for example SHA-1) are accepted.
    pub allow_weak_algorithms: bool,
    /// Whether unsigned AuthnRequests are accepted.
    pub allow_unsigned_authn_requests: bool,
    /// Whether service providers not present in metadata are accepted.
    pub allow_unknown_service_providers: bool,
    /// Whether signed AuthnRequests are required.
    pub require_signed_authn_requests: bool,
}

impl SecurityPolicy {
    /// Returns the strict default policy.
    pub const fn strict() -> Self {
        Self {
            xml_limits: XmlSecurityLimits::strict(),
            allow_weak_algorithms: false,
            allow_unsigned_authn_requests: false,
            allow_unknown_service_providers: false,
            require_signed_authn_requests: true,
        }
    }

    /// Returns the effective policy after applying feature-gated danger overrides.
    pub fn effective(self) -> Self {
        let mut result = self;
        apply_danger_overrides(&mut result);
        result
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

/// XML-specific hardening limits.
// TODO make the fields private and have builder/accessor methods that enforce invariants
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XmlSecurityLimits {
    /// Maximum number of bytes allowed for an XML payload.
    pub max_xml_bytes: usize,
    /// Maximum element nesting depth.
    pub max_depth: usize,
    /// Maximum attributes allowed per element.
    pub max_attributes_per_element: usize,
    /// Maximum textual content length for a single text node.
    pub max_text_bytes: usize,
    /// Whether processing instructions are rejected.
    pub forbid_processing_instructions: bool,
    /// Whether CDATA sections are rejected.
    pub forbid_cdata: bool,
}

impl XmlSecurityLimits {
    /// Strict XML limits used by default.
    pub const fn strict() -> Self {
        Self {
            max_xml_bytes: 64 * 1024,
            max_depth: 48,
            max_attributes_per_element: 32,
            max_text_bytes: 16 * 1024,
            forbid_processing_instructions: true,
            forbid_cdata: true,
        }
    }
}

impl Default for XmlSecurityLimits {
    fn default() -> Self {
        Self::strict()
    }
}

/// Error categories emitted by XML hardening checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecurityError {
    /// Payload exceeded configured size limit.
    XmlPayloadTooLarge {
        /// Configured maximum payload size in bytes.
        limit: usize,
        /// Actual payload size in bytes.
        actual: usize,
    },
    /// `<!DOCTYPE ...>` and DTD content are forbidden.
    XmlDtdForbidden,
    /// `<? ... ?>` processing instructions are forbidden.
    XmlProcessingInstructionForbidden,
    /// CDATA sections are forbidden.
    XmlCdataForbidden,
    /// Unexpected external or custom entity/reference usage.
    XmlReferenceForbidden(String),
    /// XInclude-like include directives are forbidden.
    XmlIncludeForbidden,
    /// External schema references are forbidden.
    XmlExternalSchemaReferenceForbidden,
    /// XML element nesting exceeds configured depth.
    XmlDepthExceeded {
        /// Configured maximum XML depth.
        limit: usize,
    },
    /// Attribute count for an element exceeds configured limit.
    XmlAttributesExceeded {
        /// Configured maximum attributes per element.
        limit: usize,
    },
    /// Text content is too large for a single node.
    XmlTextTooLarge {
        /// Configured maximum text-node size.
        limit: usize,
        /// Actual text-node size.
        actual: usize,
    },
    /// XML could not be parsed.
    XmlMalformed(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::XmlPayloadTooLarge { limit, actual } => {
                write!(
                    f,
                    "XML payload exceeds size limit: actual={} bytes, limit={} bytes",
                    actual, limit
                )
            }
            SecurityError::XmlDtdForbidden => write!(f, "DOCTYPE/DTD declarations are forbidden"),
            SecurityError::XmlProcessingInstructionForbidden => {
                write!(f, "XML processing instructions are forbidden")
            }
            SecurityError::XmlCdataForbidden => write!(f, "CDATA sections are forbidden"),
            SecurityError::XmlReferenceForbidden(reference) => {
                write!(f, "XML reference/entity is forbidden: {}", reference)
            }
            SecurityError::XmlIncludeForbidden => write!(f, "XInclude directives are forbidden"),
            SecurityError::XmlExternalSchemaReferenceForbidden => {
                write!(f, "External schema references are forbidden")
            }
            SecurityError::XmlDepthExceeded { limit } => {
                write!(
                    f,
                    "XML nesting depth exceeded the configured limit {}",
                    limit
                )
            }
            SecurityError::XmlAttributesExceeded { limit } => {
                write!(
                    f,
                    "XML attributes per element exceeded the configured limit {}",
                    limit
                )
            }
            SecurityError::XmlTextTooLarge { limit, actual } => write!(
                f,
                "XML text node exceeds size limit: actual={} bytes, limit={} bytes",
                actual, limit
            ),
            SecurityError::XmlMalformed(message) => write!(f, "Malformed XML: {}", message),
        }
    }
}

fn contains_url_reference(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("ftp://")
        || lower.contains("file://")
}

/// Runs strict XML preflight checks.
pub fn inspect_xml_payload(payload: &str, limits: XmlSecurityLimits) -> Result<(), SecurityError> {
    if payload.len() > limits.max_xml_bytes {
        return Err(SecurityError::XmlPayloadTooLarge {
            limit: limits.max_xml_bytes,
            actual: payload.len(),
        });
    }

    let mut depth = 0usize;
    let mut attributes_for_current_element = 0usize;

    for token in Tokenizer::from(payload) {
        let token = token.map_err(|error| SecurityError::XmlMalformed(format!("{:?}", error)))?;

        match token {
            Token::DtdStart { .. }
            | Token::EmptyDtd { .. }
            | Token::EntityDeclaration { .. }
            | Token::DtdEnd { .. } => return Err(SecurityError::XmlDtdForbidden),
            Token::ProcessingInstruction { .. } if limits.forbid_processing_instructions => {
                return Err(SecurityError::XmlProcessingInstructionForbidden);
            }
            Token::Cdata { .. } if limits.forbid_cdata => {
                return Err(SecurityError::XmlCdataForbidden);
            }
            Token::ElementStart { prefix, local, .. } => {
                attributes_for_current_element = 0;
                depth = depth.saturating_add(1);
                if depth > limits.max_depth {
                    return Err(SecurityError::XmlDepthExceeded {
                        limit: limits.max_depth,
                    });
                }

                if prefix.as_str().eq_ignore_ascii_case("xi")
                    && local.as_str().eq_ignore_ascii_case("include")
                {
                    return Err(SecurityError::XmlIncludeForbidden);
                }
            }
            Token::Attribute { local, value, .. } => {
                attributes_for_current_element = attributes_for_current_element.saturating_add(1);
                if attributes_for_current_element > limits.max_attributes_per_element {
                    return Err(SecurityError::XmlAttributesExceeded {
                        limit: limits.max_attributes_per_element,
                    });
                }

                if (local.as_str().eq_ignore_ascii_case("schemalocation")
                    || local
                        .as_str()
                        .eq_ignore_ascii_case("nonamespaceschemalocation"))
                    && contains_url_reference(value.as_str())
                {
                    return Err(SecurityError::XmlExternalSchemaReferenceForbidden);
                }

                if local.as_str().eq_ignore_ascii_case("href")
                    && contains_url_reference(value.as_str())
                {
                    return Err(SecurityError::XmlIncludeForbidden);
                }
            }
            Token::ElementEnd { end, .. } => match end {
                ElementEnd::Open => {}
                ElementEnd::Empty | ElementEnd::Close(_, _) => {
                    if depth == 0 {
                        return Err(SecurityError::XmlMalformed(
                            "Closing element before any opening element".to_string(),
                        ));
                    }
                    depth -= 1;
                }
            },
            Token::Text { text } => {
                if text.as_str().len() > limits.max_text_bytes {
                    return Err(SecurityError::XmlTextTooLarge {
                        limit: limits.max_text_bytes,
                        actual: text.as_str().len(),
                    });
                }
            }
            Token::Cdata { text, .. } => {
                if text.as_str().len() > limits.max_text_bytes {
                    return Err(SecurityError::XmlTextTooLarge {
                        limit: limits.max_text_bytes,
                        actual: text.as_str().len(),
                    });
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(SecurityError::XmlMalformed(
            "Unbalanced XML element nesting".to_string(),
        ));
    }

    Ok(())
}

#[cfg(feature = "danger_i_want_to_risk_it_all")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "danger_i_want_to_risk_it_all")]
static DANGER_UNLOCKED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "danger_i_want_to_risk_it_all")]
static DANGER_ALLOW_WEAK_ALGORITHMS: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "danger_i_want_to_risk_it_all")]
static DANGER_ALLOW_UNSIGNED_AUTHN_REQUESTS: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "danger_i_want_to_risk_it_all")]
static DANGER_ALLOW_UNKNOWN_SERVICE_PROVIDERS: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "danger_i_want_to_risk_it_all")]
fn danger_unlocked() -> bool {
    DANGER_UNLOCKED.load(Ordering::SeqCst)
}

#[cfg(feature = "danger_i_want_to_risk_it_all")]
fn apply_danger_overrides(policy: &mut SecurityPolicy) {
    if danger_unlocked() && DANGER_ALLOW_WEAK_ALGORITHMS.load(Ordering::SeqCst) {
        policy.allow_weak_algorithms = true;
    }
    if danger_unlocked() && DANGER_ALLOW_UNSIGNED_AUTHN_REQUESTS.load(Ordering::SeqCst) {
        policy.allow_unsigned_authn_requests = true;
        policy.require_signed_authn_requests = false;
    }
    if danger_unlocked() && DANGER_ALLOW_UNKNOWN_SERVICE_PROVIDERS.load(Ordering::SeqCst) {
        policy.allow_unknown_service_providers = true;
    }
}

#[cfg(not(feature = "danger_i_want_to_risk_it_all"))]
fn apply_danger_overrides(_policy: &mut SecurityPolicy) {}

/// Returns `true` when weak algorithms are explicitly allowed.
pub fn weak_algorithms_allowed() -> bool {
    SecurityPolicy::default().effective().allow_weak_algorithms
}

/// Returns `true` when unsigned AuthnRequests are explicitly allowed.
pub fn unsigned_authn_requests_allowed() -> bool {
    SecurityPolicy::default()
        .effective()
        .allow_unsigned_authn_requests
}

/// Returns `true` when unknown service providers are explicitly allowed.
pub fn unknown_service_providers_allowed() -> bool {
    SecurityPolicy::default()
        .effective()
        .allow_unknown_service_providers
}

#[cfg(feature = "danger_i_want_to_risk_it_all")]
/// Explicitly unsafe runtime overrides, only available behind the danger feature.
pub mod danger {
    use super::{
        DANGER_ALLOW_UNKNOWN_SERVICE_PROVIDERS, DANGER_ALLOW_UNSIGNED_AUTHN_REQUESTS,
        DANGER_ALLOW_WEAK_ALGORITHMS, DANGER_UNLOCKED,
    };
    use std::sync::atomic::Ordering;

    /// Unlock token required to enable insecure runtime behavior.
    #[derive(Clone, Copy, Debug)]
    pub struct DangerAccessToken {
        _private: (),
    }

    /// Enables danger-mode runtime toggles and returns a token for explicit opt-in calls.
    pub fn unlock() -> DangerAccessToken {
        DANGER_UNLOCKED.store(true, Ordering::SeqCst);
        DangerAccessToken { _private: () }
    }

    /// Allow weak algorithms such as SHA-1 for compatibility testing.
    pub fn enable_weak_algorithms(_token: &DangerAccessToken) {
        DANGER_ALLOW_WEAK_ALGORITHMS.store(true, Ordering::SeqCst);
    }

    /// Allow unsigned AuthnRequests.
    pub fn enable_unsigned_authn_requests(_token: &DangerAccessToken) {
        DANGER_ALLOW_UNSIGNED_AUTHN_REQUESTS.store(true, Ordering::SeqCst);
    }

    /// Allow service providers not present in configured metadata.
    pub fn enable_unknown_service_providers(_token: &DangerAccessToken) {
        DANGER_ALLOW_UNKNOWN_SERVICE_PROVIDERS.store(true, Ordering::SeqCst);
    }
}
