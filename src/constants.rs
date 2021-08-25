//! Constants for the saml-rs module.

/// 3.2.2.2 Element StatusCode
///
/// From <http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf>
#[derive(Debug)]
pub enum StatusCode {
    //  The permissible top-level <StatusCode> values are as follows:
    /// urn:oasis:names:tc:SAML:2.0:status:Success
    /// The request succeeded. Additional information MAY be returned in the <StatusMessage> and/or <StatusDetail> elements.
    Success,
    /// urn:oasis:names:tc:SAML:2.0:status:Requester
    /// The request could not be performed due to an error on the part of the requester.
    Requester,
    /// urn:oasis:names:tc:SAML:2.0:status:Responder
    /// The request could not be performed due to an error on the part of the SAML responder or SAML authority.
    Responder,
    /// urn:oasis:names:tc:SAML:2.0:status:VersionMismatch
    /// The SAML responder could not process the request because the version of the request message was incorrect.
    VersionMismatch,

    /// urn:oasis:names:tc:SAML:2.0:status:AuthnFailed
    /// The responding provider was unable to successfully authenticate the principal.
    AuthnFailed,
    /// urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue Unexpected or invalid content was encountered within a \<saml:Attribute\> or \<saml:AttributeValue\> element.
    InvalidAttrNameOrValue,

    /*
    The following second-level status codes are referenced at various places in this specification. Additional second-level status codes MAY be defined in future versions of the SAML specification. System entities are free to define more specific status codes by defining appropriate URI references.
    */
    /// urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy
    /// The responding provider cannot or will not support the requested name identifier policy.
    InvalidNameIDPolic,
    /// urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext
    /// The specified authentication context requirements cannot be met by the responder.
    NoAuthnContext,
    /// urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP
    /// Used by an intermediary to indicate that none of the supported identity provider <Loc> elements in an \<IDPList\> can be resolved or that none of the supported identity providers are available.
    NoAvailableIDP,
    /// urn:oasis:names:tc:SAML:2.0:status:NoPassive
    /// Indicates the responding provider cannot authenticate the principal passively, as has been requested.
    NoPassive,
    /// urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP
    /// Used by an intermediary to indicate that none of the identity providers in an <IDPList> are supported by the intermediary.
    NoSupportedIDP,
    /// urn:oasis:names:tc:SAML:2.0:status:PartialLogout
    /// Used by a session authority to indicate to a session participant that it was not able to propagate logout to all other session participants.
    PartialLogout,
    /// urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded
    /// Indicates that a responding provider cannot authenticate the principal directly and is not permitted to proxy the request further.
    ProxyCountExceeded,
    /// urn:oasis:names:tc:SAML:2.0:status:RequestDenied
    /// The SAML responder or SAML authority is able to process the request but has chosen not to respond. This status code MAY be used when there is concern about the security context of the request message or the sequence of request messages received from a particular requester.
    RequestDenied,
    /// urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported
    /// The SAML responder or SAML authority does not support the request.
    RequestUnsupported,
    /// urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated
    /// The SAML responder cannot process any requests with the protocol version specified in the request.
    RequestVersionDeprecated,
    /// urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh
    /// The SAML responder cannot process the request because the protocol version specified in the request message is a major upgrade from the highest protocol version supported by the responder.
    RequestVersionTooHigh,
    /// urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow
    /// The SAML responder cannot process the request because the protocol version specified in the request message is too low.
    RequestVersionTooLow,
    /// urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized
    /// The resource value provided in the request message is invalid or unrecognized.
    ResourceNotRecognized,
    /// urn:oasis:names:tc:SAML:2.0:status:TooManyResponses
    /// The response message would contain more elements than the SAML responder is able to return.
    TooManyResponses,
    /// urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile
    /// An entity that has no knowledge of a particular attribute profile has been presented with an attribute drawn from that profile.
    UnknownAttrProfile,
    /// urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal
    /// The responding provider does not recognize the principal specified or implied by the request.
    UnknownPrincipal,
    /// urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding
    /// The SAML responder cannot properly fulfill the request using the protocol binding specified in the request.
    UnsupportedBinding,
}
use std::fmt;

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// impl From<String> for StatusCode {
//     fn from(src: String) -> Self {
//         match src as str{
//             // TODO: one day expand on From<&str> for StatusCode if they're needed.
//             "AuthnFailed".to_string() => StatusCode::AuthnFailed,
//             // "InvalidAttrNameOrValue" => StatusCode::InvalidAttrNameOrValue,
//             // "Success" => StatusCode::Success,
//             // "Requester" => StatusCode::Requester,
//             // "Responder" => StatusCode::Responder,
//             // "VersionMismatch" => StatusCode::VersionMismatch,
//             _ => unimplemented!("saml_rs::constants::Statuscode From<{:?}> not implemented, please add code!", src),
//         }
//     }
// }
