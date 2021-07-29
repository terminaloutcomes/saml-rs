//! Assertion-related things
//!

/// AssertionTypes, from <http://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd> ```<complexType name="AssertionType">```
#[allow(dead_code)]
enum AssertionType {
    Statement,
    AuthnStatement,
    AuthzDecisionStatement,
    AttributeStatement,
}

/// StatusCode values
#[allow(dead_code)]
enum StatusCode {
    /// `urn:oasis:names:tc:SAML:2.0:status:Success`
    Success,
}
