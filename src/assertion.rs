//! Assertion-related things
//!

use serde::Serialize;

use chrono::{DateTime, SecondsFormat, Utc};
use std::io::Write;
use xml::writer::{EventWriter, XmlEvent};

use crate::utils::*;
use crate::xml::write_event;

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

#[derive(Debug)]
/// The content of an assertion
pub struct Assertion {
    /// Assertion ID, referred to in the signature as ds:Reference
    pub assertion_id: String,
    /// Issuer of the Assertion
    pub issuer: String,
    /// Signing algorithm
    pub signing_algorithm: crate::sign::SigningAlgorithm,
    /// Digest algorithm
    pub digest_algorithm: crate::sign::SigningAlgorithm,
    /// Digest value, based on alg
    pub digest_value: Option<String>,
    /// Signature value
    pub signature_value: Option<String>,
    /// Certificate for signing/digest? TODO: Figure this out
    pub certificate: openssl::x509::X509,

    /// Issue/Generatino time of the Assertion
    pub issue_instant: DateTime<Utc>,

    /// TODO: work out what is necessary for [SubjectData]
    pub subject_data: SubjectData,
    /// Please don't let the user do this until ... now!
    pub conditions_not_before: DateTime<Utc>,
    /// Please don't let the user do whatever we're saying they can do after this.
    pub conditions_not_after: DateTime<Utc>,
    /// Who/what should be reading this. Probably a [crate::sp::ServiceProvider]
    pub audience: String,
    /// Attributes of the assertion, things like groups and email addresses and phone numbers and favourite kind of 🥔🍠
    pub attributes: Vec<AssertionAttribute>,
}

impl Assertion {
    /// Build an assertion based on the Assertion, returns a String of XML.
    ///
    /// If you set sign, it'll sign the data.. eventually.
    pub fn build_assertion(&self, sign: bool) -> String {
        if sign {
            unimplemented!("Still need to refactor building the signed assertion")
        } else {
            unimplemented!("Still need to refactor building the assertion")
        }
        // String::from("Uh.. wait up.")
    }

    /// adds a `saml:Conditions` statement to the writer
    fn add_conditions<W: Write>(&self, writer: &mut EventWriter<W>) {
        // start conditions statement
        write_event(
            XmlEvent::start_element(("saml", "Conditions"))
                // TODO: conditions_not_before
                .attr("NotBefore", &self.conditions_not_before.to_rfc3339())
                // TODO: conditions_not_after
                .attr("NotOnOrAfter", &self.conditions_not_after.to_rfc3339())
                .into(),
            writer,
        );

        write_event(
            XmlEvent::start_element(("saml", "AudienceRestriction")).into(),
            writer,
        );
        write_event(XmlEvent::start_element(("saml", "Audience")).into(), writer);
        // TODO: BUG: this is wrong. Assertion contains an unacceptable AudienceRestriction.
        write_event(XmlEvent::characters(&self.audience), writer);
        write_event(XmlEvent::end_element().into(), writer);
        write_event(XmlEvent::end_element().into(), writer);
        // end conditions statement
        write_event(XmlEvent::end_element().into(), writer);
    }

    /// This adds the data from an Assertion to a given EventWriter.
    ///
    /// If you specify to *sign* the assertion, it's going to:
    /// - generate a temporary EventWriter
    /// - generate the *unsigned* assertion
    /// - add the signature to the assertion
    /// - weep quietly
    /// - return the full pack
    ///
    /// That's the plan, anyway.
    ///
    /// ``` xml
    /// # Assertion Header
    /// - AttributeStatement
    /// - AuthnStatement
    /// - Conditions
    /// - Issuer
    /// - Signature
    /// - Subject
    /// # End Assertion
    /// ```
    ///
    pub fn add_assertion_to_xml<W: Write>(
        &self,
        writer: &mut EventWriter<W>,
        sign_assertion: bool,
    ) {
        // start the assertion
        log::debug!("sign_assertion: {}", &sign_assertion);

        write_event(
            XmlEvent::start_element(("saml", "Assertion"))
                .attr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
                .attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
                .attr("ID", &self.assertion_id)
                .attr(
                    "IssueInstant",
                    &self
                        .issue_instant
                        .to_rfc3339_opts(SecondsFormat::Secs, true),
                )
                .attr("Version", "2.0") // yeah, not going to support anything but 2.0 here. 😅
                .into(),
            writer,
        );

        // do the issuer inside the assertion
        add_issuer(&self.issuer, writer);

        // add the subject to the assertion
        add_subject(&self.subject_data, writer);

        self.add_conditions(writer);

        // To do an expiry in an hour, do this
        // let session_expiry = Utc::now().checked_add_signed(Duration::seconds(3600));

        // self.authnstatement.add_to_xmlevent(&mut writer);

        // start the AttributeStatement
        write_event(
            XmlEvent::start_element(("saml", "AttributeStatement")).into(),
            writer,
        );
        for attribute in &self.attributes.to_vec() {
            add_attribute(attribute, writer);
        }

        // end saml:AttributeStatement
        write_event(XmlEvent::end_element().into(), writer);

        // end the assertion
        write_event(XmlEvent::end_element().into(), writer);
    }
}

/*
<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="pfx9b2e6263-8e7a-6e88-94f3-886d887744ab" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfx9b2e6263-8e7a-6e88-94f3-886d887744ab">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue>E0ZhRXxdHjBUFuSISXpWWZR7B58=</ds:DigestValue></ds:Reference></ds:SignedInfo>
<ds:SignatureValue>n6qqdooy751iuMkQTxGBx5jlJlDHsuEhuKAucouePtPChCPzS5f5ogZuAQcRbJe4oiD2N/V6m/X2NEW99RWENx15Rm53GtAvjQCWuY+FNHQ0E/LI562bwOMwn/VdKm/R+xJuJ2Laa6j3EllfjQJinzCe7ZNqSQuWMgZCQ+UQla8=</ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
*/

#[derive(Debug, Copy, Clone)]
/// Type of `saml:NameId` in a statement.
///
/// "There can be 0 or more of NameQualifier or SPNameQualifier."
///
/// I must have been reading the spec again.
///
/// They look like this:
/// ```xml
/// <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
/// ```
pub enum BaseIDAbstractType {
    ///
    NameQualifier,
    /// This'll be the one you normally use - TODO I think this comes from the metadata itself
    SPNameQualifier,
}

impl From<String> for BaseIDAbstractType {
    fn from(name: String) -> Self {
        let name = name.as_str();
        match name {
            "NameQualifier" => BaseIDAbstractType::NameQualifier,
            "SPNameQualifier" => BaseIDAbstractType::SPNameQualifier,
            _ => panic!("how did you even get here"),
        }
    }
}

impl ToString for BaseIDAbstractType {
    fn to_string(&self) -> String {
        match self {
            BaseIDAbstractType::NameQualifier => String::from("NameQualifier"),
            BaseIDAbstractType::SPNameQualifier => String::from("SPNameQualifier"),
        }
    }
}

// // use xml::name::Name;
// use std::convert::From;

// impl From<xml::name::Name> for BaseIDAbstractType{
//     fn from(name: Name) -> Self {
//         self.from_string(name.to_string())
//     }
// }

#[derive(Debug)]
/// Data type for passing subject data in because yeaaaaah, specs
///
/// TODO: Justify this better
pub struct SubjectData {
    /// Relay state as provided by the [crate::AuthnRequest]
    pub relay_state: String,
    /// Qualifier TODO: What's the qualifier again?
    pub qualifier: Option<BaseIDAbstractType>,
    /// Qualifier value TODO: I really should know what these are
    pub qualifier_value: Option<String>,
    /// [crate::sp::NameIdFormat], what kind of format you're... going TODO oh no I've done it again
    pub nameid_format: crate::sp::NameIdFormat,
    /// NameID value - I know this one, it's the reference to the user, like username or some rando noise if it's transient. Regret, if it's [crate::sp::NameIdFormat::Kerberos]
    pub nameid_value: &'static str,
    /// The AssertionConsumerService - where we'll send the request.
    pub acs: String,
    /// The expiry of this Assertion. Woo, recovered there at the end.
    pub subject_not_on_or_after: DateTime<Utc>,
}

/// Adds the Subject statement to an assertion
fn add_subject<W: Write>(subjectdata: &SubjectData, writer: &mut EventWriter<W>) {
    // start subject statement
    write_event(XmlEvent::start_element(("saml", "Subject")).into(), writer);
    // start nameid statement
    // TODO: nameid can be 0 or more of NameQualifier or SPNameQualifier
    write_event(
        XmlEvent::start_element(("saml", "NameID"))
            .attr(
                subjectdata.qualifier.unwrap().to_string().as_str(),
                subjectdata.qualifier_value.as_ref().unwrap(),
            )
            .attr("Format", &subjectdata.nameid_format.to_string())
            .into(),
        writer,
    );

    write_event(XmlEvent::characters(&subjectdata.nameid_value), writer);
    // end nameid statement
    write_event(XmlEvent::end_element().into(), writer);

    //start subjectconfirmation
    write_event(
        XmlEvent::start_element(("saml", "SubjectConfirmation"))
            .attr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
            .into(),
        writer,
    );

    //start subjectconfirmationdata
    write_event(
        XmlEvent::start_element(("saml", "SubjectConfirmationData"))
            .attr(
                "NotOnOrAfter",
                &subjectdata
                    .subject_not_on_or_after
                    .to_saml_datetime_string(),
            )
            .attr("Recipient", &subjectdata.acs)
            .attr("InResponseTo", &subjectdata.relay_state)
            .into(),
        writer,
    );

    //end subjectconfirmationdata
    write_event(XmlEvent::end_element().into(), writer);
    //end subjectconfirmation
    write_event(XmlEvent::end_element().into(), writer);

    write_event(XmlEvent::end_element().into(), writer);
    // end subject statement
}
// let mut animals: [&str; 2] = ["bird", "frog"];
#[derive(Debug, Default, Serialize, Clone)]
/// Attributes for responses
pub struct AssertionAttribute {
    name: String,
    nameformat: String,
    values: Vec<&'static str>,
}

impl AssertionAttribute {
    /// new Response Attribute with `attrname-format:basic`
    pub fn basic(name: &str, values: Vec<&'static str>) -> AssertionAttribute {
        AssertionAttribute {
            name: name.to_string(),
            nameformat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string(),
            values,
        }
    }
}

/// add an attribute to the statement
pub fn add_attribute<W: Write>(attr: &AssertionAttribute, writer: &mut EventWriter<W>) {
    write_event(
        XmlEvent::start_element(("saml", "Attribute"))
            .attr("Name", attr.name.as_str())
            .attr("NameFormat", attr.nameformat.as_str())
            .into(),
        writer,
    );
    for value in &attr.values {
        write_event(
            XmlEvent::start_element(("saml", "AttributeValue"))
                .attr("xsi:type", "xs:string")
                .into(),
            writer,
        );
        write_event(XmlEvent::characters(value), writer);
        write_event(XmlEvent::end_element().into(), writer);
    }
    // write_event(XmlEvent::end_element().into(), writer);
    write_event(XmlEvent::end_element().into(), writer);
}

/// Adds the issuer statement to a response
pub fn add_issuer<W: Write>(issuer: &str, writer: &mut EventWriter<W>) {
    write_event(XmlEvent::start_element(("saml", "Issuer")).into(), writer);
    write_event(XmlEvent::characters(&issuer), writer);
    write_event(XmlEvent::end_element().into(), writer);
}
