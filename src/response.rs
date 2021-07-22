// use std::fs::File;
// use std::io::Write as IoWrite;
// use std::io::{self, Write};
use std::io::Write;

use xml::writer::{EventWriter, EmitterConfig, XmlEvent, /*Result*/};
// use xml::attribute::Attribute;
// use xml::name::Name;

fn write_event<W: Write>(event: XmlEvent, writer:  &mut EventWriter<W>) -> String {
    match writer.write(event) {
        Ok(val) => format!("{:?}",val),
        Err(err) => format!("{:?}", err)
    }
}

fn add_issuer<W: Write>(issuer: &str, writer: &mut EventWriter<W>) {
    write_event(XmlEvent::start_element(("saml", "Issuer")).into(), writer);
    write_event(XmlEvent::characters(&issuer), writer);
    write_event(XmlEvent::end_element().into(), writer);
}

// let mut animals: [&str; 2] = ["bird", "frog"];

struct ResponseAttribute {
    name: String,
    nameformat: String,
    values: Vec<&'static str>,
}

impl ResponseAttribute {
    fn basic(name: &str, values: Vec<&'static str>) -> Self {
        ResponseAttribute {
            name: name.to_string(),
            nameformat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string(),
            values,
        }
    }
}

/// add an attribute to the statement
fn add_attribute<W: Write>(attr: ResponseAttribute, writer: &mut EventWriter<W>) {
    write_event(XmlEvent::start_element(("saml", "Attribute"))
        .attr("Name",attr.name.as_str())
        .attr("NameFormat",attr.nameformat.as_str())
        .into(), writer);
    for value in attr.values {
        write_event(XmlEvent::start_element(("saml", "AttributeValue"))
            .attr("xsi:type","xs:string")
            .into(), writer);
        write_event(XmlEvent::characters(value), writer);
        write_event(XmlEvent::end_element().into(), writer);
    };
    // write_event(XmlEvent::end_element().into(), writer);
write_event(XmlEvent::end_element().into(), writer);
}

/// Adds a set of status tags to a response
///
/// Using the command thusly: `add_status("Success", &mut writer);` Will add this:
///
/// ```
/// <samlp:Status>
///   <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
/// </samlp:Status>
/// ```
fn add_status<W: Write>(status: &str, writer: &mut EventWriter<W>) {
    write_event(XmlEvent::start_element(("samlp", "Status")).into(), writer);
    write_event(XmlEvent::start_element(("samlp", "StatusCode"))
    .attr("Value", format!("urn:oasis:names:tc:SAML:2.0:status:{}", status).as_str())
    .into(), writer);
    write_event(XmlEvent::end_element().into(), writer);
    write_event(XmlEvent::end_element().into(), writer);
}

pub struct ResponseElements {
    pub issuer: String,
}

pub fn create_response(data: ResponseElements) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .write_document_declaration(false)
        .create_writer(&mut buffer);

    // let tag = String::from("test").as_bytes();
    // let event: XmlEvent = XmlEvent::start_element(("p", "some-name")).into();

    // start of the response
    write_event(XmlEvent::start_element(("samlp", "Response"))
    .attr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
    .attr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
    .attr("ID", "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6")
    .attr("Version", "2.0")
    .attr("IssueInstant", "2014-07-17T01:01:48Z")
    .attr("Destination", "http://sp.example.com/demo1/index.php?acs")
    .attr("InResponseTo", "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685")
    .into()
    , &mut writer);

    // issuer
    add_issuer(&data.issuer, &mut writer);

    // status
    add_status("Success", &mut writer);

    // start the assertion
    write_event(XmlEvent::start_element(("saml", "Assertion"))
    .attr("xmlns:xsi","http://www.w3.org/2001/XMLSchema-instance")
    .attr("xmlns:xs","http://www.w3.org/2001/XMLSchema")
    .attr("ID","_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75")
    .attr("Version", "2.0")
    .attr("IssueInstant","2014-07-17T01:01:48Z")
    .into(), &mut writer);

    // do the issuer inside the assertion
    add_issuer(&data.issuer, &mut writer);

    // start subject statement
    write_event(XmlEvent::start_element(("saml", "Subject")).into(), &mut writer);
    // start nameid statement
    write_event(XmlEvent::start_element(("saml", "NameID"))
        .attr("SPNameQualifier","http://sp.example.com/demo1/metadata.php")
        .attr("Format","urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
        .into(), &mut writer);

        write_event(XmlEvent::characters("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"), &mut writer);
        // end nameid statement
        write_event(XmlEvent::end_element().into(), &mut writer);

        //start subjectconfirmation
        write_event(XmlEvent::start_element(("saml", "SubjectConfirmation"))
        .attr("Method","urn:oasis:names:tc:SAML:2.0:cm:bearer")
        .into(), &mut writer);

            //start subjectconfirmationdata
            write_event(XmlEvent::start_element(("saml", "SubjectConfirmationData"))
                .attr("NotOnOrAfter","2024-01-18T06:21:48Z")
                .attr("Recipient","http://sp.example.com/demo1/index.php?acs")
                .attr("InResponseTo","ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685")
                .into(), &mut writer);

            //end subjectconfirmationdata
            write_event(XmlEvent::end_element().into(), &mut writer);
        //end subjectconfirmation
        write_event(XmlEvent::end_element().into(), &mut writer);

    write_event(XmlEvent::end_element().into(), &mut writer);
    // end subject statement

    // start conditions statement
    write_event(XmlEvent::start_element(("saml", "Conditions"))
    .attr("NotBefore","2014-07-17T01:01:18Z")
    .attr("NotOnOrAfter","2024-01-18T06:21:48Z")
    .into(), &mut writer);

        write_event(XmlEvent::start_element(("saml", "AudienceRestriction")).into(), &mut writer);
            write_event(XmlEvent::start_element(("saml", "Audience")).into(), &mut writer);
            write_event(XmlEvent::characters("http://sp.example.com/demo1/metadata.php"), &mut writer);
            write_event(XmlEvent::end_element().into(), &mut writer);
            write_event(XmlEvent::end_element().into(), &mut writer);
            // end conditions statement
            write_event(XmlEvent::end_element().into(), &mut writer);

    // start authn statement
    write_event(XmlEvent::start_element(("saml", "AuthnStatement"))
        .attr("AuthnInstant","2014-07-17T01:01:48Z")
        .attr("SessionNotOnOrAfter","2024-07-17T09:01:48Z")
        .attr("SessionIndex","_be9967abd904ddcae3c0eb4189adbe3f71e327cf93")
        .into(), &mut writer);

        write_event(XmlEvent::start_element(("saml", "AuthnContext")).into(), &mut writer);
            write_event(XmlEvent::start_element(("saml", "AuthnContextClassRef")).into(), &mut writer);
                write_event(XmlEvent::characters("urn:oasis:names:tc:SAML:2.0:ac:classes:Password"), &mut writer);
            write_event(XmlEvent::end_element().into(), &mut writer);
        write_event(XmlEvent::end_element().into(), &mut writer);

    // end authn statement
    write_event(XmlEvent::end_element().into(), &mut writer);

    // start attribute statement
    write_event(XmlEvent::start_element(("saml", "AttributeStatement")).into(), &mut writer);




    add_attribute(ResponseAttribute::basic("uid", ["test"].to_vec()), &mut writer);
    add_attribute(ResponseAttribute::basic("mail", ["test@example.com"].to_vec()), &mut writer);
    add_attribute(ResponseAttribute::basic("eduPersonAffiliation",
                                        [
                                        "users",
                                        "examplerole1"
                                        ].to_vec()), &mut writer);

    // end attribute statement
    write_event(XmlEvent::end_element().into(), &mut writer);


    // end the assertion
    write_event(XmlEvent::end_element().into(), &mut writer);

    // end the response
    write_event(XmlEvent::end_element().into(), &mut writer);

    // finally we return the response
    buffer
}
