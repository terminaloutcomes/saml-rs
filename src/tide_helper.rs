use crate::metadata::{generate_metadata_xml, SamlMetadata};
use crate::{decode_authn_request_base64_encoded, parse_authn_request, SamlAuthnRequest};
use tide::prelude::Deserialize;

/// Useful for tide servers to respond with a metadata XML file
pub async fn tide_metadata_response(
    _req: tide::Request<()>,
    metadata: SamlMetadata,
) -> tide::Result {
    let mut res = tide::Response::new(200);
    // Metadata spec is here http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
    // application/samlmetadata+xml
    res.set_content_type("application/samlmetadata+xml");
    res.set_body(generate_metadata_xml(metadata));
    Ok(res)
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct SAMLRedirectQuery {
    /// Used in the SAML Redirect GET request to pull out the query values
    SAMLRequest: String,
    RelayState: String,
}
pub async fn saml_redirect_get(req: tide::Request<()>) -> tide::Result {
    let mut res = tide::Response::new(200);

    let mut response_body = String::from("saml_redirect_get\n\n");

    let referer = req
        .header("Referer")
        .and_then(|hv| hv.get(0))
        .map(|h| h.as_str())
        .ok_or_else(|| {
            error!("Missing Header: Referer in saml_redirect_get");
            tide::Error::from_str(tide::StatusCode::BadRequest, "Missing Referer header")
        })?;

    let query: SAMLRedirectQuery = match req.query() {
        Ok(val) => val,
        Err(e) => {
            error!("Missing SAMLRequest request in saml_redirect_get {:?}", e);
            return Err(tide::Error::from_str(
                tide::StatusCode::BadRequest,
                "Missing SAMLRequest",
            ));
        }
    };
    // I'm not sure why this is here but I better not lose it
    // https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd#rsa-sha1

    let base64_decoded_samlrequest =
        match decode_authn_request_base64_encoded(query.SAMLRequest.to_string()) {
            Ok(val) => val,
            Err(error) => {
                return Err(tide::Error::from_str(tide::StatusCode::BadRequest, error));
            }
        };

    let parsed_saml_request: SamlAuthnRequest =
        match parse_authn_request(&base64_decoded_samlrequest) {
            Ok(val) => {
                // this is all just yale debugging things....
                val
            }
            Err(err) => {
                eprintln!("{:?}", err);
                return Err(tide::Error::from_str(tide::StatusCode::BadRequest, err));
            }
        };

    response_body.push_str(&format!(
        "request_id: {:?}\n",
        parsed_saml_request.request_id
    ));
    response_body.push_str(&format!(
        "issue_instant: {:?}\n",
        parsed_saml_request.issue_instant
    ));
    response_body.push_str(&format!(
        "consumer_service_url: {:?}\n",
        parsed_saml_request.consumer_service_url
    ));
    response_body.push_str(&format!("issuer: {:?}\n", parsed_saml_request.issuer));
    response_body.push_str(&format!("Referer: {}\n", referer));
    response_body.push_str(&format!("SAMLRequest: {}\n", query.SAMLRequest));
    response_body.push_str(&format!("RelayState: {}\n", query.RelayState));

    res.set_body(response_body);

    Ok(res)
}
