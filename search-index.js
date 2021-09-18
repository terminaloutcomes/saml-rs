var searchIndex = JSON.parse('{\
"saml_rs":{"doc":"A library for doing SAML things, terribly, in rust.","t":[3,3,3,12,12,3,12,12,5,0,11,11,11,11,11,11,11,11,0,0,12,12,5,5,11,11,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,11,12,12,12,12,0,11,11,5,5,5,12,12,0,11,12,12,0,12,12,0,0,11,11,11,11,11,11,11,11,11,11,11,11,0,12,12,11,11,11,11,0,3,3,4,13,13,13,4,13,13,13,4,3,13,12,11,5,11,5,12,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,11,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,12,12,12,12,12,12,12,11,12,12,12,12,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,11,11,11,11,11,11,11,5,3,11,11,11,11,11,5,5,11,5,11,11,11,11,11,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,13,4,13,13,13,13,13,13,11,11,11,11,11,11,11,11,11,11,11,3,12,11,11,12,11,11,11,5,12,11,12,11,11,12,11,12,11,11,11,11,11,12,5,3,3,5,5,11,12,12,12,12,11,11,11,11,11,12,11,12,12,11,11,11,11,12,11,11,11,12,12,11,12,12,12,12,12,12,12,12,12,12,11,11,11,11,11,11,11,11,4,13,13,13,13,13,13,13,13,13,13,13,13,4,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,5,5,5,11,11,11,11,11,11,11,11,11,11,11,11,13,13,13,13,13,13,4,13,4,4,3,3,13,13,13,13,13,11,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,11,11,11,11,11,12,12,12,11,11,11,11,11,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,5,17,17,17,17,8,5,10,8,5,5,10,5],"n":["AuthnDecodeError","AuthnRequest","AuthnRequestParser","RelayState","SAMLRequest","SamlQuery","SigAlg","Signature","_get_private_key","assertion","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","cert","constants","consumer_service_url","consumer_service_url","decode_authn_request_base64_encoded","decode_authn_request_signature","default","deserialize","destination","destination","fmt","fmt","fmt","fmt","from","from","from","from","from","into","into","into","into","issue_instant","issue_instant","issue_instant_string","issuer","issuer","issuer_state","message","metadata","new","new","parse_authn_request","parse_authn_tokenizer_attribute","parse_authn_tokenizer_element_start","relay_state","relay_state","response","serialize","sigalg","sigalg","sign","signature","signature","sp","test_samples","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","utils","version","version","vzip","vzip","vzip","vzip","xml","Assertion","AssertionAttribute","AssertionType","AttributeStatement","AuthnStatement","AuthzDecisionStatement","BaseIDAbstractType","NameQualifier","SPNameQualifier","Statement","StatusCode","SubjectData","Success","acs","add_assertion_to_xml","add_attribute","add_conditions","add_subject","assertion_id","attributes","audience","basic","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","build_assertion","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","conditions_not_after","conditions_not_before","default","digest_algorithm","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","into","into","into","into","into","into","into","issue_instant","issuer","name","nameformat","nameid_format","nameid_value","qualifier","qualifier_value","relay_state","serialize","sign_assertion","signing_algorithm","signing_cert","signing_key","subject_data","subject_not_on_or_after","to_owned","to_owned","to_owned","to_owned","to_string","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","type_id","values","vzip","vzip","vzip","vzip","vzip","vzip","without_signature","write_assertion_tmpdir","CertParseError","borrow","borrow_mut","fmt","fmt","from","gen_self_signed_certificate","init_cert_from_base64","into","strip_cert_headers","to_string","try_from","try_into","type_id","vzip","AuthnFailed","InvalidAttrNameOrValue","InvalidNameIDPolic","NoAuthnContext","NoAvailableIDP","NoPassive","NoSupportedIDP","PartialLogout","ProxyCountExceeded","RequestDenied","RequestUnsupported","RequestVersionDeprecated","RequestVersionTooHigh","RequestVersionTooLow","Requester","ResourceNotRecognized","Responder","StatusCode","Success","TooManyResponses","UnknownAttrProfile","UnknownPrincipal","UnsupportedBinding","VersionMismatch","borrow","borrow_mut","fmt","fmt","from","into","to_string","try_from","try_into","type_id","vzip","SamlMetadata","baseurl","borrow","borrow_mut","entity_id","fmt","from","from_hostname","generate_metadata_xml","hostname","into","logout_suffix","logout_url","new","post_suffix","post_url","redirect_suffix","redirect_url","try_from","try_into","type_id","vzip","x509_certificate","xml_add_certificate","AuthNStatement","ResponseElements","add_issuer","add_status","add_to_xmlevent","assertion_consumer_service","assertion_id","attributes","authnstatement","base64_encoded_response","borrow","borrow","borrow_mut","borrow_mut","classref","default","destination","expiry","fmt","fmt","from","from","instant","into","into","into","issue_instant","issuer","regenerate_response_id","relay_state","response_id","service_provider","session_index","session_length_seconds","sign_assertion","sign_message","signing_cert","signing_key","status","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip","DigestAlgorithm","InvalidAlgorithm","InvalidAlgorithm","Sha1","Sha1","Sha224","Sha224","Sha256","Sha256","Sha384","Sha384","Sha512","Sha512","SigningAlgorithm","borrow","borrow","borrow_mut","borrow_mut","clone","clone","clone_into","clone_into","fmt","fmt","fmt","fmt","from","from","from","from","from","hash","into","into","load_key_from_filename","load_public_cert_from_filename","sign_data","to_owned","to_owned","to_string","to_string","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip","AssertionConsumerService","EmailAddress","Entity","HttpPost","HttpRedirect","Kerberos","NameIdFormat","Persistent","SamlBinding","SamlBindingType","ServiceBinding","ServiceProvider","SingleLogoutService","Transient","Unspecified","WindowsDomainQualifiedName","X509SubjectName","attrib_parser","authn_requests_signed","binding","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","default","default","default","deserialize","deserialize","deserialize","deserialize","entity_id","find_first_acs","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from_str","from_str","from_str","from_str","index","into","into","into","into","into","location","nameid_format","protocol_support_enumeration","serialize","serialize","serialize","serialize","service_attrib_parser","services","servicetype","set_binding","test_generic","to_owned","to_owned","to_owned","to_owned","to_owned","to_string","to_string","to_string","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","vzip","vzip","vzip","vzip","vzip","want_assertions_signed","x509_certificate","xml_indent","TEST_AUTHN_REQUEST_EXAMPLE_COM","TEST_AUTHN_REQUEST_EXAMPLE_COM_BASE64_DEFLATED","TEST_AUTHN_REQUEST_WITH_EMBEDDED_SIGNATURE_POST","TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION","DateTimeUtils","to_hex_string","to_saml_datetime_string","X509Utils","add_assertion_signature","generate_signedinfo","get_as_pem_string","write_event"],"q":["saml_rs","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::assertion","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::cert","","","","","","","","","","","","","","","saml_rs::constants","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::metadata","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::response","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::sign","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::sp","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::test_samples","","","","saml_rs::utils","","","saml_rs::xml","","","",""],"d":["Custom error for failing to parse an AuthN request","Stores the values one would expect in an AuthN Request","Used to pull apart a SAML AuthN Request and build a …","The RelayState token is an opaque reference to state …","The value of the SAMLRequest parameter is a deflated, …","Used in the SAML Redirect GET request to pull out the …","Stores the signature type - this should be URL-decoded by …","Stores a base64-encoded signature… TODO: is Signature <em>…","","Assertion-related things","","","","","","","","","Certificate and signing-related things","Constants for the saml-rs module.","Consumer URL - where the SP wants you to send responses to","Consumer URL - where the SP wants you to send responses to","Removes base64 encoding and also deflates the input …","Does the decoding to hand the signature to the verifier","","","Destination… TODO: work out if/why this is different to …","Destination…","","","","","","Allows one to turn a AuthnRequestParser into a Request …","","","","","","","","AuthN request issue time, generated by the SP - or shoved …","AuthN request issue time, generated by the SP - or shoved …","Return the issue instant in the required form","Issuer of the request - used for matching to the …","Issuer of the request - used for matching to the …","Internal state id for the issuer","Error message","Handy for the XML metadata part of SAML","Generatin’ a new AuthDecodeError","Generate a new AuthnRequestParser","Give it a string full of XML and it’ll give you back a …","Used inside AuthnRequestParser to help parse the AuthN …","Used inside AuthnRequestParser to help parse the AuthN …","RelayState provided as part of the request","Request ID / RelayState as provided by the SP","Want to build a SAML response? Here’s your module. 🥳","","Signature algorithm, if the request is signed","Signature algorithm, if the request is signed","Functions for signing data","Signature, if signed","Signature algorithm, if the request is signed","Service Provider utilities and functions","Random samples of XML I’ve found around the place","","","","","","","","","","","","","Extensions for things and generic utilities","This better be 2.0!","This better be 2.0!","","","","","Internal utilities for doing things with XML","The content of an assertion","Attributes for responses","AssertionTypes, from …","","","","Type of <code>saml:NameId</code> in a statement.","","This’ll be the one you normally use - TODO I think …","","StatusCode values","Data type for passing subject data in because yeaaaaah, …","<code>urn:oasis:names:tc:SAML:2.0:status:Success</code>","The AssertionConsumerService - where we’ll send the …","This adds the data from an Assertion to a given …","add an attribute to the statement","adds a <code>saml:Conditions</code> statement to the writer","Adds the Subject statement to an assertion","Assertion ID, referred to in the signature as ds:Reference","Attributes of the assertion, things like groups and email …","Who/what should be reading this. Probably a …","new Response Attribute with <code>attrname-format:basic</code>","","","","","","","","","","","","","Build an assertion based on the Assertion, returns a …","","","","","","","","","Please don’t let the user do whatever we’re saying …","Please don’t let the user do this until … now!","","Digest algorithm","","","","","","","","","","","","","","","","","","","Issue/Generatino time of the Assertion","Issuer of the Assertion","","","crate::sp::NameIdFormat, what kind of format you’re… …","NameID value - I know this one, it’s the reference to …","Qualifier TODO: What’s the qualifier again?","Qualifier value TODO: I really should know what these are","Relay state as provided by the crate::AuthnRequest","","Should we sign the assertion?","Signing algorithm","Certificate for signing/digest","an openssl private key for signing","TODO: work out what is necessary for SubjectData","The expiry of this Assertion. Woo, recovered there at the …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","This exists so we can return a copy of an Assertion …","","Error type for when parsing certificates from input","","","","","","generates a really terrible self-signed certificate for …","this is a terrible function and only used for me to …","","Strips <code>-----BEGIN CERTIFICATE-----</code> and …","","","","","","urn:oasis:names:tc:SAML:2.0:status:AuthnFailed The …","urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue …","urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy …","urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext The …","urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP Used by …","urn:oasis:names:tc:SAML:2.0:status:NoPassive Indicates …","urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP Used by …","urn:oasis:names:tc:SAML:2.0:status:PartialLogout Used by …","urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded …","urn:oasis:names:tc:SAML:2.0:status:RequestDenied The SAML …","urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported The …","…","urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh …","urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow …","urn:oasis:names:tc:SAML:2.0:status:Requester The request …","urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized …","urn:oasis:names:tc:SAML:2.0:status:Responder The request …","3.2.2.2 Element StatusCode","urn:oasis:names:tc:SAML:2.0:status:Success The request …","urn:oasis:names:tc:SAML:2.0:status:TooManyResponses The …","urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile An …","urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal The …","urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding The …","urn:oasis:names:tc:SAML:2.0:status:VersionMismatch The …","","","","","","","","","","","","Stores the required data for generating a SAML metadata …","Set this as the base of the suffix-items elsewhere","","","entityID is transmitted in all requests","","","really simple version with a self-signed certificate …","Generates the XML For a metadata file","Hostname of the issuer, used for URLs etc","","Appended to the baseurl when using the …","return the generated Logout URL based on the baseurl + …","Create a new SamlMetadata object for your IdP","Appended to the baseurl when using the …","return the generated post URL based on the baseurl + …","Appended to the baseurl when using the …","return the generated redirect URL based on the baseurl + …","","","","","Public certificate for signing/encryption","Write a signing key to an XMLEventWriter","An Authentication Statement for returning inside an …","Stores all the required elements of a SAML response… …","Adds the issuer statement to a response","Adds a set of status tags to a response","Used elsewhere in the API to add an AuthNStatement to the …","TODO: Decide if we can just pick it from the SP","ID Of the assertion","A list of relevant AssertionAttributes","The AuthNStatement itself","returns the base64 encoded version of a ResponseElements","","","","","TODO: do we need to respond with multiple context class …","Default values, mostly so I can pull out a default …","Destination endpoint of the request","Expiry of the statement, TODO: find out if this is …","","","","","Issue time of the response TODO Figure out if this is …","","","","Issue time of the response","Issuer of the resposne?","generate a response ID, which will be the issuer and uuid …","RelayState from the original AuthN request","ID of the response TODO: Figure out the rules for …","crate::sp::ServiceProvider","TODO document this","Session length in seconds, 4294967295 should be enough …","Should we sign the assertion?","Should we sign the message?","The signing certificate","an openssl private key for signing","crate::constants::StatusCode of the response","","","","","","","","","Options of Digest Algorithms for things","If you try to use the wrong one","If you try to use the wrong one","SHA1 Algorithm","SHA1 Algorithm (Use is DISCOURAGED; see SHA-1 Warning)","Really?","Really?","SHA256 Algorithm","SHA256 Algorithm","For when 256 isn’t enough","For when 256 isn’t enough","Size does matter, I guess?","Size does matter, I guess?","Options of Signing Algorithms for things","","","","","","","","","","","","","","","","","","Hash a set of bytes using an openssl::hash::MessageDigest","","","Loads a PEM-encoded public key into a PKey object","Loads a public cert from a PEM file into an X509 object","Sign some data, with a key","","","","","","","","","","","","","AssertionConsumerService, where you send Authn Rssponses","Email Address","TODO: entity?","HTTP-POST method","HTTP-REDIRECT method","Kerberos, the worst-eros","Different types of name-id formats from the spec","Should stay the same","Binding methods TODO: should this be renamed to binding …","Allows one to build a definition with …","Types of bindings for service providers TODO: implement a …","SP metadata object, used for being able to find one when …","Logout endpoints","Don’t keep this, it’ll change","🤷‍♂️🤷‍♀️ who even knows","Windows format","X509 format","Let’s parse some attributes!","Will this SP send signed requests? If so, we’ll reject …","Binding method","","","","","","","","","","","","","","","","","","","","","","","return a default broken binding for testing or later …","","","","","EntityID","return the first AssertionConsumerService we find","","","","","","","","","","","","","turn a string into a SamlBinding","","Consumer index, if there’s more than 256 then wow, …","","","","","","Where to send the response to","NameIdFormat - how we should identify the user","TODO protocol_support_enumeration? what’s this?","","","","","Used for handling the attributes of services in the tags …","SP Services","SamlBindingType Binding type, things like <code>HTTP-POST</code> or …","TODO: actually use this in ServiceProvider from_xml or …","Generate a test generic ServiceProvider with nonsense …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Does this SP expect signed assertions?","The signing (public) certificate for the SP","Used for showing the details of the SP Metadata XML file","Simple AuthnRequest base64 ID=1234","Simple AuthnRequest ID=1234 base64 encoded and deflate-d","AuthNRequest with embedded signature (HTTP-POST binding)","Example SAML unsigned response with unsigned assertion - …","Extensions for chrono::DateTime for nicer functionality","Takes a Vec and turns it into a String","return a DateTime object as a string","Extensions for openssl::x509::X509 for nicer functionality","add a signature to the statement","add a signature to the statement","return an X509 object as a string, either including the …","Used by the XML Event writer to append events to the …"],"i":[0,0,0,1,1,0,1,1,0,0,2,3,4,1,2,3,4,1,0,0,3,4,0,0,4,1,3,4,2,3,4,1,2,3,3,4,1,2,3,4,1,3,4,3,3,4,4,2,0,2,4,0,0,0,3,4,0,3,3,4,0,3,4,0,0,2,3,4,1,2,3,4,1,2,3,4,1,0,3,4,2,3,4,1,0,0,0,0,5,5,5,0,6,6,5,0,0,7,8,9,0,9,0,9,9,9,10,5,7,9,6,8,10,5,7,9,6,8,10,9,9,6,8,10,9,6,8,10,9,9,10,9,9,6,8,10,5,7,9,6,6,8,10,5,7,9,9,6,8,10,9,9,10,10,8,8,8,8,8,10,9,9,9,9,9,8,9,6,8,10,6,5,7,9,6,8,10,5,7,9,6,8,10,5,7,9,6,8,10,10,5,7,9,6,8,10,9,0,0,11,11,11,11,11,0,0,11,0,11,11,11,11,11,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,0,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,0,13,13,13,13,13,13,13,0,13,13,13,13,13,13,13,13,13,13,13,13,13,13,0,0,0,0,0,14,15,15,15,15,15,15,14,15,14,14,15,15,14,15,14,15,14,14,15,15,14,15,15,15,15,15,15,14,15,15,15,15,15,15,15,14,15,14,15,14,15,14,0,16,17,16,17,16,17,16,17,16,17,16,17,0,16,17,16,17,16,17,16,17,16,16,17,17,16,16,17,17,17,17,16,17,0,0,0,16,17,16,17,16,17,16,17,16,17,16,17,18,19,19,20,20,19,0,19,0,0,0,0,18,19,19,19,19,21,21,22,19,18,20,22,21,19,18,20,22,21,19,18,20,22,21,19,18,20,22,21,19,20,22,19,18,20,22,21,21,19,18,20,22,21,19,18,20,22,21,19,18,20,21,22,19,18,20,22,21,22,21,21,19,18,20,22,21,21,22,22,21,19,18,20,22,21,19,18,20,19,18,20,22,21,19,18,20,22,21,19,18,20,22,21,19,18,20,22,21,21,21,0,0,0,0,0,0,0,23,0,0,0,24,0],"f":[null,null,null,null,null,null,null,null,[[]],null,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],null,null,null,null,[[["string",3]],[["string",3],["authndecodeerror",3],["result",4,["string","authndecodeerror"]]]],[[["string",3]],["string",3]],[[],["authnrequestparser",3]],[[],["result",4]],null,null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[["authnrequestparser",3]]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],null,null,[[],["string",3]],null,null,null,null,null,[[["string",3]],["authndecodeerror",3]],[[]],[[["str",15]],[["string",3],["authnrequest",3],["result",4,["authnrequest","string"]]]],[[["authnrequestparser",3],["strspan",3]],[["authndecodeerror",3],["result",4,["authnrequestparser","authndecodeerror"]],["authnrequestparser",3]]],[[["authnrequestparser",3],["strspan",3]],["authnrequestparser",3]],null,null,null,[[],["result",4]],null,null,null,null,null,null,null,[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],null,null,null,[[]],[[]],[[]],[[]],null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[["eventwriter",3]]],[[["assertionattribute",3],["eventwriter",3]]],[[["eventwriter",3]]],[[["subjectdata",3],["eventwriter",3]]],null,null,null,[[["str",15],["vec",3,["str"]],["str",15]],["assertionattribute",3]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[["bool",15]],["string",3]],[[],["assertion",3]],[[],["baseidabstracttype",4]],[[],["subjectdata",3]],[[],["assertionattribute",3]],[[]],[[]],[[]],[[]],null,null,[[],["assertionattribute",3]],null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[]],[[]],[[["string",3]]],[[]],[[]],[[]],[[]],[[]],[[],[["vec",3,["u8"]],["u8",15]]],[[]],[[]],[[]],null,null,null,null,null,null,null,null,null,[[],["result",4]],null,null,null,null,null,null,[[]],[[]],[[]],[[]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],null,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],null,[[]],[[]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[["str",15]],["x509",3]],[[["str",15]],[["certparseerror",3],["x509",3],["result",4,["x509","certparseerror"]]]],[[]],[[["string",3]],["string",3]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[]],[[]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],null,null,[[]],[[]],null,[[["formatter",3]],["result",6]],[[]],[[["str",15]],["samlmetadata",3]],[[["samlmetadata",3]],["string",3]],null,[[]],null,[[],["string",3]],[[["string",3],["option",4,["x509"]],["x509",3],["str",15],["option",4,["string"]]]],null,[[],["string",3]],null,[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],null,[[["str",15],["eventwriter",3]]],null,null,[[["str",15],["eventwriter",3]]],[[["str",15],["eventwriter",3]]],[[["eventwriter",3]]],null,null,null,null,[[],[["vec",3,["u8"]],["u8",15]]],[[]],[[]],[[]],[[]],null,[[]],null,null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],null,[[]],[[],[["vec",3,["u8"]],["u8",15]]],[[]],null,null,[[]],null,null,null,null,null,null,null,null,null,null,[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]],null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[]],[[]],[[]],[[]],[[],["signingalgorithm",4]],[[],["digestalgorithm",4]],[[]],[[]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[["string",3]]],[[["string",3]]],[[["messagedigest",3]]],[[]],[[],[["result",4,["digestbytes","errorstack"]],["digestbytes",3],["errorstack",3]]],[[]],[[]],[[["str",15]],[["string",3],["pkey",3,["private"]],["result",4,["pkey","string"]]]],[[["str",15]],[["string",3],["x509",3],["result",4,["x509","string"]]]],[[["signingalgorithm",4],["pkey",3]],[["vec",3,["u8"]],["u8",15]]],[[]],[[]],[[],["string",3]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]],null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[["ownedattribute",3],["str",15],["vec",3,["ownedattribute"]]]],null,null,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],["nameidformat",4]],[[],["samlbindingtype",4]],[[],["samlbinding",4]],[[],["servicebinding",3]],[[],["serviceprovider",3]],[[]],[[]],[[]],[[]],[[]],[[],["nameidformat",4]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],null,[[],[["str",15],["result",4,["servicebinding","str"]],["servicebinding",3]]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[]],[[]],[[]],[[["str",15]],["result",4]],[[["str",15]],["result",4]],[[["str",15]],["result",4]],[[["str",15]],["result",4]],null,[[]],[[]],[[]],[[]],[[]],null,null,null,[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[["samlbindingtype",4],["ownedattribute",3],["vec",3,["ownedattribute"]]],[["result",4,["servicebinding","string"]],["string",3],["servicebinding",3]]],null,null,[[["string",3]],[["string",3],["result",4,["string"]]]],[[["str",15]]],[[]],[[]],[[]],[[]],[[]],[[],["string",3]],[[],["string",3]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[]],null,null,[[["usize",15]],["string",3]],null,null,null,null,null,[[["u8",15],["option",4,["str"]],["vec",3,["u8"]],["str",15]],["string",3]],[[],["string",3]],null,[[["string",3],["eventwriter",3],["assertion",3]]],[[["str",15],["eventwriter",3],["assertion",3]]],[[["bool",15]],["string",3]],[[["eventwriter",3],["xmlevent",4]],["string",3]]],"p":[[3,"SamlQuery"],[3,"AuthnDecodeError"],[3,"AuthnRequest"],[3,"AuthnRequestParser"],[4,"AssertionType"],[4,"BaseIDAbstractType"],[4,"StatusCode"],[3,"SubjectData"],[3,"Assertion"],[3,"AssertionAttribute"],[3,"CertParseError"],[4,"StatusCode"],[3,"SamlMetadata"],[3,"AuthNStatement"],[3,"ResponseElements"],[4,"SigningAlgorithm"],[4,"DigestAlgorithm"],[4,"SamlBindingType"],[4,"NameIdFormat"],[4,"SamlBinding"],[3,"ServiceProvider"],[3,"ServiceBinding"],[8,"DateTimeUtils"],[8,"X509Utils"]]},\
"saml_test_server":{"doc":"A test server for running as a SAML IdP","t":[5,5,5,5,5,0,3,3,12,11,11,11,11,11,11,11,11,11,5,12,11,11,11,11,11,11,12,11,11,12,5,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,11,11,11,11,11,11,11,11,11,11],"n":["generate_login_form","main","saml_metadata_get","saml_post_binding","saml_redirect_get","util","AppState","ServerConfig","bind_address","borrow","borrow","borrow_mut","borrow_mut","clone","clone","clone_into","clone_into","default","do_nothing","entity_id","fmt","fmt","from","from","from","from_filename_and_env","hostname","into","into","issuer","load_sp_metadata","public_hostname","saml_cert_path","saml_cert_path","saml_key_path","saml_key_path","saml_signing_cert","saml_signing_cert","saml_signing_key","saml_signing_key","service_providers","session_lifetime","sp_metadata","sp_metadata_files","tls_cert_path","tls_cert_path","tls_key_path","tls_key_path","to_owned","to_owned","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip"],"q":["saml_test_server","","","","","","saml_test_server::util","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"d":["Generate a fake login form for the user to interact with","","Provides a GET response for the metadata URL","Handles a POST binding","SAML requests or responses transmitted via HTTP Redirect …","","","","","","","","","","","","","","Placeholder function for development purposes, just …","","","","","","","Pass this a filename (with or without extension) and it’…","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"i":[0,0,0,0,0,0,0,0,1,1,2,1,2,1,2,1,2,1,0,1,1,2,1,2,2,1,2,1,2,2,0,1,1,2,1,2,1,2,1,2,2,1,1,1,1,2,1,2,1,2,1,2,1,2,1,2,1,2],"f":[[[["responseelements",3],["string",3]],["string",3]],[[],["result",6]],[[["request",3,["appstate"]],["appstate",3]]],[[["request",3,["appstate"]],["appstate",3]]],[[["request",3,["appstate"]],["appstate",3]]],null,null,null,null,[[]],[[]],[[]],[[]],[[],["serverconfig",3]],[[],["appstate",3]],[[]],[[]],[[]],[[["request",3,["appstate"]],["appstate",3]]],null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[["serverconfig",3]],["appstate",3]],[[]],[[["string",3]]],null,[[]],[[]],null,[[["vec",3,["string"]],["string",3]],[["serviceprovider",3],["string",3],["hashmap",3,["string","serviceprovider"]]]],null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]]],"p":[[3,"ServerConfig"],[3,"AppState"]]}\
}');
if (window.initSearch) {window.initSearch(searchIndex)};