var searchIndex = JSON.parse('{\
"saml_rs":{"doc":"A library for doing SAML things, terribly, in rust.","t":[3,12,12,3,3,3,12,12,5,11,11,11,11,11,11,11,11,0,12,12,5,5,11,11,12,12,12,11,11,11,11,11,11,11,11,11,11,11,11,12,12,11,12,12,12,12,0,11,11,5,5,5,12,12,0,11,12,12,0,12,12,0,0,11,11,11,11,11,11,11,11,11,11,11,11,12,12,11,11,11,11,0,3,11,11,11,11,11,5,5,11,5,11,11,11,11,11,3,12,11,11,12,11,11,11,5,12,11,12,11,11,12,11,12,11,11,11,11,11,12,3,3,5,5,11,12,12,12,5,11,11,11,11,12,5,12,12,11,11,11,11,12,11,11,12,12,12,12,12,11,11,11,11,11,11,11,11,11,5,5,5,13,13,13,13,13,13,4,13,4,4,3,3,13,13,13,13,13,11,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,11,11,11,11,11,12,12,12,11,11,11,11,11,12,12,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,12,12,5,17,17,17,17,3,5,11,11,11,11,11,11,11,11,11,12,12,11,11,11,11,11,12,11,5],"n":["AuthnDecodeError","RelayState","SAMLRequest","SamlAuthnRequest","SamlAuthnRequestParser","SamlQuery","SigAlg","Signature","_get_private_key","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","cert","consumer_service_url","consumer_service_url","decode_authn_request_base64_encoded","decode_authn_request_signature","default","deserialize","destination","destination","error","fmt","fmt","fmt","from","from","from","from","from","into","into","into","into","issue_instant","issue_instant","issue_instant_string","issuer","issuer","issuer_state","message","metadata","new","new","parse_authn_request","parse_authn_tokenizer_attribute","parse_authn_tokenizer_element_start","request_id","request_id","response","serialize","sigalg","sigalg","sign","signature","signature","sp","test_samples","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","version","version","vzip","vzip","vzip","vzip","xml","CertParseError","borrow","borrow_mut","fmt","fmt","from","gen_self_signed_certificate","init_cert_from_base64","into","strip_cert_headers","to_string","try_from","try_into","type_id","vzip","SamlMetadata","baseurl","borrow","borrow_mut","entity_id","fmt","from","from_hostname","generate_metadata_xml","hostname","into","logout_suffix","logout_url","new","post_suffix","post_url","redirect_suffix","redirect_url","try_from","try_into","type_id","vzip","x509_certificate","AuthNStatement","ResponseElements","add_issuer","add_status","add_to_xmlevent","assertion_id","attributes","authnstatement","base64_encoded_response","borrow","borrow","borrow_mut","borrow_mut","classref","create_response","destination","expiry","fmt","fmt","from","from","instant","into","into","issue_instant","issuer","request_id","response_id","session_index","to_string","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip","load_key_from_filename","load_public_cert_from_filename","sign_data","AssertionConsumerService","EmailAddress","Entity","HttpPost","HttpRedirect","Kerberos","NameIdFormat","Persistent","SamlBinding","SamlBindingType","ServiceBinding","ServiceProvider","SingleLogoutService","Transient","Unspecified","WindowsDomainQualifiedName","X509SubjectName","attrib_parser","authn_requests_signed","binding","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","default","default","default","deserialize","deserialize","deserialize","deserialize","entity_id","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from_str","from_str","from_str","from_xml","index","into","into","into","into","into","location","nameid_format","protocol_support_enumeration","serialize","serialize","serialize","serialize","service_attrib_parser","services","servicetype","set_binding","to_owned","to_owned","to_owned","to_owned","to_owned","to_string","to_string","to_string","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","vzip","vzip","vzip","vzip","vzip","want_assertions_signed","x509_certificate","xml_indent","TEST_AUTHN_REQUEST_EXAMPLE_COM","TEST_AUTHN_REQUEST_EXAMPLE_COM_BASE64_DEFLATED","TEST_AUTHN_REQUEST_WITH_EMBEDDED_SIGNATURE_POST","TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION","ResponseAttribute","add_attribute","basic","borrow","borrow_mut","clone","clone_into","default","fmt","from","into","name","nameformat","serialize","to_owned","try_from","try_into","type_id","values","vzip","write_event"],"q":["saml_rs","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::cert","","","","","","","","","","","","","","","saml_rs::metadata","","","","","","","","","","","","","","","","","","","","","","","saml_rs::response","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::sign","","","saml_rs::sp","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::test_samples","","","","saml_rs::xml","","","","","","","","","","","","","","","","","","","",""],"d":["","The RelayState token is an opaque reference to state …","The value of the SAMLRequest parameter is a deflated, …","Stores the values one would expect in an AuthN Request","Used to pull apart a SAML AuthN Request and build a […","Used in the SAML Redirect GET request to pull out the …","","","","","","","","","","","","Certificate and signing-related things","","","","","","","","","","","","","","Allows one to turn a [SamlAuthnRequestParser] into a …","","","","","","","","","","","","","","","Handy for the XML metadata part of SAML","","","Give it a string full of XML and it’ll give you back a […","Used inside SamlAuthnRequestParser to help parse the …","Used inside SamlAuthnRequestParser to help parse the …","","","Want to build a SAML response? Here’s your module. 🥳","","","","Functions for signing data","","","Service Provider utilities and functions","Random samples of XML I’ve found around the place","","","","","","","","","","","","","","","","","","","Internal utilities for doing things with XML","","","","","","","generates a really terrible self-signed certificate for …","this is a terrible function and only used for me to …","","","","","","","","Stores the required data for generating a SAML metadata …","","","","entityID is transmitted in all requests Every SAML system …","","","","Generates the XML For a metadata file","","","Appended to the baseurl when using the […","","","Appended to the baseurl when using the […","","Appended to the baseurl when using the […","","","","","","","An Authentication Statement for returning inside an …","Stores all the required elements of a SAML response… …","Adds the issuer statement to a response","Adds a set of status tags to a response","Used elsewhere in the API to add it to the Response XML","","","","returns the base64 encoded version of [create_response]","","","","","","Creates a <code>samlp:Response</code> objects based on the input data (…","","","","","","","","","","","","","","","Formats it all pretty-like, in XML","","","","","","","","","","","","","","","","","","","","","Allows one to build a definition with […","Types of bindings for service providers TODO: implement a …","","","","","","","Let’s parse some attributes!","Will this SP send signed requests? If so, we’ll reject …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","EntityID","","","","","","","","","","","","","","Hand this a bucket of string data and you should get a …","Consumer index, if there’s more than 256 then wow, …","","","","","","Where to send the response to","","","","","","","Used for handling the attributes of services in the tags …","SP Services","","TODO: actually use this in ServiceProvider::fromxml()","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Does this SP expect signed assertions?","The signing (public) certificate for the SP","Used for showing the details of the SP Metadata XML file","Simple AuthnRequest base64 ID=1234","Simple AuthnRequest ID=1234 base64 encoded and deflate-d","","Example SAML unsigned response with unsigned assertion - …","","add an attribute to the statement","","","","","","","","","","","","","","","","","","","Used by the XML Event writer to append events to the …"],"i":[0,1,1,0,0,0,1,1,0,2,3,4,1,2,3,4,1,0,3,4,0,0,4,1,3,4,4,2,3,4,2,3,3,4,1,2,3,4,1,3,4,3,3,4,4,2,0,2,4,0,0,0,3,4,0,3,3,4,0,3,4,0,0,2,3,4,1,2,3,4,1,2,3,4,1,3,4,2,3,4,1,0,0,5,5,5,5,5,0,0,5,0,5,5,5,5,5,0,6,6,6,6,6,6,6,0,6,6,6,6,6,6,6,6,6,6,6,6,6,6,0,0,0,0,7,8,8,8,0,8,7,8,7,7,0,8,7,8,7,8,7,7,8,7,8,8,8,8,7,7,8,7,8,7,8,7,8,7,0,0,0,9,10,10,11,11,10,0,10,0,0,0,0,9,10,10,10,10,12,12,13,10,9,11,13,12,10,9,11,13,12,10,9,11,13,12,10,9,11,13,12,10,11,13,10,9,11,13,12,10,9,11,13,12,10,9,11,13,12,10,9,11,12,13,10,9,11,13,12,13,12,12,10,9,11,13,12,12,13,13,10,9,11,13,12,10,9,11,10,9,11,13,12,10,9,11,13,12,10,9,11,13,12,10,9,11,13,12,12,12,0,0,0,0,0,0,0,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,0],"f":[null,null,null,null,null,null,null,null,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],null,null,null,[[["string",3]],[["authndecodeerror",3],["string",3],["result",4]]],[[["string",3]],["string",3]],[[],["samlauthnrequestparser",3]],[[],["result",4]],null,null,null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[["samlauthnrequestparser",3]]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],null,null,[[],["string",3]],null,null,null,null,null,[[["string",3]],["authndecodeerror",3]],[[]],[[["str",15]],[["str",15],["result",4],["samlauthnrequest",3]]],[[["strspan",3],["samlauthnrequestparser",3]],["samlauthnrequestparser",3]],[[["strspan",3],["samlauthnrequestparser",3]],["samlauthnrequestparser",3]],null,null,null,[[],["result",4]],null,null,null,null,null,null,null,[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],null,null,[[]],[[]],[[]],[[]],null,null,[[]],[[]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[["str",15]],["x509",3]],[[["str",15]],[["x509",3],["result",4],["certparseerror",3]]],[[]],[[["string",3]],["string",3]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],null,null,[[]],[[]],null,[[["formatter",3]],["result",6]],[[]],[[["str",15]],["samlmetadata",3]],[[["samlmetadata",3]],["string",3]],null,[[]],null,[[],["string",3]],[[["x509",3],["string",3],["str",15],["option",4]]],null,[[],["string",3]],null,[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],null,null,null,[[["str",15],["eventwriter",3]]],[[["str",15],["eventwriter",3]]],[[["eventwriter",3]]],null,null,null,[[["responseelements",3],["bool",15]],[["u8",15],["vec",3]]],[[]],[[]],[[]],[[]],null,[[["responseelements",3]],[["u8",15],["vec",3]]],null,null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],null,[[]],[[]],null,null,null,null,null,[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]],[[["str",15]],[["pkey",3],["string",3],["result",4]]],[[["str",15]],[["result",4],["x509",3],["string",3]]],[[["string",3]]],null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[["vec",3],["str",15],["ownedattribute",3]]],null,null,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],["nameidformat",4]],[[],["samlbindingtype",4]],[[],["samlbinding",4]],[[],["servicebinding",3]],[[],["serviceprovider",3]],[[]],[[]],[[]],[[]],[[]],[[],["nameidformat",4]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[]],[[]],[[]],[[["str",15]],["result",4]],[[["str",15]],["result",4]],[[["str",15]],["result",4]],[[["str",15]],["serviceprovider",3]],null,[[]],[[]],[[]],[[]],[[]],null,null,null,[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[["samlbindingtype",4],["ownedattribute",3],["vec",3]],[["string",3],["result",4],["servicebinding",3]]],null,null,[[["string",3]],[["result",4],["string",3]]],[[]],[[]],[[]],[[]],[[]],[[],["string",3]],[[],["string",3]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[]],null,null,[[["usize",15]],["string",3]],null,null,null,null,null,[[["responseattribute",3],["eventwriter",3]]],[[["string",3],["str",15],["vec",3]],["responseattribute",3]],[[]],[[]],[[],["responseattribute",3]],[[]],[[],["responseattribute",3]],[[["formatter",3]],["result",6]],[[]],[[]],null,null,[[],["result",4]],[[]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],null,[[]],[[["xmlevent",4],["eventwriter",3]],["string",3]]],"p":[[3,"SamlQuery"],[3,"AuthnDecodeError"],[3,"SamlAuthnRequest"],[3,"SamlAuthnRequestParser"],[3,"CertParseError"],[3,"SamlMetadata"],[3,"AuthNStatement"],[3,"ResponseElements"],[4,"SamlBindingType"],[4,"NameIdFormat"],[4,"SamlBinding"],[3,"ServiceProvider"],[3,"ServiceBinding"],[3,"ResponseAttribute"]]},\
"saml_test_server":{"doc":"A test server for running as a SAML IdP","t":[3,11,11,11,11,11,11,5,12,11,12,5,5,5,5,12,5,12,12,11,11,11,11,0,11,3,12,11,11,11,5,12,11,11,11,11,5,12,12,12,12,12,11,11,11,11],"n":["AppState","borrow","borrow_mut","clone","clone_into","fmt","from","generate_login_form","hostname","into","issuer","main","saml_metadata_get","saml_post_binding","saml_redirect_get","service_providers","test_sign","tls_cert_path","tls_key_path","to_owned","try_from","try_into","type_id","util","vzip","ServerConfig","bind_address","borrow","borrow_mut","default","do_nothing","entity_id","fmt","from","from_filename_and_env","into","load_sp_metadata","public_hostname","sp_metadata","sp_metadata_files","tls_cert_path","tls_key_path","try_from","try_into","type_id","vzip"],"q":["saml_test_server","","","","","","","","","","","","","","","","","","","","","","","","","saml_test_server::util","","","","","","","","","","","","","","","","","","","",""],"d":["","","","","","","","Generate a fake login form for the user to interact with","","","","","Provides a GET response for the metadata URL","Handles a POST binding","SAML requests or responses transmitted via HTTP Redirect …","","","","","","","","","","","","","","","","Placeholder function for development purposes, just …","","","","Pass this a filename (with or without extension) and it’…","","","","","","","","","","",""],"i":[0,1,1,1,1,1,1,0,1,1,1,0,0,0,0,1,0,1,1,1,1,1,1,0,1,0,2,2,2,2,0,2,2,2,2,2,0,2,2,2,2,2,2,2,2,2],"f":[null,[[]],[[]],[[],["appstate",3]],[[]],[[["formatter",3]],["result",6]],[[]],[[["responseelements",3],["string",3]],["string",3]],null,[[]],null,[[],["result",6]],[[["request",3],["appstate",3]]],[[["request",3],["appstate",3]]],[[["request",3],["appstate",3]]],null,[[["request",3],["appstate",3]]],null,null,[[]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],null,[[]],null,null,[[]],[[]],[[]],[[["request",3],["appstate",3]]],null,[[["formatter",3]],["result",6]],[[]],[[["string",3]]],[[]],[[["vec",3],["string",3]],[["hashmap",3],["serviceprovider",3],["string",3]]],null,null,null,null,null,[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]]],"p":[[3,"AppState"],[3,"ServerConfig"]]}\
}');
if (window.initSearch) {window.initSearch(searchIndex)};