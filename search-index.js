var searchIndex = JSON.parse('{\
"saml_rs":{"doc":"A library for doing SAML things, terribly, in rust.","t":[3,3,11,11,11,11,12,12,5,11,11,12,12,12,11,11,11,11,11,11,11,12,12,12,12,12,0,11,5,12,12,0,11,0,0,11,11,11,11,11,11,12,12,11,11,3,12,11,11,12,11,11,11,5,12,11,12,11,11,12,11,12,11,11,11,11,11,11,5,17,17,17,17,12,3,12,11,11,11,11,11,5,11,11,11,11],"n":["SamlAuthnRequest","SamlAuthnRequestParser","borrow","borrow","borrow_mut","borrow_mut","consumer_service_url","consumer_service_url","decode_authn_request_base64_encoded","default","default","destination","destination","error","fmt","fmt","from","from","from","into","into","issue_instant","issue_instant","issuer","issuer","issuer_state","metadata","new","parse_authn_request","request_id","request_id","response","serialize","test_samples","tide_helpers","try_from","try_from","try_into","try_into","type_id","type_id","version","version","vzip","vzip","SamlMetadata","baseurl","borrow","borrow_mut","entity_id","fmt","from","from_hostname","generate_metadata_xml","hostname","into","logout_suffix","logout_url","new","post_suffix","post_url","redirect_suffix","redirect_url","serialize","try_from","try_into","type_id","vzip","create_response","TEST_AUTHN_REQUEST_EXAMPLE_COM","TEST_AUTHN_REQUEST_EXAMPLE_COM_BASE64_DEFLATED","TEST_AUTHN_REQUEST_WITH_EMBEDDED_SIGNATURE_POST","TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION","RelayState","SAMLRedirectQuery","SAMLRequest","borrow","borrow_mut","deserialize","from","into","tide_metadata_response","try_from","try_into","type_id","vzip"],"q":["saml_rs","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::metadata","","","","","","","","","","","","","","","","","","","","","","","saml_rs::response","saml_rs::test_samples","","","","saml_rs::tide_helpers","","","","","","","","","","","",""],"d":["Stores the values one would expect in an AuthN Request","Used to pull apart a SAML AuthN Request and build a […","","","","","","","","","","","","","","","","Allows one to turn a [SamlAuthnRequestParser] into a …","","","","","","","","","Handy for the XML metadata part of SAML","","Give it a string full of XML and it’ll give you back a […","","","","","","Helpers for working with tide-based HTTP(S) services","","","","","","","","","","","Stores the required data for generating a SAML metadata …","","","","entityID is transmitted in all requests Every SAML system …","","","","Generates the XML For a metadata file","","","Appended to the baseurl when using the […","","","Appended to the baseurl when using the […","","Appended to the baseurl when using the […","","","","","","","","Random samples of XML I’ve found around the place …","Simple AuthnRequest ID=1234 base64 encoded and deflate-d","","Example SAML unsigned response with unsigned assertion - …","","","Used in the SAML Redirect GET request to pull out the …","","","","","","Responds with the metadata XML file in a 200-status …","","","",""],"i":[0,0,1,2,1,2,1,2,0,1,2,1,2,2,1,2,1,1,2,1,2,1,2,1,2,2,0,2,0,1,2,0,1,0,0,1,2,1,2,1,2,1,2,1,2,0,3,3,3,3,3,3,3,0,3,3,3,3,3,3,3,3,3,3,3,3,3,3,0,0,0,0,0,4,0,4,4,4,4,4,4,0,4,4,4,4],"f":[null,null,[[]],[[]],[[]],[[]],null,null,[[["string",3]],[["str",15],["result",4],["string",3]]],[[],["samlauthnrequest",3]],[[],["samlauthnrequestparser",3]],null,null,null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[["samlauthnrequestparser",3]]],[[]],[[]],[[]],null,null,null,null,null,null,[[]],[[["str",15]],[["result",4],["samlauthnrequest",3],["str",15]]],null,null,null,[[],["result",4]],null,null,[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],null,null,[[]],[[]],null,null,[[]],[[]],null,[[["formatter",3]],["result",6]],[[]],[[["str",15]],["samlmetadata",3]],[[["samlmetadata",3]],["string",3]],null,[[]],null,[[],["string",3]],[[["str",15],["option",4],["string",3]]],null,[[],["string",3]],null,[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],[[["string",3]],[["u8",15],["vec",3]]],null,null,null,null,null,null,null,[[]],[[]],[[],["result",4]],[[]],[[]],[[["samlmetadata",3]],["response",3]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]]],"p":[[3,"SamlAuthnRequest"],[3,"SamlAuthnRequestParser"],[3,"SamlMetadata"],[3,"SAMLRedirectQuery"]]},\
"samlrs":{"doc":"","t":[5],"n":["main"],"q":["samlrs"],"d":[""],"i":[0],"f":[[[]]],"p":[]}\
}');
if (window.initSearch) {window.initSearch(searchIndex)};