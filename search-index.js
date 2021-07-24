var searchIndex = JSON.parse('{\
"saml_rs":{"doc":"A library for doing SAML things, terribly, in rust.","t":[3,12,12,3,3,3,11,11,11,11,11,11,11,11,12,12,5,11,11,11,12,12,12,11,11,11,11,11,11,11,11,11,11,11,11,12,12,12,12,12,12,0,11,11,5,12,12,0,11,0,11,11,11,11,11,11,11,11,11,11,11,11,12,12,3,12,11,11,12,11,11,11,5,12,11,12,11,11,12,11,12,11,11,11,11,11,3,3,3,11,12,12,12,11,11,11,11,11,11,11,12,11,11,5,11,12,12,11,11,11,11,11,11,12,11,11,11,12,12,12,12,11,12,11,11,11,11,11,11,11,11,11,11,11,17,17,17,17],"n":["AuthnDecodeError","RelayState","SAMLRequest","SamlAuthnRequest","SamlAuthnRequestParser","SamlQuery","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","consumer_service_url","consumer_service_url","decode_authn_request_base64_encoded","default","default","deserialize","destination","destination","error","fmt","fmt","fmt","from","from","from","from","from","into","into","into","into","issue_instant","issue_instant","issuer","issuer","issuer_state","message","metadata","new","new","parse_authn_request","request_id","request_id","response","serialize","test_samples","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","version","version","SamlMetadata","baseurl","borrow","borrow_mut","entity_id","fmt","from","from_hostname","generate_metadata_xml","hostname","into","logout_suffix","logout_url","new","post_suffix","post_url","redirect_suffix","redirect_url","serialize","try_from","try_into","type_id","AuthNStatement","ResponseAttribute","ResponseElements","add_to_xmlevent","assertion_id","attributes","authnstatement","basic","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","classref","clone","clone_into","create_response","default","destination","expiry","fmt","fmt","fmt","from","from","from","instant","into","into","into","issue_instant","issuer","request_id","response_id","serialize","session_index","to_owned","to_string","try_from","try_from","try_from","try_into","try_into","try_into","type_id","type_id","type_id","TEST_AUTHN_REQUEST_EXAMPLE_COM","TEST_AUTHN_REQUEST_EXAMPLE_COM_BASE64_DEFLATED","TEST_AUTHN_REQUEST_WITH_EMBEDDED_SIGNATURE_POST","TEST_SAML_UNSIGNED_RESPONSE_UNSIGNED_ASSERTION"],"q":["saml_rs","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::metadata","","","","","","","","","","","","","","","","","","","","","","saml_rs::response","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","saml_rs::test_samples","","",""],"d":["","","","Stores the values one would expect in an AuthN Request","Used to pull apart a SAML AuthN Request and build a […","Used in the SAML Redirect GET request to pull out the …","","","","","","","","","","","","","","","","","","","","","","","Allows one to turn a [SamlAuthnRequestParser] into a …","","","","","","","","","","","","","Handy for the XML metadata part of SAML","","","Give it a string full of XML and it’ll give you back a […","","","Want to build a SAML response? Here’s your module. 🥳","","Random samples of XML I’ve found around the place","","","","","","","","","","","","","","","Stores the required data for generating a SAML metadata …","","","","entityID is transmitted in all requests Every SAML system …","","","","Generates the XML For a metadata file","","","Appended to the baseurl when using the […","","","Appended to the baseurl when using the […","","Appended to the baseurl when using the […","","","","","","An Authentication Statement for returning inside an …","","Stores all the required elements of a SAML response… …","Used elsewhere in the API to add it to the Response XML","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Formats it all pretty-like, in XML","","","","","","","","","","Simple AuthnRequest base64 ID=1234","Simple AuthnRequest ID=1234 base64 encoded and deflate-d","","Example SAML unsigned response with unsigned assertion - …"],"i":[0,1,1,0,0,0,2,3,4,1,2,3,4,1,3,4,0,3,4,1,3,4,4,2,3,4,2,3,3,4,1,2,3,4,1,3,4,3,4,4,2,0,2,4,0,3,4,0,3,0,2,3,4,1,2,3,4,1,2,3,4,1,3,4,0,5,5,5,5,5,5,5,0,5,5,5,5,5,5,5,5,5,5,5,5,5,0,0,0,6,7,7,7,8,7,8,6,7,8,6,6,8,8,0,8,7,6,7,8,6,7,8,6,6,7,8,6,7,7,7,7,8,6,8,6,7,8,6,7,8,6,7,8,6,0,0,0,0],"f":[null,null,null,null,null,null,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],null,null,[[["string",3]],[["result",4],["authndecodeerror",3],["string",3]]],[[],["samlauthnrequest",3]],[[],["samlauthnrequestparser",3]],[[],["result",4]],null,null,null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[["samlauthnrequestparser",3]]],[[]],[[]],[[]],[[]],[[]],[[]],null,null,null,null,null,null,null,[[["string",3]],["authndecodeerror",3]],[[]],[[["str",15]],[["result",4],["samlauthnrequest",3],["str",15]]],null,null,null,[[],["result",4]],null,[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],null,null,null,null,[[]],[[]],null,[[["formatter",3]],["result",6]],[[]],[[["str",15]],["samlmetadata",3]],[[["samlmetadata",3]],["string",3]],null,[[]],null,[[],["string",3]],[[["str",15],["option",4],["string",3]]],null,[[],["string",3]],null,[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],null,null,null,[[["eventwriter",3]]],null,null,null,[[["vec",3],["str",15],["string",3]],["responseattribute",3]],[[]],[[]],[[]],[[]],[[]],[[]],null,[[],["responseattribute",3]],[[]],[[["responseelements",3]],[["u8",15],["vec",3]]],[[],["responseattribute",3]],null,null,[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[]],null,[[]],[[]],[[]],null,null,null,null,[[],["result",4]],null,[[]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],null,null,null,null],"p":[[3,"SamlQuery"],[3,"AuthnDecodeError"],[3,"SamlAuthnRequest"],[3,"SamlAuthnRequestParser"],[3,"SamlMetadata"],[3,"AuthNStatement"],[3,"ResponseElements"],[3,"ResponseAttribute"]]}\
}');
if (window.initSearch) {window.initSearch(searchIndex)};