#!/usr/bin/env python
""" playing around with using python to sign things """
# from io import StringIO
# import lxml.etree as ET
# https://signxml.readthedocs.io/en/latest/

# from base64 import b64decode

from lxml import etree
from signxml import XMLSigner, XMLVerifier, methods # type: ignore

def main() -> None:
    """ main func """
    # filename = '2021-08-26-saml-response-signed.txt'
    filename = '2021-08-26-saml-response-unsigned.txt'
    # import xml.etree.ElementTree

    # with open(f"c14n_{filename}", mode='w', encoding='utf-8') as out_file:
    #     print(xml.etree.ElementTree.canonicalize(from_file=filename, out=out_file))

    data_to_sign = open(filename, encoding="utf-8").read()
    cert = open("/Users/yaleman/Downloads/kanidm_sp_test/m1-server.pem", encoding="utf-8").read()
    key = open("/Users/yaleman/Downloads/kanidm_sp_test/m1-server-key.pem", encoding="utf-8").read()
    root = etree.fromstring(data_to_sign)
    signed_root = XMLSigner(method=methods.enveloped).sign(root, key=key, cert=cert)
    verified_data = XMLVerifier().verify(signed_root, x509_cert=cert).signed_xml

    print(etree.tostring(signed_root).decode('utf-8'))
    print(f"Verified: {verified_data}")

    # from signxml import XMLVerifier

    # with open("metadata.xml", "rb") as fh:
    #     cert = etree.parse(fh).find("//ds:X509Certificate").text

    # assertion_data = XMLVerifier().verify(b64decode("""), x509_cert=cert).signed_xml

if __name__ == "__main__":
    main()
