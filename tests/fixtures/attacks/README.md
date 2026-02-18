# Attack Fixture Matrix

This folder contains adversarial XML/SAML fixtures used by `tests/security_attack_matrix.rs`.

- The concise case inventory is below.
- The full intent + expected response contract for each case is documented in `ATTACK_EXPECTATIONS.md`.

## Sources

- OWASP SAML Security Cheat Sheet
- OASIS SAML Security Considerations
- Somorovsky et al. (USENIX 2012) XML Signature Wrapping research
- Duo SAML implementation bypass write-up
- CVE-2022-41912 class (multiple assertion / validation confusion)

## Fixture Index

1. `01_xxe_local_file_authn.xml`
2. `02_xxe_remote_ssrf_authn.xml`
3. `03_parameter_entity_expansion_authn.xml`
4. `04_billion_laughs_authn.xml`
5. `05_external_schema_location_authn.xml`
6. `06_xinclude_authn.xml`
7. `07_xml_stylesheet_pi_authn.xml`
8. `08_cdata_authn.xml`
9. `09_too_deep_authn.xml`
10. `10_too_many_attributes_authn.xml`
11. `11_duplicate_id_attribute_authn.xml`
12. `12_duplicate_destination_attribute_authn.xml`
13. `13_duplicate_issuer_authn.xml`
14. `14_empty_issuer_authn.xml`
15. `15_nested_authnrequest_authn.xml`
16. `16_version_downgrade_authn.xml`
17. `17_malformed_unbalanced_authn.xml`
18. `18_general_entity_ref_metadata.xml`
19. `19_external_schema_location_metadata.xml`
20. `20_xxe_metadata_remote.xml`
