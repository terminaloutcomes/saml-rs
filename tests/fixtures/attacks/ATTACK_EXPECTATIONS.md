# Attack Expectations

This document defines the attack intent and expected behavior contract for every fixture in this folder.

## Mode Definitions

- `safe mode`: default build without `danger_i_want_to_risk_it_all`.
- `danger-locked mode`: built with `danger_i_want_to_risk_it_all` but without runtime `danger::unlock()`.
- `danger-unlocked mode`: built with `danger_i_want_to_risk_it_all` and runtime unlock + explicit toggles.

For this attack corpus, all XML-structure attacks are expected to be rejected in every mode. The danger feature only relaxes explicitly selected compatibility controls (for example weak algorithm acceptance), not XML parser hardening.

## Case Matrix

| ID | Fixture | Attack Class | Attack Intent | Attacker Goal | Expected Safe Response | Expected Danger-Locked Response | Expected Danger-Unlocked Response | Expected Rejection Surface |
|---|---|---|---|---|---|---|---|---|
| A01 | `01_xxe_local_file_authn.xml` | XXE local entity | Define SYSTEM entity for local path | Read local files from parser host | Reject preflight | Reject preflight | Reject preflight | DOCTYPE/DTD forbidden |
| A02 | `02_xxe_remote_ssrf_authn.xml` | XXE remote entity | Define SYSTEM entity for remote URL | Trigger SSRF and remote fetch | Reject preflight | Reject preflight | Reject preflight | DOCTYPE/DTD forbidden |
| A03 | `03_parameter_entity_expansion_authn.xml` | Parameter entity abuse | Use `%entity` chain to smuggle external declarations | Bypass naive XXE filters | Reject preflight | Reject preflight | Reject preflight | DOCTYPE/DTD forbidden |
| A04 | `04_billion_laughs_authn.xml` | Entity expansion DoS | Recursive/expanding entities | CPU/memory exhaustion | Reject preflight | Reject preflight | Reject preflight | DOCTYPE/DTD forbidden |
| A05 | `05_external_schema_location_authn.xml` | External schema resolution | Set remote `xsi:schemaLocation` | SSRF/schema poisoning/parser differential | Reject preflight | Reject preflight | Reject preflight | External schema reference forbidden |
| A06 | `06_xinclude_authn.xml` | XInclude | Add `xi:include` with remote `href` | Include attacker XML into trusted parse tree | Reject preflight | Reject preflight | Reject preflight | XInclude forbidden |
| A07 | `07_xml_stylesheet_pi_authn.xml` | XML PI external fetch | Add `xml-stylesheet` PI with remote URL | Trigger unsafe URL fetch path | Reject preflight | Reject preflight | Reject preflight | Processing instruction forbidden |
| A08 | `08_cdata_authn.xml` | CDATA ambiguity | Inject CDATA near protocol fields | Exploit parser differentials around text handling | Reject preflight | Reject preflight | Reject preflight | CDATA forbidden |
| A09 | `09_too_deep_authn.xml` | Depth/resource stress | Deep element nesting | Stack/resource exhaustion | Reject preflight | Reject preflight | Reject preflight | Depth limit exceeded |
| A10 | `10_too_many_attributes_authn.xml` | Attribute flood | Oversized attribute set | Resource stress / override ambiguity | Reject preflight | Reject preflight | Reject preflight | Attribute-per-element limit exceeded |
| A11 | `11_duplicate_id_attribute_authn.xml` | Duplicate ID confusion | Two `ID` attributes | Reference/signature confusion | Reject semantic parse | Reject semantic parse | Reject semantic parse | Duplicate root attribute rejection |
| A12 | `12_duplicate_destination_attribute_authn.xml` | Duplicate destination | Two `Destination` attributes | First-win/last-win divergence | Reject semantic parse | Reject semantic parse | Reject semantic parse | Duplicate root attribute rejection |
| A13 | `13_duplicate_issuer_authn.xml` | Issuer confusion | Two Issuer elements with different values | Bypass issuer trust mapping | Reject semantic parse | Reject semantic parse | Reject semantic parse | Duplicate issuer rejection |
| A14 | `14_empty_issuer_authn.xml` | Empty issuer bypass | Issuer element with empty value | Slip through issuer-presence-only checks | Reject semantic parse | Reject semantic parse | Reject semantic parse | Empty issuer rejection |
| A15 | `15_nested_authnrequest_authn.xml` | Wrapping/nested root confusion | AuthnRequest nested inside AuthnRequest | Alternate parser view / signature bypass class | Reject semantic parse | Reject semantic parse | Reject semantic parse | Nested/duplicate root rejection |
| A16 | `16_version_downgrade_authn.xml` | Protocol downgrade | Set `Version="1.1"` | Force unsupported protocol handling | Reject semantic parse | Reject semantic parse | Reject semantic parse | Version != 2.0 rejected |
| A17 | `17_malformed_unbalanced_authn.xml` | Malformed XML | Unbalanced tags around critical fields | Differential parser recovery | Reject parse | Reject parse | Reject parse | Malformed XML/token error |
| A18 | `18_general_entity_ref_metadata.xml` | General entity reference | Inject unknown entity in metadata text | Entity confusion / expansion behavior abuse | Reject parse/preflight | Reject parse/preflight | Reject parse/preflight | Entity/reference forbidden |
| A19 | `19_external_schema_location_metadata.xml` | External schema in metadata | Remote `schemaLocation` in SP metadata | SSRF and schema poisoning | Reject preflight | Reject preflight | Reject preflight | External schema reference forbidden |
| A20 | `20_xxe_metadata_remote.xml` | XXE in metadata | DTD with remote SYSTEM entity | Metadata-time SSRF/exfiltration | Reject preflight | Reject preflight | Reject preflight | DOCTYPE/DTD forbidden |

## Additional Policy Expectations (Non-fixture)

The matrix test also asserts these non-XML policy controls:

- Safe mode blocks SHA-1 signing and SHA-1 verification.
- Danger mode does not relax anything until explicit runtime unlock is called.
- After explicit runtime unlock, weak algorithm compatibility may be enabled, but all structural XML attack fixtures above still must fail.
