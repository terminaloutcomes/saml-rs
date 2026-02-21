#!/usr/bin/env python3
"""Run a full headless Keycloak->saml-rs->Keycloak SAML broker round-trip."""

from __future__ import annotations

import base64
import binascii
import http.client
import http.cookiejar
import os
import ssl
import sys
import zlib
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from typing import Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from urllib.request import (
    HTTPCookieProcessor,
    HTTPSHandler,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from lxml import etree as LET

REDIRECT_CODES = {301, 302, 303, 307, 308}
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEBUG_HTML_PATH = os.getenv(
    "LIVE_E2E_DEBUG_HTML", ".tmp/live-e2e/last-keycloak-page.html"
)
EXPECT_RESULT = os.getenv("LIVE_E2E_EXPECT_RESULT", "success").strip().lower()
EXPECTED_ERROR_CLASS = os.getenv("LIVE_E2E_EXPECTED_ERROR_CLASS", "").strip()
EXPECT_ASSERTION_SIGNATURE = os.getenv(
    "LIVE_E2E_EXPECT_ASSERTION_SIGNATURE", "ignore"
).lower()
EXPECT_RESPONSE_SIGNATURE = os.getenv(
    "LIVE_E2E_EXPECT_RESPONSE_SIGNATURE", "ignore"
).lower()
EXPECT_C14N_METHOD = os.getenv("LIVE_E2E_EXPECT_C14N_METHOD", "ignore").lower()
TAMPER_MODE = os.getenv("LIVE_E2E_TAMPER_MODE", "none").strip().lower()
CLOCK_SKEW_SECONDS = int(os.getenv("LIVE_E2E_ALLOWED_CLOCK_SKEW_SECONDS", "120"))
EXPECTED_AUDIENCE = os.getenv("LIVE_E2E_EXPECT_AUDIENCE", "")
SCHEMA_DIR = os.getenv("LIVE_E2E_SCHEMA_DIR", "examples/schemas")
SCHEMA_DIR = os.path.abspath(
    SCHEMA_DIR if os.path.isabs(SCHEMA_DIR) else os.path.join(ROOT_DIR, SCHEMA_DIR)
)


class FlowError(RuntimeError):
    """Raised for controlled protocol-flow failures."""

    def __init__(
        self, message: str = "", error_class: str = "response_validation_error"
    ) -> None:
        super().__init__(message)
        self.error_class = error_class


class LocalInsecureCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Allow secure cookies on localhost HTTP during local-only test runs."""

    def return_ok_secure(self, cookie, request):
        return True


class NoRedirectHandler(HTTPRedirectHandler):
    """Keep redirect responses visible to the caller."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SamlFormParser(HTMLParser):
    """Extract the first POST form with hidden fields from the IdP page."""

    def __init__(self) -> None:
        super().__init__()
        self.form_action: Optional[str] = None
        self.in_target_form = False
        self.inputs: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_dict = dict(attrs)
        if tag.lower() == "form":
            method = attrs_dict.get("method", "get").lower()
            if method == "post" and self.form_action is None:
                self.form_action = attrs_dict.get("action")
                self.in_target_form = True
        if tag.lower() == "input" and self.in_target_form:
            name = attrs_dict.get("name")
            if name:
                self.inputs[name] = attrs_dict.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.in_target_form:
            self.in_target_form = False


def _expect_bool(expected: str, observed: bool, label: str) -> None:
    if expected == "ignore":
        return
    wanted = expected in {"1", "true", "yes"}
    if wanted != observed:
        raise FlowError(
            f"{label} expectation mismatch: expected={wanted}, observed={observed}",
            "signature_expectation_mismatch",
        )


def _parse_saml_datetime(value: str, label: str) -> datetime:
    raw_value = value.strip()
    if raw_value.endswith("Z"):
        raw_value = f"{raw_value[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(raw_value)
    except ValueError as error:
        raise FlowError(f"Invalid {label} datetime value {value!r}: {error}")
    if parsed.tzinfo is None:
        raise FlowError(f"Invalid {label} datetime value {value!r}: missing timezone")
    return parsed.astimezone(timezone.utc)


def _is_saml_id(value: str | None) -> bool:
    if not value:
        return False
    if ":" in value:
        return False
    first = value[0]
    if not (first.isalpha() or first == "_"):
        return False
    return all(char.isalnum() or char in {"_", "-", "."} for char in value[1:])


def _flip_string(value: str) -> str:
    if not value:
        return value
    first = value[0]
    replacement = "A" if first != "A" else "B"
    return f"{replacement}{value[1:]}"


class LocalSchemaResolver(LET.Resolver):
    """Resolve schema imports from the vendored local schema directory."""

    def __init__(self, schema_dir: str) -> None:
        self.schema_dir = schema_dir
        self.absolute_map = {
            "http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd": "xmldsig-core-schema.xsd",
            "http://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd": "xenc-schema.xsd",
        }

    def resolve(
        self,
        system_url: str,
        public_id: str,
        context: object | None = None,
    ):
        """Resolve an imported schema URL to a local vendored schema file.

        The resolver first checks ``absolute_map`` for known absolute URLs, then
        falls back to ``os.path.basename(url)``. If the mapped file exists under
        ``self.schema_dir``, it returns an lxml filename resolution object.
        Returning ``None`` allows normal parser resolution behavior.
        """
        _ = public_id
        mapped = self.absolute_map.get(system_url, os.path.basename(system_url))
        candidate = os.path.join(self.schema_dir, mapped)
        if os.path.exists(candidate):
            try:
                with open(candidate, "rb") as schema_file:
                    schema_bytes = schema_file.read()
            except OSError:
                return None
            return self.resolve_string(schema_bytes, context, base_url=candidate)
        return None


def _validate_response_schema(decoded_xml: str) -> None:
    parser = LET.XMLParser(no_network=True)
    parser.resolvers.add(LocalSchemaResolver(SCHEMA_DIR))
    schema_path = os.path.join(SCHEMA_DIR, "saml-schema-protocol-2.0.xsd")

    try:
        schema_doc = LET.parse(schema_path, parser)
    except OSError as error:
        raise FlowError(
            f"Failed loading schema file {schema_path}: {error}",
            "schema_validation_error",
        )
    except LET.XMLSyntaxError as error:
        raise FlowError(
            f"Schema XML syntax error in {schema_path}: {error}",
            "schema_validation_error",
        )

    try:
        schema = LET.XMLSchema(schema_doc)
    except LET.XMLSchemaParseError as error:
        raise FlowError(
            f"Failed to parse protocol schema {schema_path}: {error}",
            "schema_validation_error",
        )

    try:
        document = LET.fromstring(
            decoded_xml.encode("utf-8"), parser=LET.XMLParser(no_network=True)
        )
    except LET.XMLSyntaxError as error:
        raise FlowError(
            f"SAMLResponse schema parse failed: {error}", "schema_validation_error"
        )

    if not schema.validate(document):
        error = schema.error_log.last_error
        raise FlowError(
            f"SAMLResponse failed XSD validation: {error}", "schema_validation_error"
        )


def _decode_authn_request_xml(encoded_request: str) -> str:
    try:
        decoded = base64.b64decode(encoded_request)
    except (binascii.Error, ValueError) as error:
        raise FlowError(
            f"SAMLRequest is not valid base64: {error}", "request_decode_error"
        )

    try:
        inflated = zlib.decompress(decoded, -15)
    except zlib.error:
        inflated = decoded

    try:
        return inflated.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FlowError(
            f"SAMLRequest was not utf-8 XML: {error}", "request_decode_error"
        )


def _extract_authn_request_context(idp_url: str) -> tuple[str, str, str, str]:
    query = parse_qs(urlparse(idp_url).query)
    encoded_request = query.get("SAMLRequest", [None])[0]
    if not encoded_request:
        raise FlowError(
            "IdP redirect URL did not contain SAMLRequest", "request_validation_error"
        )
    relay_state = query.get("RelayState", [""])[0]

    request_xml = _decode_authn_request_xml(encoded_request)
    try:
        request_root = ET.fromstring(request_xml)
    except ET.ParseError as error:
        raise FlowError(
            f"Decoded SAMLRequest was not valid XML: {error}",
            "request_validation_error",
        )

    request_id = request_root.attrib.get("ID")
    if not request_id:
        raise FlowError("AuthnRequest was missing ID", "request_validation_error")
    if not _is_saml_id(request_id):
        raise FlowError(
            f"AuthnRequest ID is not SAML-safe: {request_id}",
            "request_validation_error",
        )
    acs_url = request_root.attrib.get("AssertionConsumerServiceURL")
    if not acs_url:
        raise FlowError(
            "AuthnRequest was missing AssertionConsumerServiceURL",
            "request_validation_error",
        )

    issuer_node = request_root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer_text = (
        issuer_node.text.strip() if issuer_node is not None and issuer_node.text else ""
    )
    if not issuer_text:
        raise FlowError("AuthnRequest was missing Issuer", "request_validation_error")

    return request_id, relay_state, acs_url, issuer_text


def _tamper_authnrequest_signature(idp_url: str) -> str:
    parsed = urlparse(idp_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    signatures = query.get("Signature")
    if not signatures:
        raise FlowError(
            "Tamper mode requested authnrequest signature corruption but Signature is absent",
            "tamper_precondition_failed",
        )
    query["Signature"] = [_flip_string(signatures[0])]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def inspect_saml_response(
    saml_response: str,
    expected_request_id: str,
    expected_relay_state: str,
    expected_acs_url: str,
    expected_audience: str,
    observed_relay_state: str,
) -> None:
    try:
        decoded_xml = base64.b64decode(saml_response).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as error:
        raise FlowError(
            f"SAMLResponse is not valid base64: {error}", "response_validation_error"
        )
    _validate_response_schema(decoded_xml)
    ns = {
        "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
        "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    }
    try:
        root = ET.fromstring(decoded_xml)
    except ET.ParseError as error:
        raise FlowError(
            f"SAMLResponse was not valid XML: {error}", "response_validation_error"
        )
    response_sig = root.find("./ds:Signature", ns) is not None
    assertion_sig = root.find("./saml:Assertion/ds:Signature", ns) is not None
    _expect_bool(EXPECT_RESPONSE_SIGNATURE, response_sig, "response signature")
    _expect_bool(EXPECT_ASSERTION_SIGNATURE, assertion_sig, "assertion signature")

    if observed_relay_state != expected_relay_state:
        raise FlowError(
            "RelayState mismatch between redirect request and IdP form: "
            f"expected={expected_relay_state!r}, observed={observed_relay_state!r}",
            "response_validation_error",
        )

    response_version = root.attrib.get("Version")
    if response_version != "2.0":
        raise FlowError(f"SAML Response Version must be 2.0, got {response_version!r}")
    response_id = root.attrib.get("ID")
    if not _is_saml_id(response_id):
        raise FlowError(f"SAML Response ID is not SAML-safe: {response_id!r}")
    response_in_response_to = root.attrib.get("InResponseTo")
    if response_in_response_to != expected_request_id:
        raise FlowError(
            "Response InResponseTo does not match AuthnRequest ID: "
            f"expected={expected_request_id!r}, got={response_in_response_to!r}",
        )
    destination = root.attrib.get("Destination")
    if not destination:
        raise FlowError("SAML Response missing Destination")
    if destination != expected_acs_url:
        raise FlowError(
            "Response Destination does not match AuthnRequest AssertionConsumerServiceURL: "
            f"expected={expected_acs_url!r}, got={destination!r}",
        )

    assertion = root.find("./saml:Assertion", ns)
    if assertion is None:
        raise FlowError("SAML Response missing Assertion element")
    assertion_id = assertion.attrib.get("ID")
    if not _is_saml_id(assertion_id):
        raise FlowError(f"Assertion ID is not SAML-safe: {assertion_id!r}")
    if assertion.attrib.get("Version") != "2.0":
        raise FlowError(
            f"Assertion Version must be 2.0, got {assertion.attrib.get('Version')!r}"
        )

    issue_instant = root.attrib.get("IssueInstant")
    assertion_issue_instant = assertion.attrib.get("IssueInstant")
    if not issue_instant:
        raise FlowError("SAML Response missing IssueInstant")
    if not assertion_issue_instant:
        raise FlowError("Assertion missing IssueInstant")
    _parse_saml_datetime(issue_instant, "Response IssueInstant")
    _parse_saml_datetime(assertion_issue_instant, "Assertion IssueInstant")

    subject_confirmation_data = assertion.find(
        "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", ns
    )
    if subject_confirmation_data is None:
        raise FlowError("Assertion missing SubjectConfirmationData")
    subject_in_response_to = subject_confirmation_data.attrib.get("InResponseTo")
    if subject_in_response_to != expected_request_id:
        raise FlowError(
            "SubjectConfirmationData InResponseTo does not match AuthnRequest ID: "
            f"expected={expected_request_id!r}, got={subject_in_response_to!r}",
        )
    recipient = subject_confirmation_data.attrib.get("Recipient")
    if not recipient:
        raise FlowError("SubjectConfirmationData missing Recipient")
    if recipient != destination:
        raise FlowError(
            "SubjectConfirmationData Recipient and Response Destination must match: "
            f"recipient={recipient!r}, destination={destination!r}",
        )
    if recipient != expected_acs_url:
        raise FlowError(
            "SubjectConfirmationData Recipient does not match AuthnRequest AssertionConsumerServiceURL: "
            f"expected={expected_acs_url!r}, got={recipient!r}",
        )

    conditions = assertion.find("./saml:Conditions", ns)
    if conditions is None:
        raise FlowError("Assertion missing Conditions")
    not_before_raw = conditions.attrib.get("NotBefore")
    not_on_or_after_raw = conditions.attrib.get("NotOnOrAfter")
    if not not_before_raw or not not_on_or_after_raw:
        raise FlowError("Assertion Conditions must include NotBefore and NotOnOrAfter")
    not_before = _parse_saml_datetime(not_before_raw, "Conditions NotBefore")
    not_on_or_after = _parse_saml_datetime(
        not_on_or_after_raw, "Conditions NotOnOrAfter"
    )

    subject_not_on_or_after_raw = subject_confirmation_data.attrib.get("NotOnOrAfter")
    if not subject_not_on_or_after_raw:
        raise FlowError("SubjectConfirmationData missing NotOnOrAfter")
    subject_not_on_or_after = _parse_saml_datetime(
        subject_not_on_or_after_raw,
        "SubjectConfirmationData NotOnOrAfter",
    )

    if not_before > not_on_or_after:
        raise FlowError(
            "Conditions NotBefore must be <= NotOnOrAfter: "
            f"NotBefore={not_before.isoformat()}, NotOnOrAfter={not_on_or_after.isoformat()}"
        )

    now = datetime.now(timezone.utc)
    skew = timedelta(seconds=CLOCK_SKEW_SECONDS)
    if now + skew < not_before:
        raise FlowError(
            f"Assertion is not yet valid: now={now.isoformat()} "
            f"NotBefore={not_before.isoformat()} skew={CLOCK_SKEW_SECONDS}s"
        )
    if now - skew >= not_on_or_after:
        raise FlowError(
            f"Assertion Conditions expired: now={now.isoformat()} "
            f"NotOnOrAfter={not_on_or_after.isoformat()} skew={CLOCK_SKEW_SECONDS}s"
        )
    if now - skew >= subject_not_on_or_after:
        raise FlowError(
            f"SubjectConfirmationData expired: now={now.isoformat()} "
            f"NotOnOrAfter={subject_not_on_or_after.isoformat()} skew={CLOCK_SKEW_SECONDS}s"
        )

    audiences = [
        node.text
        for node in assertion.findall(
            "./saml:Conditions/saml:AudienceRestriction/saml:Audience",
            ns,
        )
        if node.text
    ]
    if expected_audience not in audiences:
        raise FlowError(
            f"Expected audience {expected_audience!r} not present in assertion audiences {audiences!r}"
        )

    if EXPECT_C14N_METHOD != "ignore":
        expected_uri = {
            "exclusive": "http://www.w3.org/2001/10/xml-exc-c14n#",
            "inclusive": "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        }.get(EXPECT_C14N_METHOD)
        if not expected_uri:
            raise FlowError(
                f"Unknown LIVE_E2E_EXPECT_C14N_METHOD={EXPECT_C14N_METHOD}",
                "configuration_error",
            )
        c14n_nodes = root.findall(".//ds:CanonicalizationMethod", ns)
        if not c14n_nodes:
            raise FlowError(
                "Expected SignedInfo CanonicalizationMethod nodes but found none"
            )
        bad_nodes = [
            node.attrib.get("Algorithm")
            for node in c14n_nodes
            if node.attrib.get("Algorithm") != expected_uri
        ]
        if bad_nodes:
            raise FlowError(
                f"Unexpected c14n algorithms found: {bad_nodes}, expected only {expected_uri}"
            )


def request_no_redirect(
    opener,
    url: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    req = Request(url=url, data=body, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)

    try:
        with opener.open(req) as response:
            status = response.getcode()
            response_headers = dict(response.headers.items())
            return status, response_headers, response.read()
    except HTTPError as err:
        status = err.code
        response_headers = dict(err.headers.items())
        return status, response_headers, err.read()
    except (
        URLError,
        TimeoutError,
        ssl.SSLError,
        OSError,
        http.client.HTTPException,
    ) as error:
        raise FlowError(
            f"HTTP request failed for {url}: {error}", "http_request_failed"
        )


def first_location(current_url: str, status: int, headers: Dict[str, str]) -> str:
    if status not in REDIRECT_CODES:
        raise FlowError(
            f"Expected redirect from {current_url}, got status={status}",
            "redirect_protocol_error",
        )
    location = headers.get("Location")
    if not location:
        raise FlowError(
            f"Redirect from {current_url} did not include Location header",
            "redirect_protocol_error",
        )
    return urljoin(current_url, location)


def main() -> None:
    if EXPECT_RESULT not in {"success", "error"}:
        raise FlowError(
            f"LIVE_E2E_EXPECT_RESULT must be success|error, got {EXPECT_RESULT!r}",
            "configuration_error",
        )

    keycloak_base = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:18080")
    realm = os.getenv("KEYCLOAK_REALM", "saml-e2e")
    client_id = os.getenv("KEYCLOAK_CLIENT_ID", "e2e-client")
    redirect_uri = os.getenv("E2E_REDIRECT_URI", "http://localhost:18082/callback")
    idp_redirect_prefix = os.getenv(
        "IDP_REDIRECT_PREFIX", "http://localhost:18081/SAML/Redirect"
    )

    cookie_jar = http.cookiejar.CookieJar(policy=LocalInsecureCookiePolicy())
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    opener = build_opener(
        HTTPCookieProcessor(cookie_jar),
        HTTPSHandler(context=ssl_context),
        NoRedirectHandler(),
    )

    auth_query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid",
            "kc_idp_hint": "saml-rs",
        }
    )
    current_url = (
        f"{keycloak_base}/realms/{realm}/protocol/openid-connect/auth?{auth_query}"
    )

    print(f"Starting OIDC auth flow at: {current_url}")

    idp_url: Optional[str] = None
    for _ in range(10):
        status, headers, _ = request_no_redirect(opener, current_url)
        next_url = first_location(current_url, status, headers)
        print(f"Redirect -> {next_url}")
        if next_url.startswith(idp_redirect_prefix):
            idp_url = next_url
            break
        current_url = next_url

    if idp_url is None:
        raise FlowError(
            "Never reached IdP Redirect endpoint", "idp_redirect_not_reached"
        )

    if TAMPER_MODE == "authnrequest_signature_corrupt":
        idp_url = _tamper_authnrequest_signature(idp_url)

    (
        expected_request_id,
        expected_relay_state,
        expected_acs_url,
        expected_request_issuer,
    ) = _extract_authn_request_context(idp_url)

    status, _, body = request_no_redirect(opener, idp_url)
    if status not in {200, 203}:
        raise FlowError(
            f"IdP redirect endpoint returned unexpected status={status}",
            "idp_redirect_rejected",
        )

    html = body.decode("utf-8", errors="replace")
    parser = SamlFormParser()
    parser.feed(html)

    if not parser.form_action:
        raise FlowError(
            "IdP response page did not include a POST form action", "idp_form_missing"
        )

    saml_response = parser.inputs.get("SAMLResponse")
    relay_state = parser.inputs.get("RelayState", "")
    if not saml_response:
        raise FlowError(
            "IdP response page did not include a SAMLResponse input",
            "idp_form_missing",
        )

    expected_audience = EXPECTED_AUDIENCE or expected_request_issuer
    inspect_saml_response(
        saml_response,
        expected_request_id=expected_request_id,
        expected_relay_state=expected_relay_state,
        expected_acs_url=expected_acs_url,
        expected_audience=expected_audience,
        observed_relay_state=relay_state,
    )
    if TAMPER_MODE == "response_corrupt":
        saml_response = _flip_string(saml_response)

    form_action = urljoin(idp_url, parser.form_action)
    post_body = urlencode(
        {
            "SAMLResponse": saml_response,
            "RelayState": relay_state,
        }
    ).encode("utf-8")

    status, headers, body = request_no_redirect(
        opener,
        form_action,
        method="POST",
        body=post_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    if status not in REDIRECT_CODES:
        snippet = body.decode("utf-8", errors="replace")[:400]
        raise FlowError(
            f"Broker endpoint did not redirect after SAML POST (status={status})\n{snippet}",
            "broker_post_rejected",
        )

    current_url = first_location(form_action, status, headers)

    for _ in range(10):
        parsed = urlparse(current_url)
        qs = parse_qs(parsed.query)
        callback_origin = (
            urlparse(redirect_uri).scheme + "://" + urlparse(redirect_uri).netloc
        )
        current_origin = parsed.scheme + "://" + parsed.netloc
        if current_origin == callback_origin:
            if "code" in qs:
                print(
                    "Success: Keycloak accepted the SAML response and issued an OIDC auth code."
                )
                print(f"Callback URL: {current_url}")
                return
            raise FlowError(
                f"Reached callback without auth code: {current_url}",
                "callback_missing_code",
            )

        status, headers, body = request_no_redirect(opener, current_url)
        if status in REDIRECT_CODES:
            current_url = first_location(current_url, status, headers)
            continue

        if status == 200 and "login-actions/first-broker-login" in current_url:
            rendered = body.decode("utf-8", errors="replace")
            parser = SamlFormParser()
            parser.feed(rendered)
            if not parser.form_action:
                raise FlowError(
                    "First-broker-login page did not include a submit form action",
                    "broker_flow_unexpected_status",
                )

            profile_payload = dict(parser.inputs)
            profile_payload["username"] = (
                profile_payload.get("username") or "saml-e2e-user"
            )
            profile_payload["email"] = (
                profile_payload.get("email") or "saml-e2e@example.com"
            )
            profile_payload["firstName"] = profile_payload.get("firstName") or "SAML"
            profile_payload["lastName"] = profile_payload.get("lastName") or "E2E"

            form_action = urljoin(current_url, parser.form_action)
            encoded = urlencode(profile_payload).encode("utf-8")
            status, headers, body = request_no_redirect(
                opener,
                form_action,
                method="POST",
                body=encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if status in REDIRECT_CODES:
                current_url = first_location(form_action, status, headers)
                continue

            snippet = body.decode("utf-8", errors="replace")[:400]
            raise FlowError(
                "First-broker-login form submission did not redirect "
                f"(status={status}, url={form_action})\n{snippet}",
                "broker_flow_unexpected_status",
            )

        rendered = body.decode("utf-8", errors="replace")
        try:
            os.makedirs(os.path.dirname(DEBUG_HTML_PATH), exist_ok=True)
            with open(DEBUG_HTML_PATH, "w", encoding="utf-8") as debug_file:
                debug_file.write(rendered)
        except OSError as error:
            raise FlowError(
                f"Failed writing debug HTML to {DEBUG_HTML_PATH}: {error}",
                "io_error",
            )
        snippet = rendered[:400]
        raise FlowError(
            "Unexpected non-redirect while following broker flow "
            f"(status={status}, url={current_url}, dumped_html={DEBUG_HTML_PATH})\n{snippet}",
            "broker_flow_unexpected_status",
        )

    raise FlowError(
        "Exceeded redirect limit while waiting for final callback",
        "redirect_limit_exceeded",
    )


def _handle_failure(error_class: str, message: str) -> int:
    if EXPECT_RESULT == "success":
        print(f"ERROR [{error_class}]: {message}", file=sys.stderr)
        return 1

    if EXPECTED_ERROR_CLASS and error_class != EXPECTED_ERROR_CLASS:
        print(
            "ERROR: expected error class "
            f"{EXPECTED_ERROR_CLASS!r} but observed {error_class!r}: {message}",
            file=sys.stderr,
        )
        return 1

    print(f"Expected failure observed [{error_class}]: {message}")
    return 0


if __name__ == "__main__":
    try:
        main()
    except FlowError as error:
        raise SystemExit(_handle_failure(error.error_class, str(error))) from error
    except (
        URLError,
        TimeoutError,
        ssl.SSLError,
        OSError,
        http.client.HTTPException,
        ValueError,
        ET.ParseError,
        binascii.Error,
    ) as error:
        raise SystemExit(_handle_failure("unexpected_exception", str(error))) from error
    except KeyboardInterrupt as error:
        print("ERROR: interrupted", file=sys.stderr)
        raise SystemExit(130) from error

    if EXPECT_RESULT == "error":
        print(
            "ERROR: flow unexpectedly succeeded but failure was expected",
            file=sys.stderr,
        )
        raise SystemExit(1)
