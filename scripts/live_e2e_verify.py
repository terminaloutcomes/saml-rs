#!/usr/bin/env python3
"""Run a full headless Keycloak->saml-rs->Keycloak SAML broker round-trip."""

from __future__ import annotations

import http.cookiejar
import os
import ssl
import sys
from html.parser import HTMLParser
from typing import Dict, Optional, Tuple
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
from urllib.request import (
    HTTPCookieProcessor,
    HTTPSHandler,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

REDIRECT_CODES = {301, 302, 303, 307, 308}
DEBUG_HTML_PATH = os.getenv("LIVE_E2E_DEBUG_HTML", ".tmp/live-e2e/last-keycloak-page.html")


class LocalInsecureCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Allow secure cookies on localhost HTTP during local-only test runs."""

    def return_ok_secure(self, cookie, request):  # type: ignore[override]
        return True


class NoRedirectHandler(HTTPRedirectHandler):
    """Keep redirect responses visible to the caller."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class SamlFormParser(HTMLParser):
    """Extract the first POST form with hidden fields from the IdP page."""

    def __init__(self) -> None:
        super().__init__()
        self.form_action: Optional[str] = None
        self.in_target_form = False
        self.inputs: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[override]
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

    def handle_endtag(self, tag: str) -> None:  # type: ignore[override]
        if tag.lower() == "form" and self.in_target_form:
            self.in_target_form = False


def fail(message: str) -> "None":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def request_no_redirect(opener, url: str, method: str = "GET", body: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], bytes]:
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


def first_location(current_url: str, status: int, headers: Dict[str, str]) -> str:
    if status not in REDIRECT_CODES:
        fail(f"Expected redirect from {current_url}, got status={status}")
    location = headers.get("Location")
    if not location:
        fail(f"Redirect from {current_url} did not include Location header")
    return urljoin(current_url, location)


def main() -> None:
    keycloak_base = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:18080")
    realm = os.getenv("KEYCLOAK_REALM", "saml-e2e")
    client_id = os.getenv("KEYCLOAK_CLIENT_ID", "e2e-client")
    redirect_uri = os.getenv("E2E_REDIRECT_URI", "http://localhost:18082/callback")
    idp_redirect_prefix = os.getenv("IDP_REDIRECT_PREFIX", "http://localhost:18081/SAML/Redirect")

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
    current_url = f"{keycloak_base}/realms/{realm}/protocol/openid-connect/auth?{auth_query}"

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
        fail("Never reached IdP Redirect endpoint")

    status, _, body = request_no_redirect(opener, idp_url)
    if status not in {200, 203}:
        fail(f"IdP redirect endpoint returned unexpected status={status}")

    html = body.decode("utf-8", errors="replace")
    parser = SamlFormParser()
    parser.feed(html)

    if not parser.form_action:
        fail("IdP response page did not include a POST form action")

    saml_response = parser.inputs.get("SAMLResponse")
    relay_state = parser.inputs.get("RelayState", "")
    if not saml_response:
        fail("IdP response page did not include a SAMLResponse input")

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
        fail(f"Broker endpoint did not redirect after SAML POST (status={status})\n{snippet}")

    current_url = first_location(form_action, status, headers)

    for _ in range(10):
        parsed = urlparse(current_url)
        qs = parse_qs(parsed.query)
        if parsed.scheme + "://" + parsed.netloc == urlparse(redirect_uri).scheme + "://" + urlparse(redirect_uri).netloc:
            if "code" in qs:
                print("Success: Keycloak accepted the SAML response and issued an OIDC auth code.")
                print(f"Callback URL: {current_url}")
                return
            fail(f"Reached callback without auth code: {current_url}")

        status, headers, body = request_no_redirect(opener, current_url)
        if status in REDIRECT_CODES:
            current_url = first_location(current_url, status, headers)
            continue

        if status == 200 and "login-actions/first-broker-login" in current_url:
            rendered = body.decode("utf-8", errors="replace")
            parser = SamlFormParser()
            parser.feed(rendered)
            if not parser.form_action:
                fail("First-broker-login page did not include a submit form action")

            profile_payload = dict(parser.inputs)
            profile_payload["username"] = profile_payload.get("username") or "saml-e2e-user"
            profile_payload["email"] = profile_payload.get("email") or "saml-e2e@example.com"
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
            fail(
                "First-broker-login form submission did not redirect "
                f"(status={status}, url={form_action})\n{snippet}"
            )

        rendered = body.decode("utf-8", errors="replace")
        os.makedirs(os.path.dirname(DEBUG_HTML_PATH), exist_ok=True)
        with open(DEBUG_HTML_PATH, "w", encoding="utf-8") as debug_file:
            debug_file.write(rendered)
        snippet = rendered[:400]
        fail(
            "Unexpected non-redirect while following broker flow "
            f"(status={status}, url={current_url}, dumped_html={DEBUG_HTML_PATH})\n{snippet}"
        )

    fail("Exceeded redirect limit while waiting for final callback")


if __name__ == "__main__":
    main()
