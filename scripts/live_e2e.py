#!/usr/bin/env python3
"""Live local SAML e2e harness."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import docker
from docker.errors import DockerException, ImageNotFound, NotFound

ROOT_DIR = Path(__file__).resolve().parent.parent
WORK_DIR = ROOT_DIR / ".tmp" / "live-e2e"
CERT_PATH = WORK_DIR / "idp-signing-cert.pem"
KEY_PATH = WORK_DIR / "idp-signing-key.pem"
SAML_SERVER_PID_FILE = WORK_DIR / "saml_test_server.pid"
SAML_SERVER_LOG = WORK_DIR / "saml_test_server.log"
KEYCLOAK_CONTAINER_NAME = "saml-live-e2e-keycloak"
KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.0.8"
KEYCLOAK_REALM_TEMPLATE = ROOT_DIR / "examples" / "live_e2e" / "keycloak-realm.json"
KEYCLOAK_REALM_RENDERED = WORK_DIR / "keycloak-realm.generated.json"
KEYCLOAK_IMPORT_REALM_DST = "/opt/keycloak/data/import/saml-e2e-realm.json"


class HarnessError(RuntimeError):
    """Base error type for the live e2e harness."""


class ConfigError(HarnessError):
    """Raised for invalid harness configuration."""


class CommandError(HarnessError):
    """Raised when an external command fails."""


class DockerControlError(HarnessError):
    """Raised when Docker container lifecycle operations fail."""


class WaitTimeoutError(HarnessError):
    """Raised when waiting for a URL times out."""


@dataclass(frozen=True)
class DangerToggles:
    unlock: bool = False
    allow_unsigned_authn_requests: bool = False
    allow_unknown_service_providers: bool = False
    allow_weak_algorithms: bool = False


@dataclass(frozen=True)
class IdpBehavior:
    sign_assertion: bool
    sign_message: bool
    require_signed_authn_requests: bool
    c14n_method: str
    allow_unknown_sp: bool


@dataclass(frozen=True)
class RpBehavior:
    validate_signature: bool
    want_assertions_signed: bool
    want_authn_requests_signed: bool
    signature_algorithm: str | None = None


@dataclass(frozen=True)
class CaseExpectation:
    result: Literal["success", "error"]
    error_class: str | None = None
    assertion_signature: str = "ignore"
    response_signature: str = "ignore"
    c14n_method: str = "ignore"
    tamper_mode: str = "none"
    startup_log_fragment: str | None = None


@dataclass(frozen=True)
class LiveE2ECase:
    name: str
    mode: Literal["strict", "danger"]
    phase: Literal["startup", "flow"]
    idp: IdpBehavior
    rp: RpBehavior
    danger: DangerToggles
    expectation: CaseExpectation


@dataclass(frozen=True)
class CaseRunResult:
    name: str
    status: Literal["passed", "failed"]
    message: str


OutputMode = Literal["human", "github-actions"]


def _env_float(name: str, default: str) -> float:
    raw = os.getenv(name, default)
    try:
        value = float(raw)
    except ValueError as error:
        raise ConfigError(f"{name} must be a float, got {raw!r}") from error
    if value <= 0:
        raise ConfigError(f"{name} must be > 0, got {value}")
    return value


def _env_int(name: str, default: str) -> int:
    raw = os.getenv(name, default)
    try:
        value = int(raw)
    except ValueError as error:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from error
    if value <= 0:
        raise ConfigError(f"{name} must be > 0, got {value}")
    return value


WAIT_INTERVAL_SECONDS = _env_float("LIVE_E2E_WAIT_INTERVAL_SECONDS", "1")
KEYCLOAK_WAIT_TIMEOUT_SECONDS = _env_int(
    "LIVE_E2E_KEYCLOAK_WAIT_TIMEOUT_SECONDS", "180"
)
SAML_SERVER_WAIT_TIMEOUT_SECONDS = _env_int(
    "LIVE_E2E_SAML_SERVER_WAIT_TIMEOUT_SECONDS", "120"
)


def _bool_string(value: bool) -> str:
    return "true" if value else "false"


def _output_mode(raw_mode: str) -> OutputMode:
    normalized = raw_mode.strip().lower()
    if normalized == "human":
        return "human"
    if normalized == "github-actions":
        return "github-actions"
    raise ConfigError(
        f"LIVE_E2E_OUTPUT_MODE/--output-mode must be 'human' or 'github-actions', got {raw_mode!r}"
    )


def _default_output_mode() -> OutputMode:
    env_mode = os.getenv("LIVE_E2E_OUTPUT_MODE")
    if env_mode is not None:
        return _output_mode(env_mode)
    if os.getenv("CI") == "1":
        return "github-actions"
    return "human"


def _gha_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _emit_case_result(output_mode: OutputMode, result: CaseRunResult) -> None:
    if output_mode == "human":
        return

    escaped_name = _gha_escape(result.name)
    escaped_message = _gha_escape(result.message)
    if result.status == "passed":
        print(f"::notice title=live-e2e case passed::{escaped_name}: {escaped_message}")
    else:
        print(f"::error title=live-e2e case failed::{escaped_name}: {escaped_message}")


def _write_gha_summary(results: list[CaseRunResult]) -> None:
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    passed = sum(1 for result in results if result.status == "passed")
    failed = len(results) - passed
    lines = [
        "## Live E2E Matrix",
        "",
        f"- Passed: {passed}",
        f"- Failed: {failed}",
        "",
        "| Case | Status | Details |",
        "|---|---|---|",
    ]
    for result in results:
        status_emoji = "✅" if result.status == "passed" else "❌"
        details = result.message.replace("\n", "<br>")
        lines.append(f"| {result.name} | {status_emoji} {result.status} | {details} |")

    try:
        Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as error:
        print(
            f"Warning: failed to write GitHub Actions step summary to {summary_path}: {error}",
            file=sys.stderr,
        )


def _validate_case(case: LiveE2ECase) -> None:
    if case.mode == "strict" and case.danger.unlock:
        raise ConfigError(f"Case {case.name}: strict mode cannot unlock danger mode")
    if case.mode == "danger" and not case.danger.unlock:
        raise ConfigError(
            f"Case {case.name}: danger mode cases must unlock danger mode"
        )
    if case.expectation.result == "error" and not case.expectation.error_class:
        raise ConfigError(
            f"Case {case.name}: error expectation requires expectation.error_class"
        )
    if case.expectation.result == "success" and case.expectation.error_class:
        raise ConfigError(
            f"Case {case.name}: success expectation must not set expectation.error_class"
        )
    if case.phase == "startup" and case.expectation.result != "error":
        raise ConfigError(f"Case {case.name}: startup phase must expect error")


def run_command(args: list[str], env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(args, cwd=ROOT_DIR, env=env, check=True)
    except FileNotFoundError as error:
        raise CommandError(f"Missing required executable {args[0]!r}") from error
    except subprocess.CalledProcessError as error:
        raise CommandError(
            f"Command failed with exit code {error.returncode}: {args}"
        ) from error


def docker_client() -> docker.DockerClient:
    try:
        return docker.from_env()
    except DockerException as error:
        raise DockerControlError(
            f"Failed to initialize Docker client: {error}"
        ) from error


def ensure_keycloak_image(client: docker.DockerClient) -> None:
    try:
        client.images.get(KEYCLOAK_IMAGE)
    except ImageNotFound:
        print(f"Pulling Keycloak image: {KEYCLOAK_IMAGE}")
        try:
            client.images.pull(KEYCLOAK_IMAGE)
        except DockerException as error:
            raise DockerControlError(
                f"Failed to pull Keycloak image {KEYCLOAK_IMAGE}: {error}"
            ) from error
    except DockerException as error:
        raise DockerControlError(
            f"Failed to inspect Keycloak image {KEYCLOAK_IMAGE}: {error}"
        ) from error


def render_keycloak_realm(rp_behavior: RpBehavior) -> None:
    try:
        template_raw = KEYCLOAK_REALM_TEMPLATE.read_text(encoding="utf-8")
    except OSError as error:
        raise HarnessError(
            f"Failed to read realm template {KEYCLOAK_REALM_TEMPLATE}: {error}"
        ) from error

    try:
        realm = json.loads(template_raw)
    except json.JSONDecodeError as error:
        raise HarnessError(
            f"Invalid JSON in realm template {KEYCLOAK_REALM_TEMPLATE}: {error}"
        ) from error

    idp_config = None
    for provider in realm.get("identityProviders", []):
        if provider.get("providerId") == "saml" and provider.get("alias") == "saml-rs":
            idp_config = provider.setdefault("config", {})
            break

    if idp_config is None:
        raise HarnessError(
            "Keycloak realm template is missing identityProviders alias=saml-rs providerId=saml"
        )

    idp_config["validateSignature"] = _bool_string(rp_behavior.validate_signature)
    idp_config["wantAssertionsSigned"] = _bool_string(
        rp_behavior.want_assertions_signed
    )
    idp_config["wantAuthnRequestsSigned"] = _bool_string(
        rp_behavior.want_authn_requests_signed
    )
    if rp_behavior.signature_algorithm:
        idp_config["signatureAlgorithm"] = rp_behavior.signature_algorithm
    else:
        idp_config.pop("signatureAlgorithm", None)

    try:
        signing_cert_pem = CERT_PATH.read_text(encoding="utf-8")
    except OSError as error:
        raise HarnessError(
            f"Failed reading signing certificate {CERT_PATH}: {error}"
        ) from error

    signing_cert = "".join(
        line.strip()
        for line in signing_cert_pem.splitlines()
        if line.strip()
        and "BEGIN CERTIFICATE" not in line
        and "END CERTIFICATE" not in line
    )
    if not signing_cert:
        raise HarnessError(f"Signing certificate file is empty: {CERT_PATH}")
    idp_config["signingCertificate"] = signing_cert

    try:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        KEYCLOAK_REALM_RENDERED.write_text(
            f"{json.dumps(realm, indent=2)}\n",
            encoding="utf-8",
        )
    except OSError as error:
        raise HarnessError(
            f"Failed writing rendered realm config {KEYCLOAK_REALM_RENDERED}: {error}"
        ) from error


def start_keycloak() -> None:
    if not KEYCLOAK_REALM_RENDERED.exists():
        raise HarnessError(
            f"Rendered Keycloak realm file does not exist: {KEYCLOAK_REALM_RENDERED}"
        )

    client = docker_client()
    try:
        ensure_keycloak_image(client)
        try:
            container = client.containers.get(KEYCLOAK_CONTAINER_NAME)
            container.reload()
            if container.status == "running":
                print(f"Keycloak container already running: {KEYCLOAK_CONTAINER_NAME}")
                return
            print(f"Starting existing Keycloak container: {KEYCLOAK_CONTAINER_NAME}")
            try:
                container.start()
            except DockerException as error:
                raise DockerControlError(
                    f"Failed to start Keycloak container {KEYCLOAK_CONTAINER_NAME}: {error}"
                ) from error
            return
        except NotFound:
            pass

        print(f"Creating Keycloak container: {KEYCLOAK_CONTAINER_NAME}")
        try:
            client.containers.run(
                KEYCLOAK_IMAGE,
                name=KEYCLOAK_CONTAINER_NAME,
                command=[
                    "start-dev",
                    "--import-realm",
                    "--http-port=8080",
                    "--hostname=http://localhost:18080",
                    "--hostname-strict=false",
                ],
                environment={
                    "KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
                    "KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
                },
                ports={"8080/tcp": 18080},
                volumes={
                    str(KEYCLOAK_REALM_RENDERED): {
                        "bind": KEYCLOAK_IMPORT_REALM_DST,
                        "mode": "ro",
                    }
                },
                detach=True,
            )
        except DockerException as error:
            raise DockerControlError(
                f"Failed to create/start Keycloak container {KEYCLOAK_CONTAINER_NAME}: {error}"
            ) from error
    finally:
        client.close()


def stop_keycloak() -> None:
    client = docker_client()
    try:
        try:
            container = client.containers.get(KEYCLOAK_CONTAINER_NAME)
        except NotFound:
            return

        container.reload()
        if container.status == "running":
            print(f"Stopping Keycloak container: {KEYCLOAK_CONTAINER_NAME}")
            try:
                container.stop(timeout=10)
            except DockerException as error:
                raise DockerControlError(
                    f"Failed to stop Keycloak container {KEYCLOAK_CONTAINER_NAME}: {error}"
                ) from error
        print(f"Removing Keycloak container: {KEYCLOAK_CONTAINER_NAME}")
        try:
            container.remove(v=True, force=True)
        except DockerException as error:
            raise DockerControlError(
                f"Failed to remove Keycloak container {KEYCLOAK_CONTAINER_NAME}: {error}"
            ) from error
    except DockerException as error:
        raise DockerControlError(
            f"Docker error while stopping Keycloak container {KEYCLOAK_CONTAINER_NAME}: {error}"
        ) from error
    finally:
        client.close()


def wait_for_url(url: str, label: str, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            with urllib.request.urlopen(url, timeout=5):
                print(f"{label} is ready: {url}")
                return
        except (
            urllib.error.URLError,
            TimeoutError,
            http.client.HTTPException,
            OSError,
        ):
            time.sleep(WAIT_INTERVAL_SECONDS)
    raise WaitTimeoutError(
        f"Timed out waiting for {label}: {url} after {timeout_seconds}s ({attempts} attempts)"
    )


def restart_keycloak_for_case(case: LiveE2ECase) -> None:
    render_keycloak_realm(case.rp)
    stop_keycloak()
    start_keycloak()
    wait_for_url(
        "http://localhost:18080/realms/master",
        "Keycloak",
        KEYCLOAK_WAIT_TIMEOUT_SECONDS,
    )


def _saml_server_pid() -> int | None:
    if not SAML_SERVER_PID_FILE.exists():
        return None
    try:
        return int(SAML_SERVER_PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as error:
        raise HarnessError(
            f"Failed to read pid file {SAML_SERVER_PID_FILE}: {error}"
        ) from error


def _log_tail(path: Path, max_lines: int = 120) -> str:
    if not path.exists():
        return "<log file missing>"
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return f"<failed to read {path}: {error}>"
    lines = data.splitlines()
    if not lines:
        return "<log file empty>"
    return "\n".join(lines[-max_lines:])


def _pid_is_zombie(pid: int) -> bool:
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "stat="],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False

    state = result.stdout.strip()
    return state.startswith("Z")


def is_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

    return not _pid_is_zombie(pid)


def wait_for_saml_server_ready(label: str, timeout_seconds: int) -> None:
    url = "http://localhost:18081/SAML/Metadata"
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            with urllib.request.urlopen(url, timeout=5):
                print(f"{label} is ready: {url}")
                return
        except (
            urllib.error.URLError,
            TimeoutError,
            http.client.HTTPException,
            OSError,
        ):
            pid = _saml_server_pid()
            if pid is not None and not is_pid_running(pid):
                raise HarnessError(
                    "saml_test_server exited before becoming ready. "
                    f"attempts={attempts}. Last logs:\n{_log_tail(SAML_SERVER_LOG)}"
                )
            time.sleep(WAIT_INTERVAL_SECONDS)
    raise WaitTimeoutError(
        f"Timed out waiting for {label}: {url} after {timeout_seconds}s ({attempts} attempts). "
        f"Last logs:\n{_log_tail(SAML_SERVER_LOG)}"
    )


def wait_for_saml_server_exit(timeout_seconds: int = 8) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        pid = _saml_server_pid()
        if pid is None:
            return True
        if not is_pid_running(pid):
            return True
        time.sleep(0.2)
    return False


def prepare_signing_material() -> None:
    try:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise HarnessError(
            f"Failed to create work directory {WORK_DIR}: {error}"
        ) from error
    if CERT_PATH.exists() and KEY_PATH.exists():
        return

    print(f"Generating temporary SAML signing certificate in {WORK_DIR}")
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(KEY_PATH),
                "-out",
                str(CERT_PATH),
                "-sha256",
                "-nodes",
                "-days",
                "14",
                "-subj",
                "/CN=saml-rs-live-e2e",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError as error:
        raise CommandError("Missing required executable 'openssl'") from error
    except subprocess.CalledProcessError as error:
        raise CommandError(
            f"Failed to generate temporary SAML signing material with openssl: {error}"
        ) from error


def start_saml_server(case: LiveE2ECase) -> None:
    try:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise HarnessError(
            f"Failed to create work directory {WORK_DIR}: {error}"
        ) from error

    if SAML_SERVER_PID_FILE.exists():
        try:
            existing_pid = int(SAML_SERVER_PID_FILE.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as error:
            raise HarnessError(
                f"Failed to read pid file {SAML_SERVER_PID_FILE}: {error}"
            ) from error
        if is_pid_running(existing_pid):
            print(f"saml_test_server already running with PID {existing_pid}")
            return
        try:
            SAML_SERVER_PID_FILE.unlink(missing_ok=True)
        except OSError as error:
            raise HarnessError(
                f"Failed to remove stale pid file {SAML_SERVER_PID_FILE}: {error}"
            ) from error

    print(f"Starting saml_test_server for case {case.name} (logs: {SAML_SERVER_LOG})")

    env = os.environ.copy()
    env.update(
        {
            "SAML_TEST_SERVER_BIND_ADDRESS": "127.0.0.1",
            "SAML_TEST_SERVER_BIND_PORT": "18081",
            "SAML_TEST_SERVER_FRONTEND_HOSTNAME": "localhost",
            "SAML_TEST_SERVER_FRONTEND_PORT": "18081",
            "SAML_TEST_SERVER_PUBLIC_BASE_URL": "http://localhost:18081/SAML",
            "SAML_TEST_SERVER_ENTITY_ID": "http://localhost:18081/SAML/Metadata",
            "SAML_TEST_SERVER_SAML_CERT_PATH": str(CERT_PATH),
            "SAML_TEST_SERVER_SAML_KEY_PATH": str(KEY_PATH),
            "SAML_TEST_SERVER_CANONICALIZATION_METHOD": case.idp.c14n_method,
            "SAML_DANGER_UNLOCK": _bool_string(case.danger.unlock),
            "SAML_DANGER_ALLOW_UNSIGNED_AUTHN_REQUESTS": _bool_string(
                case.danger.allow_unsigned_authn_requests
            ),
            "SAML_DANGER_ALLOW_UNKNOWN_SERVICE_PROVIDERS": _bool_string(
                case.danger.allow_unknown_service_providers
            ),
            "SAML_DANGER_ALLOW_WEAK_ALGORITHMS": _bool_string(
                case.danger.allow_weak_algorithms
            ),
        }
    )

    bool_flags = {
        "SAML_TEST_SERVER_ALLOW_UNKNOWN_SP": case.idp.allow_unknown_sp,
        "SAML_TEST_SERVER_DISABLE_ASSERTION_SIGNING": not case.idp.sign_assertion,
        "SAML_TEST_SERVER_DISABLE_MESSAGE_SIGNING": not case.idp.sign_message,
        "SAML_TEST_SERVER_DISABLE_REQUIRED_SIGNED_AUTHN_REQUESTS": not case.idp.require_signed_authn_requests,
    }
    for flag_name, enabled in bool_flags.items():
        if enabled:
            env[flag_name] = "true"
        else:
            env.pop(flag_name, None)

    try:
        SAML_SERVER_LOG.write_text("", encoding="utf-8")
        with SAML_SERVER_LOG.open("ab") as log_file:
            process = subprocess.Popen(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--manifest-path",
                    str(ROOT_DIR / "Cargo.toml"),
                    "-p",
                    "saml_test_server",
                    "--features",
                    "danger_i_want_to_risk_it_all",
                    "--bin",
                    "saml_test_server",
                ],
                cwd=ROOT_DIR,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=log_file,
                start_new_session=True,
            )
    except FileNotFoundError as error:
        raise CommandError("Missing required executable 'cargo'") from error
    except OSError as error:
        raise HarnessError(f"Failed to start saml_test_server: {error}") from error

    try:
        SAML_SERVER_PID_FILE.write_text(f"{process.pid}\n", encoding="utf-8")
    except OSError as error:
        raise HarnessError(
            f"Failed to write pid file {SAML_SERVER_PID_FILE}: {error}"
        ) from error


def stop_saml_server() -> None:
    if not SAML_SERVER_PID_FILE.exists():
        return

    try:
        pid = int(SAML_SERVER_PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as error:
        raise HarnessError(
            f"Failed to read pid file {SAML_SERVER_PID_FILE}: {error}"
        ) from error

    if is_pid_running(pid):
        print(f"Stopping saml_test_server PID {pid}")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise HarnessError(
                f"Failed to send SIGTERM to saml_test_server ({pid}): {error}"
            ) from error
        for _ in range(20):
            if not is_pid_running(pid):
                break
            time.sleep(0.2)
        if is_pid_running(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                raise HarnessError(
                    f"Failed to send SIGKILL to saml_test_server ({pid}): {error}"
                ) from error

    try:
        SAML_SERVER_PID_FILE.unlink(missing_ok=True)
    except OSError as error:
        raise HarnessError(
            f"Failed to remove pid file {SAML_SERVER_PID_FILE}: {error}"
        ) from error


def assert_danger_mode_state(case: LiveE2ECase) -> None:
    log_text = SAML_SERVER_LOG.read_text(encoding="utf-8", errors="replace")
    unlock_phrase = "Danger mode unlocked for saml_test_server via SAML_DANGER_UNLOCK."
    toggle_phrases = {
        "allow_unsigned_authn_requests": "Enabled unsigned AuthnRequests in danger mode.",
        "allow_unknown_service_providers": "Enabled unknown service providers in danger mode.",
        "allow_weak_algorithms": "Enabled weak signature algorithms in danger mode.",
    }

    if case.mode == "strict":
        if unlock_phrase in log_text:
            raise HarnessError(
                f"Case {case.name}: strict mode unexpectedly unlocked danger mode"
            )
        for phrase in toggle_phrases.values():
            if phrase in log_text:
                raise HarnessError(
                    f"Case {case.name}: strict mode unexpectedly enabled danger override"
                )
        return

    expected_toggle_state = {
        "allow_unsigned_authn_requests": case.danger.allow_unsigned_authn_requests,
        "allow_unknown_service_providers": case.danger.allow_unknown_service_providers,
        "allow_weak_algorithms": case.danger.allow_weak_algorithms,
    }
    for key, enabled in expected_toggle_state.items():
        phrase = toggle_phrases[key]
        if not enabled and phrase in log_text:
            raise HarnessError(
                f"Case {case.name}: unexpected danger override {key} enabled"
            )


def expect_startup_failure(case: LiveE2ECase) -> None:
    if not wait_for_saml_server_exit():
        raise HarnessError(
            f"Case {case.name}: expected startup failure but saml_test_server stayed running"
        )

    log_text = SAML_SERVER_LOG.read_text(encoding="utf-8", errors="replace")
    fragment = case.expectation.startup_log_fragment
    if fragment and fragment not in log_text:
        raise HarnessError(
            f"Case {case.name}: startup failed, but expected log fragment was missing: {fragment!r}\n"
            f"Last logs:\n{_log_tail(SAML_SERVER_LOG)}"
        )
    print(
        f"Expected startup failure observed [{case.expectation.error_class}]: {case.name}"
    )


def verify_case(case: LiveE2ECase) -> None:
    env = os.environ.copy()
    env.update(
        {
            "LIVE_E2E_EXPECT_RESULT": case.expectation.result,
            "LIVE_E2E_EXPECT_ASSERTION_SIGNATURE": case.expectation.assertion_signature,
            "LIVE_E2E_EXPECT_RESPONSE_SIGNATURE": case.expectation.response_signature,
            "LIVE_E2E_EXPECT_C14N_METHOD": case.expectation.c14n_method,
            "LIVE_E2E_TAMPER_MODE": case.expectation.tamper_mode,
        }
    )
    if case.expectation.error_class:
        env["LIVE_E2E_EXPECTED_ERROR_CLASS"] = case.expectation.error_class

    run_command(
        [sys.executable, str(ROOT_DIR / "scripts" / "live_e2e_verify.py")], env=env
    )


def run_case(case: LiveE2ECase) -> None:
    _validate_case(case)
    print(f"=== Running case: {case.name} ===")

    if case.phase == "flow":
        restart_keycloak_for_case(case)

    stop_saml_server()
    start_saml_server(case)

    if case.phase == "startup":
        expect_startup_failure(case)
        stop_saml_server()
        return

    wait_for_saml_server_ready(
        f"saml_test_server ({case.name})",
        SAML_SERVER_WAIT_TIMEOUT_SECONDS,
    )
    assert_danger_mode_state(case)
    verify_case(case)


def build_matrix() -> list[LiveE2ECase]:
    strict = DangerToggles()
    danger_base = DangerToggles(
        unlock=True,
        allow_unsigned_authn_requests=True,
        allow_unknown_service_providers=True,
        allow_weak_algorithms=False,
    )

    return [
        LiveE2ECase(
            name="strict-startup-refuse-unknown-sp-toggle",
            mode="strict",
            phase="flow",
            idp=IdpBehavior(True, False, True, "exclusive", True),
            rp=RpBehavior(True, True, False),
            danger=strict,
            expectation=CaseExpectation(
                result="error",
                error_class="idp_redirect_rejected",
            ),
        ),
        LiveE2ECase(
            name="strict-startup-refuse-unsigned-authn-toggle",
            mode="strict",
            phase="flow",
            idp=IdpBehavior(True, False, False, "exclusive", False),
            rp=RpBehavior(True, True, False),
            danger=strict,
            expectation=CaseExpectation(
                result="error",
                error_class="idp_redirect_rejected",
            ),
        ),
        LiveE2ECase(
            name="strict-startup-refuse-weak-algorithm-toggle",
            mode="strict",
            phase="startup",
            idp=IdpBehavior(True, False, True, "exclusive", False),
            rp=RpBehavior(True, True, False),
            danger=DangerToggles(allow_weak_algorithms=True),
            expectation=CaseExpectation(
                result="error",
                error_class="server_startup_rejected",
            ),
        ),
        LiveE2ECase(
            name="strict-flow-unknown-sp-rejected",
            mode="strict",
            phase="flow",
            idp=IdpBehavior(True, False, True, "exclusive", False),
            rp=RpBehavior(True, True, False),
            danger=strict,
            expectation=CaseExpectation(
                result="error",
                error_class="idp_redirect_rejected",
            ),
        ),
        LiveE2ECase(
            name="danger-startup-refuse-unknown-sp-when-toggle-missing",
            mode="danger",
            phase="flow",
            idp=IdpBehavior(True, False, True, "exclusive", True),
            rp=RpBehavior(True, True, False),
            danger=DangerToggles(
                unlock=True,
                allow_unsigned_authn_requests=True,
                allow_unknown_service_providers=False,
                allow_weak_algorithms=False,
            ),
            expectation=CaseExpectation(
                result="error",
                error_class="idp_redirect_rejected",
            ),
        ),
        LiveE2ECase(
            name="danger-startup-refuse-unsigned-authn-when-toggle-missing",
            mode="danger",
            phase="flow",
            idp=IdpBehavior(True, False, False, "exclusive", False),
            rp=RpBehavior(True, True, False),
            danger=DangerToggles(
                unlock=True,
                allow_unsigned_authn_requests=False,
                allow_unknown_service_providers=True,
                allow_weak_algorithms=False,
            ),
            expectation=CaseExpectation(
                result="error",
                error_class="idp_redirect_rejected",
            ),
        ),
        LiveE2ECase(
            name="danger-flow-signed-assertion-success",
            mode="danger",
            phase="flow",
            idp=IdpBehavior(True, False, False, "exclusive", True),
            rp=RpBehavior(True, True, False),
            danger=danger_base,
            expectation=CaseExpectation(
                result="success",
                assertion_signature="true",
                response_signature="false",
                c14n_method="exclusive",
            ),
        ),
        LiveE2ECase(
            name="danger-flow-tampered-response-rejected",
            mode="danger",
            phase="flow",
            idp=IdpBehavior(True, False, False, "exclusive", True),
            rp=RpBehavior(True, True, False),
            danger=danger_base,
            expectation=CaseExpectation(
                result="error",
                error_class="broker_post_rejected",
                assertion_signature="true",
                response_signature="false",
                c14n_method="exclusive",
                tamper_mode="response_corrupt",
            ),
        ),
        LiveE2ECase(
            name="danger-flow-weak-toggle-enabled-still-rejects-tamper",
            mode="danger",
            phase="flow",
            idp=IdpBehavior(True, False, False, "exclusive", True),
            rp=RpBehavior(True, True, False),
            danger=DangerToggles(
                unlock=True,
                allow_unsigned_authn_requests=True,
                allow_unknown_service_providers=True,
                allow_weak_algorithms=True,
            ),
            expectation=CaseExpectation(
                result="error",
                error_class="broker_post_rejected",
                assertion_signature="true",
                response_signature="false",
                c14n_method="exclusive",
                tamper_mode="response_corrupt",
            ),
        ),
        LiveE2ECase(
            name="danger-flow-signed-authnrequest-required-rejected-without-sp-cert",
            mode="danger",
            phase="flow",
            idp=IdpBehavior(True, False, True, "exclusive", True),
            rp=RpBehavior(True, True, True),
            danger=DangerToggles(
                unlock=True,
                allow_unsigned_authn_requests=False,
                allow_unknown_service_providers=True,
                allow_weak_algorithms=False,
            ),
            expectation=CaseExpectation(
                result="error",
                error_class="idp_redirect_rejected",
                assertion_signature="ignore",
                response_signature="ignore",
                c14n_method="ignore",
            ),
        ),
        LiveE2ECase(
            name="danger-flow-response-signing-required-success",
            mode="danger",
            phase="flow",
            idp=IdpBehavior(True, True, False, "exclusive", True),
            rp=RpBehavior(True, True, False),
            danger=danger_base,
            expectation=CaseExpectation(
                result="success",
                assertion_signature="true",
                response_signature="true",
                c14n_method="exclusive",
            ),
        ),
    ]


def run_matrix(output_mode: OutputMode) -> None:
    results: list[CaseRunResult] = []
    failures: list[tuple[str, str]] = []
    for case in build_matrix():
        try:
            run_case(case)
            result = CaseRunResult(case.name, "passed", "case completed as expected")
            results.append(result)
            _emit_case_result(output_mode, result)
        except (
            HarnessError,
            CommandError,
            DockerControlError,
            WaitTimeoutError,
            ConfigError,
        ) as error:
            failures.append((case.name, str(error)))
            result = CaseRunResult(case.name, "failed", str(error))
            results.append(result)
            _emit_case_result(output_mode, result)
            print(f"Case failed: {case.name}: {error}", file=sys.stderr)
        except Exception as error:  # noqa: BLE001
            failures.append((case.name, f"unexpected exception: {error}"))
            result = CaseRunResult(
                case.name, "failed", f"unexpected exception: {error}"
            )
            results.append(result)
            _emit_case_result(output_mode, result)
            print(
                f"Case failed with unexpected exception: {case.name}: {error}",
                file=sys.stderr,
            )
        finally:
            try:
                stop_saml_server()
            except HarnessError as stop_error:
                failures.append((case.name, f"cleanup failure: {stop_error}"))
                print(
                    f"Case cleanup failed after {case.name}: {stop_error}",
                    file=sys.stderr,
                )

    if output_mode == "github-actions":
        _write_gha_summary(results)

    if failures:
        summary = "\n".join(f"- {name}: {message}" for name, message in failures)
        raise HarnessError("live-e2e matrix reported unexpected failures:\n" + summary)


def up() -> None:
    prepare_signing_material()
    # Bring up a default runtime profile suitable for manual debugging.
    default_case = LiveE2ECase(
        name="up-default",
        mode="danger",
        phase="flow",
        idp=IdpBehavior(True, False, False, "exclusive", True),
        rp=RpBehavior(True, True, False),
        danger=DangerToggles(
            unlock=True,
            allow_unsigned_authn_requests=True,
            allow_unknown_service_providers=True,
            allow_weak_algorithms=False,
        ),
        expectation=CaseExpectation(result="success"),
    )
    restart_keycloak_for_case(default_case)
    stop_saml_server()
    start_saml_server(default_case)
    wait_for_saml_server_ready("saml_test_server", SAML_SERVER_WAIT_TIMEOUT_SECONDS)
    assert_danger_mode_state(default_case)


def down() -> None:
    stop_saml_server()
    stop_keycloak()


def run_all(output_mode: OutputMode) -> None:
    keep_up = os.getenv("KEEP_UP", "0") == "1"
    try:
        prepare_signing_material()
        run_matrix(output_mode)
    finally:
        if not keep_up:
            down()
        else:
            print("KEEP_UP=1 set, leaving Keycloak + saml_test_server running.")


def main() -> int:
    parser = argparse.ArgumentParser(usage="%(prog)s [run|up|down]")
    parser.add_argument(
        "command", nargs="?", default="run", choices=["run", "up", "down"]
    )
    parser.add_argument(
        "--output-mode",
        default=_default_output_mode(),
        choices=["human", "github-actions"],
        help="Control result output formatting; use 'github-actions' for CI annotations and step summary.",
    )
    args = parser.parse_args()
    output_mode = _output_mode(args.output_mode)

    if args.command == "run":
        run_all(output_mode)
    elif args.command == "up":
        up()
    elif args.command == "down":
        down()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    except KeyboardInterrupt as error:
        print("ERROR: interrupted", file=sys.stderr)
        raise SystemExit(130) from error
