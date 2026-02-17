#!/usr/bin/env python3
"""Live local SAML e2e harness."""

from __future__ import annotations

import argparse
import http.client
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

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
KEYCLOAK_IMPORT_REALM_SRC = ROOT_DIR / "examples" / "live_e2e" / "keycloak-realm.json"
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
KEYCLOAK_WAIT_TIMEOUT_SECONDS = _env_int("LIVE_E2E_KEYCLOAK_WAIT_TIMEOUT_SECONDS", "180")
SAML_SERVER_WAIT_TIMEOUT_SECONDS = _env_int("LIVE_E2E_SAML_SERVER_WAIT_TIMEOUT_SECONDS", "120")


def run_command(args: list[str], env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(args, cwd=ROOT_DIR, env=env, check=True)
    except FileNotFoundError as error:
        raise CommandError(f"Missing required executable {args[0]!r}") from error
    except subprocess.CalledProcessError as error:
        raise CommandError(f"Command failed with exit code {error.returncode}: {args}") from error


def docker_client() -> docker.DockerClient:
    try:
        return docker.from_env()
    except DockerException as error:
        raise DockerControlError(f"Failed to initialize Docker client: {error}") from error


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


def start_keycloak() -> None:
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
                    str(KEYCLOAK_IMPORT_REALM_SRC): {
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
        except (urllib.error.URLError, TimeoutError, http.client.HTTPException, OSError):
            time.sleep(WAIT_INTERVAL_SECONDS)
    raise WaitTimeoutError(
        f"Timed out waiting for {label}: {url} after {timeout_seconds}s ({attempts} attempts)"
    )


def is_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def prepare_signing_material() -> None:
    try:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise HarnessError(f"Failed to create work directory {WORK_DIR}: {error}") from error
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


def current_signing_env() -> tuple[str, str, str, str]:
    return (
        os.getenv("SAML_SIGN_ASSERTION_VALUE", "true"),
        os.getenv("SAML_SIGN_MESSAGE_VALUE", "false"),
        os.getenv("SAML_REQUIRE_SIGNED_AUTHN_REQUESTS_VALUE", "false"),
        os.getenv("SAML_C14N_METHOD_VALUE", "exclusive"),
    )


def start_saml_server() -> None:
    try:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise HarnessError(f"Failed to create work directory {WORK_DIR}: {error}") from error

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

    print(f"Starting saml_test_server on host (logs: {SAML_SERVER_LOG})")
    sign_assertion, sign_message, require_signed_authn, c14n_method = (
        current_signing_env()
    )

    env = os.environ.copy()
    env.update(
        {
            "SAML_BIND_ADDRESS": "127.0.0.1",
            "SAML_BIND_PORT": "18081",
            "SAML_LISTEN_SCHEME": "http",
            "SAML_PUBLIC_HOSTNAME": "localhost:18081",
            "SAML_PUBLIC_BASE_URL": "http://localhost:18081/SAML",
            "SAML_ENTITY_ID": "http://localhost:18081/SAML/Metadata",
            "SAML_ALLOW_UNKNOWN_SP": "true",
            "SAML_SAML_CERT_PATH": str(CERT_PATH),
            "SAML_SAML_KEY_PATH": str(KEY_PATH),
            "SAML_SIGN_ASSERTION": sign_assertion,
            "SAML_SIGN_MESSAGE": sign_message,
            "SAML_REQUIRE_SIGNED_AUTHN_REQUESTS": require_signed_authn,
            "SAML_C14N_METHOD": c14n_method,
        }
    )
    try:
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
            raise HarnessError(f"Failed to send SIGTERM to saml_test_server ({pid}): {error}") from error
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


def up() -> None:
    prepare_signing_material()
    start_keycloak()
    wait_for_url(
        "http://localhost:18080/realms/master",
        "Keycloak",
        KEYCLOAK_WAIT_TIMEOUT_SECONDS,
    )

    start_saml_server()
    wait_for_url(
        "http://localhost:18081/SAML/Metadata",
        "saml_test_server",
        SAML_SERVER_WAIT_TIMEOUT_SECONDS,
    )


def down() -> None:
    stop_saml_server()
    stop_keycloak()


def verify(extra_env: dict[str, str] | None = None) -> None:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    run_command(
        [sys.executable, str(ROOT_DIR / "scripts" / "live_e2e_verify.py")], env=env
    )


def run_case(
    case_name: str,
    sign_assertion: str,
    sign_message: str,
    require_signed_authn: str,
    c14n_method: str,
    expect_success: str,
    expect_assertion_signature: str,
    expect_response_signature: str,
    expect_c14n_method: str,
    tamper_response: str,
) -> None:
    print(f"=== Running case: {case_name} ===")
    os.environ["SAML_SIGN_ASSERTION_VALUE"] = sign_assertion
    os.environ["SAML_SIGN_MESSAGE_VALUE"] = sign_message
    os.environ["SAML_REQUIRE_SIGNED_AUTHN_REQUESTS_VALUE"] = require_signed_authn
    os.environ["SAML_C14N_METHOD_VALUE"] = c14n_method

    stop_saml_server()
    start_saml_server()
    wait_for_url(
        "http://localhost:18081/SAML/Metadata",
        f"saml_test_server ({case_name})",
        SAML_SERVER_WAIT_TIMEOUT_SECONDS,
    )

    verify(
        {
            "LIVE_E2E_EXPECT_SUCCESS": expect_success,
            "LIVE_E2E_EXPECT_ASSERTION_SIGNATURE": expect_assertion_signature,
            "LIVE_E2E_EXPECT_RESPONSE_SIGNATURE": expect_response_signature,
            "LIVE_E2E_EXPECT_C14N_METHOD": expect_c14n_method,
            "LIVE_E2E_TAMPER_SAML_RESPONSE": tamper_response,
        }
    )


def run_matrix() -> None:
    run_case(
        "unsigned-response+unsigned-assertion",
        "false",
        "false",
        "false",
        "exclusive",
        "true",
        "false",
        "false",
        "ignore",
        "false",
    )
    run_case(
        "signed-assertion-only",
        "true",
        "false",
        "false",
        "exclusive",
        "true",
        "true",
        "false",
        "exclusive",
        "false",
    )
    run_case(
        "signed-message-only",
        "false",
        "true",
        "false",
        "exclusive",
        "true",
        "false",
        "true",
        "exclusive",
        "false",
    )
    run_case(
        "signed-assertion+signed-message-inclusive-c14n",
        "true",
        "true",
        "false",
        "inclusive",
        "true",
        "true",
        "true",
        "inclusive",
        "false",
    )
    run_case(
        "require-signed-authnrequest-negative",
        "true",
        "false",
        "true",
        "exclusive",
        "false",
        "ignore",
        "ignore",
        "ignore",
        "false",
    )
    run_case(
        "tampered-saml-response-negative",
        "true",
        "false",
        "false",
        "exclusive",
        "false",
        "true",
        "false",
        "exclusive",
        "true",
    )


def run_all() -> None:
    keep_up = os.getenv("KEEP_UP", "0") == "1"
    try:
        up()
        run_matrix()
    finally:
        if not keep_up:
            down()
        else:
            print("KEEP_UP=1 set, leaving Keycloak + saml_test_server running.")


def main() -> int:
    parser = argparse.ArgumentParser(usage="%(prog)s [run|up|verify|down]")
    parser.add_argument(
        "command", nargs="?", default="run", choices=["run", "up", "verify", "down"]
    )
    args = parser.parse_args()

    if args.command == "run":
        run_all()
    elif args.command == "up":
        up()
    elif args.command == "verify":
        verify()
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
