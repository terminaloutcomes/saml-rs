#!/usr/bin/env python3
"""Live local SAML e2e harness."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
COMPOSE_FILE = ROOT_DIR / "docker-compose.live-e2e.yml"
PROJECT_NAME = "saml-live-e2e"
WORK_DIR = TemporaryDirectory()
CERT_PATH = Path(WORK_DIR.name) / "idp-signing-cert.pem"
KEY_PATH = Path(WORK_DIR.name) / "idp-signing-key.pem"
SAML_SERVER_PID_FILE = Path(WORK_DIR.name) / "saml_test_server.pid"
SAML_SERVER_LOG = Path(WORK_DIR.name) / "saml_test_server.log"


def run_command(args: list[str], env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=ROOT_DIR, env=env, check=True)


def compose(args: list[str]) -> None:
    run_command(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "-p", PROJECT_NAME, *args]
    )


def wait_for_url(url: str, label: str) -> None:
    for _ in range(90):
        try:
            with urllib.request.urlopen(url, timeout=5):
                print(f"{label} is ready: {url}")
                return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(1)
    raise RuntimeError(f"Timed out waiting for {label}: {url}")


def is_pid_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def prepare_signing_material() -> None:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    if CERT_PATH.exists() and KEY_PATH.exists():
        return

    print(f"Generating temporary SAML signing certificate in {WORK_DIR}")
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


def current_signing_env() -> tuple[str, str, str, str]:
    return (
        os.getenv("SAML_SIGN_ASSERTION_VALUE", "true"),
        os.getenv("SAML_SIGN_MESSAGE_VALUE", "false"),
        os.getenv("SAML_REQUIRE_SIGNED_AUTHN_REQUESTS_VALUE", "false"),
        os.getenv("SAML_C14N_METHOD_VALUE", "exclusive"),
    )


def start_saml_server() -> None:
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    if SAML_SERVER_PID_FILE.exists():
        existing_pid = int(SAML_SERVER_PID_FILE.read_text(encoding="utf-8").strip())
        if is_pid_running(existing_pid):
            print(f"saml_test_server already running with PID {existing_pid}")
            return
        SAML_SERVER_PID_FILE.unlink(missing_ok=True)

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

    SAML_SERVER_PID_FILE.write_text(f"{process.pid}\n", encoding="utf-8")


def stop_saml_server() -> None:
    if not SAML_SERVER_PID_FILE.exists():
        return

    pid = int(SAML_SERVER_PID_FILE.read_text(encoding="utf-8").strip())
    if is_pid_running(pid):
        print(f"Stopping saml_test_server PID {pid}")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(20):
            if not is_pid_running(pid):
                break
            time.sleep(0.2)
        if is_pid_running(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    SAML_SERVER_PID_FILE.unlink(missing_ok=True)


def up() -> None:
    prepare_signing_material()
    compose(["up", "-d"])
    wait_for_url("http://localhost:18080/realms/master", "Keycloak")

    start_saml_server()
    wait_for_url("http://localhost:18081/SAML/Metadata", "saml_test_server")


def down() -> None:
    stop_saml_server()
    compose(["down", "-v", "--remove-orphans"])


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
        "http://localhost:18081/SAML/Metadata", f"saml_test_server ({case_name})"
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
    raise SystemExit(main())
