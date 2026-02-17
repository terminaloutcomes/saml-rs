#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker-compose.live-e2e.yml"
PROJECT_NAME="saml-live-e2e"
WORK_DIR="${ROOT_DIR}/.tmp/live-e2e"
CERT_PATH="${WORK_DIR}/idp-signing-cert.pem"
KEY_PATH="${WORK_DIR}/idp-signing-key.pem"
SAML_SERVER_PID_FILE="${WORK_DIR}/saml_test_server.pid"
SAML_SERVER_LOG="${WORK_DIR}/saml_test_server.log"
SAML_SIGN_ASSERTION_VALUE="${SAML_SIGN_ASSERTION_VALUE:-true}"
SAML_SIGN_MESSAGE_VALUE="${SAML_SIGN_MESSAGE_VALUE:-false}"
SAML_REQUIRE_SIGNED_AUTHN_REQUESTS_VALUE="${SAML_REQUIRE_SIGNED_AUTHN_REQUESTS_VALUE:-false}"
SAML_C14N_METHOD_VALUE="${SAML_C14N_METHOD_VALUE:-exclusive}"

compose() {
    docker compose -f "${COMPOSE_FILE}" -p "${PROJECT_NAME}" "$@"
}

wait_for_url() {
    local url="$1"
    local label="$2"

    for _ in $(seq 1 90); do
        if curl -fsS "${url}" >/dev/null 2>&1; then
            echo "${label} is ready: ${url}"
            return 0
        fi
        sleep 1
    done

    echo "Timed out waiting for ${label}: ${url}" >&2
    return 1
}

is_pid_running() {
    local pid="$1"
    kill -0 "${pid}" >/dev/null 2>&1
}

prepare_signing_material() {
    mkdir -p "${WORK_DIR}"
    if [[ -f "${CERT_PATH}" && -f "${KEY_PATH}" ]]; then
        return 0
    fi

    echo "Generating temporary SAML signing certificate in ${WORK_DIR}"
    openssl req \
        -x509 \
        -newkey rsa:2048 \
        -keyout "${KEY_PATH}" \
        -out "${CERT_PATH}" \
        -sha256 \
        -nodes \
        -days 14 \
        -subj "/CN=saml-rs-live-e2e" >/dev/null 2>&1
}

start_saml_server() {
    mkdir -p "${WORK_DIR}"

    if [[ -f "${SAML_SERVER_PID_FILE}" ]]; then
        local existing_pid
        existing_pid="$(cat "${SAML_SERVER_PID_FILE}")"
        if is_pid_running "${existing_pid}"; then
            echo "saml_test_server already running with PID ${existing_pid}"
            return 0
        fi
        rm -f "${SAML_SERVER_PID_FILE}"
    fi

    echo "Starting saml_test_server on host (logs: ${SAML_SERVER_LOG})"
    nohup env \
        SAML_BIND_ADDRESS=127.0.0.1 \
        SAML_BIND_PORT=18081 \
        SAML_LISTEN_SCHEME=http \
        SAML_PUBLIC_HOSTNAME=localhost:18081 \
        SAML_PUBLIC_BASE_URL=http://localhost:18081/SAML \
        SAML_ENTITY_ID=http://localhost:18081/SAML/Metadata \
        SAML_ALLOW_UNKNOWN_SP=true \
        SAML_SAML_CERT_PATH="${CERT_PATH}" \
        SAML_SAML_KEY_PATH="${KEY_PATH}" \
        SAML_SIGN_ASSERTION="${SAML_SIGN_ASSERTION_VALUE}" \
        SAML_SIGN_MESSAGE="${SAML_SIGN_MESSAGE_VALUE}" \
        SAML_REQUIRE_SIGNED_AUTHN_REQUESTS="${SAML_REQUIRE_SIGNED_AUTHN_REQUESTS_VALUE}" \
        SAML_C14N_METHOD="${SAML_C14N_METHOD_VALUE}" \
        cargo run --quiet --manifest-path "${ROOT_DIR}/Cargo.toml" -p saml_test_server --bin saml_test_server \
        >"${SAML_SERVER_LOG}" 2>&1 < /dev/null &

    local pid=$!
    echo "${pid}" >"${SAML_SERVER_PID_FILE}"
}

stop_saml_server() {
    if [[ ! -f "${SAML_SERVER_PID_FILE}" ]]; then
        return 0
    fi

    local pid
    pid="$(cat "${SAML_SERVER_PID_FILE}")"
    if is_pid_running "${pid}"; then
        echo "Stopping saml_test_server PID ${pid}"
        kill "${pid}" >/dev/null 2>&1 || true
        for _ in $(seq 1 20); do
            if ! is_pid_running "${pid}"; then
                break
            fi
            sleep 0.2
        done
        if is_pid_running "${pid}"; then
            kill -9 "${pid}" >/dev/null 2>&1 || true
        fi
        wait "${pid}" 2>/dev/null || true
    fi

    rm -f "${SAML_SERVER_PID_FILE}"
}

up() {
    prepare_signing_material
    compose up -d
    wait_for_url "http://localhost:18080/realms/master" "Keycloak"

    start_saml_server
    wait_for_url "http://localhost:18081/SAML/Metadata" "saml_test_server"
}

down() {
    stop_saml_server
    compose down -v --remove-orphans
}

verify() {
    python3 "${ROOT_DIR}/scripts/live_e2e_verify.py"
}

run_case() {
    local case_name="$1"
    local sign_assertion="$2"
    local sign_message="$3"
    local require_signed_authn="$4"
    local c14n_method="$5"
    local expect_success="$6"
    local expect_assertion_signature="$7"
    local expect_response_signature="$8"
    local expect_c14n_method="$9"
    local tamper_response="${10}"

    echo "=== Running case: ${case_name} ==="
    SAML_SIGN_ASSERTION_VALUE="${sign_assertion}"
    SAML_SIGN_MESSAGE_VALUE="${sign_message}"
    SAML_REQUIRE_SIGNED_AUTHN_REQUESTS_VALUE="${require_signed_authn}"
    SAML_C14N_METHOD_VALUE="${c14n_method}"

    stop_saml_server
    start_saml_server
    wait_for_url "http://localhost:18081/SAML/Metadata" "saml_test_server (${case_name})"

    env \
        LIVE_E2E_EXPECT_SUCCESS="${expect_success}" \
        LIVE_E2E_EXPECT_ASSERTION_SIGNATURE="${expect_assertion_signature}" \
        LIVE_E2E_EXPECT_RESPONSE_SIGNATURE="${expect_response_signature}" \
        LIVE_E2E_EXPECT_C14N_METHOD="${expect_c14n_method}" \
        LIVE_E2E_TAMPER_SAML_RESPONSE="${tamper_response}" \
        python3 "${ROOT_DIR}/scripts/live_e2e_verify.py"
}

run_matrix() {
    run_case "unsigned-response+unsigned-assertion" \
        "false" "false" "false" "exclusive" \
        "true" "false" "false" "ignore" "false"

    run_case "signed-assertion-only" \
        "true" "false" "false" "exclusive" \
        "true" "true" "false" "exclusive" "false"

    run_case "signed-message-only" \
        "false" "true" "false" "exclusive" \
        "true" "false" "true" "exclusive" "false"

    run_case "signed-assertion+signed-message-inclusive-c14n" \
        "true" "true" "false" "inclusive" \
        "true" "true" "true" "inclusive" "false"

    run_case "require-signed-authnrequest-negative" \
        "true" "false" "true" "exclusive" \
        "false" "ignore" "ignore" "ignore" "false"

    run_case "tampered-saml-response-negative" \
        "true" "false" "false" "exclusive" \
        "false" "true" "false" "exclusive" "true"
}

run_all() {
    if [[ "${KEEP_UP:-0}" != "1" ]]; then
        trap down EXIT
    fi

    up
    run_matrix

    if [[ "${KEEP_UP:-0}" == "1" ]]; then
        echo "KEEP_UP=1 set, leaving Keycloak + saml_test_server running."
    fi
}

case "${1:-run}" in
    run)
        run_all
        ;;
    up)
        up
        ;;
    verify)
        verify
        ;;
    down)
        down
        ;;
    *)
        echo "Usage: $0 [run|up|verify|down]" >&2
        exit 1
        ;;
esac
