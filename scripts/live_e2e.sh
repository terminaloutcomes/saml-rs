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

run_all() {
    if [[ "${KEEP_UP:-0}" != "1" ]]; then
        trap down EXIT
    fi

    up
    verify

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
