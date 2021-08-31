#!/bin/bash

# run_docker_example.sh
# runs the .. docker example.

DOCKERIMAGE="saml-rs/saml_test_server:latest"

# \/ SC2068 "quote array to avoid re-splitting" - we want this \/
#shellcheck disable=SC2068
docker run --rm \
    --name saml_test_server \
     -e 'SAML_TLS_CERT_PATH=~/.config/fullchain.pem' \
     -e 'SAML_TLS_KEY_PATH=~/.config/privkey.pem' \
     -e 'SAML_SAML_CERT_PATH=~/.config/fullchain.pem' \
     -e 'SAML_SAML_KEY_PATH=~/.config/privkey.pem' \
     -p 443:443 \
    $@ \
    "${DOCKERIMAGE}"


