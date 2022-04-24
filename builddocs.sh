#!/bin/bash

#shellcheck disable=SC2048,SC2086
cargo doc --no-deps --workspace --document-private-items $*
