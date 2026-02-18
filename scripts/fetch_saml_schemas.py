#!/usr/bin/env python3
"""Fetch and verify vendored SAML/XMDSIG/XMLENC schema files."""

from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT_DIR / "examples" / "schemas"


@dataclass(frozen=True)
class SchemaSource:
    filename: str
    url: str
    sha256: str


SCHEMA_SOURCES: tuple[SchemaSource, ...] = (
    SchemaSource(
        filename="saml-schema-protocol-2.0.xsd",
        url="https://docs.oasis-open.org/security/saml/v2.0/saml-schema-protocol-2.0.xsd",
        sha256="554250583cd5eacc6ce5f094f6ff50fc2547972c436dc96e2e7eb41abf2c817e",
    ),
    SchemaSource(
        filename="saml-schema-assertion-2.0.xsd",
        url="https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd",
        sha256="006eb7553843cb7baa9b08da2a9d444346c0e982fb9d9293babe08ede680924b",
    ),
    SchemaSource(
        filename="xmldsig-core-schema.xsd",
        url="https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd",
        sha256="35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c",
    ),
    SchemaSource(
        filename="xenc-schema.xsd",
        url="https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd",
        sha256="5dd57f074870e1d91f7eb814aa92967cefcce9011a86adf5e12a769fcf2a237e",
    ),
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read()
    except urllib.error.URLError as error:
        raise RuntimeError(f"Failed downloading {url}: {error}") from error


def verify_schema_file(path: Path, expected_sha256: str) -> None:
    payload = path.read_bytes()
    observed_sha256 = sha256_hex(payload)
    if observed_sha256 != expected_sha256:
        raise RuntimeError(
            f"Hash mismatch for {path.name}: expected {expected_sha256}, got {observed_sha256}"
        )


def fetch_and_verify(verify_only: bool) -> None:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)

    for source in SCHEMA_SOURCES:
        destination = SCHEMA_DIR / source.filename

        if not verify_only:
            payload = download(source.url)
            observed_sha256 = sha256_hex(payload)
            if observed_sha256 != source.sha256:
                raise RuntimeError(
                    f"Downloaded content hash mismatch for {source.filename}: expected "
                    f"{source.sha256}, got {observed_sha256}"
                )
            destination.write_bytes(payload)
            print(f"Fetched {source.filename}")

        if not destination.exists():
            raise RuntimeError(
                f"Missing schema file {destination}. Run without --verify-only first."
            )

        verify_schema_file(destination, source.sha256)
        print(f"Verified {source.filename}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch and verify vendored SAML schema files."
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify local files against pinned hashes; do not download.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        fetch_and_verify(verify_only=args.verify_only)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
