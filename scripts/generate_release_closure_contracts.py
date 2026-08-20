#!/usr/bin/env python3
"""Enforce HOLD by refusing to generate an unfrozen public closure contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.evidence.release_public_closure_hold import REASON, REASON_CODE  # noqa: E402

FORBIDDEN_OUTPUTS = (
    Path("docs/schemas/release/release-evidence-v2.schema.json"),
    Path("docs/schemas/release/release-controller-closure-manifest-v1.schema.json"),
    Path(
        "docs/schemas/release/release-runtime-closure-provider-observation-v1.schema.json"
    ),
    Path("docs/schemas/release/release-runtime-closure-request-v1.schema.json"),
    Path("docs/schemas/release/release-runtime-closure-stream-response-v1.schema.json"),
    Path("tests/fixtures/release-controller-closure-v1/closed-receipt-v2.json"),
    Path("tests/fixtures/release-controller-closure-v1/closure-manifest-v1.json"),
    Path("tests/fixtures/release-controller-closure-v1/receipt-chain-v2.json"),
    Path("tests/fixtures/release-controller-closure-v1/release-evidence-v2.json"),
    Path(
        "docs/schemas/release-controller-wire-v1/"
        "dpone.release-controller-closed-finalize-response.v1.json"
    ),
    Path(
        "docs/schemas/release-controller-wire-v1/"
        "dpone.release-controller-closure-materialization.v1.json"
    ),
    Path(
        "docs/schemas/release-controller-wire-v1/"
        "dpone.release-controller-closure-upload-proof.v1.json"
    ),
    Path(
        "docs/schemas/release-controller-wire-v1/"
        "dpone.release-controller-runtime-closure-verification-result.v1.json"
    ),
    Path(
        "docs/schemas/release-controller-wire-v1/"
        "dpone.release-runtime-closure-request.v1.json"
    ),
    Path(
        "docs/schemas/release-controller-wire-v1/"
        "dpone.release-runtime-closure-stream-response.v1.json"
    ),
    Path(
        "tests/fixtures/release-controller-wire-v1/"
        "dpone.release-controller-closed-finalize-response.v1.json"
    ),
    Path(
        "tests/fixtures/release-controller-wire-v1/"
        "dpone.release-controller-closure-materialization.v1.json"
    ),
    Path(
        "tests/fixtures/release-controller-wire-v1/"
        "dpone.release-controller-closure-materialization.v1.zip"
    ),
    Path(
        "tests/fixtures/release-controller-wire-v1/"
        "dpone.release-controller-closure-upload-proof.v1.json"
    ),
    Path(
        "tests/fixtures/release-controller-wire-v1/"
        "dpone.release-controller-runtime-closure-verification-result.v1.json"
    ),
    Path(
        "tests/fixtures/release-controller-wire-v1/"
        "dpone.release-runtime-closure-request.v1.json"
    ),
    Path(
        "tests/fixtures/release-controller-wire-v1/"
        "dpone.release-runtime-closure-stream-response.v1.headers.json"
    ),
    Path(
        "tests/fixtures/release-controller-wire-v1/"
        "dpone.release-runtime-closure-stream-response.v1.zip"
    ),
)
FORBIDDEN_SCHEMA_IDS = (
    "https://paulkov.github.io/dpone-release-controller/schemas/release/"
    "release-evidence-v2.schema.json",
)


def generated_files() -> dict[Path, bytes]:
    """Return no outputs while the public projection contract is held."""

    return {}


def check_quarantine() -> tuple[Path, ...]:
    """Return forbidden paths or schema IDs that still exist on disk."""

    stale = {path for path in FORBIDDEN_OUTPUTS if (ROOT / path).exists()}
    schema_root = ROOT / "docs/schemas"
    if schema_root.is_dir():
        for path in schema_root.rglob("*.json"):
            try:
                document = json.loads(path.read_bytes())
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                isinstance(document, dict)
                and document.get("$id") in FORBIDDEN_SCHEMA_IDS
            ):
                stale.add(path.relative_to(ROOT))
    return tuple(sorted(stale, key=lambda path: path.as_posix()))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that forbidden legacy outputs are absent",
    )
    arguments = parser.parse_args(argv)
    stale = check_quarantine()
    if stale:
        print("forbidden public closure outputs: " + ", ".join(map(str, stale)))
        return 1
    print(f"{REASON_CODE}: {REASON}")
    return 0 if arguments.check else 2


if __name__ == "__main__":
    raise SystemExit(main())
