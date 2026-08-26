#!/usr/bin/env python3
"""Generate the closed JSON Schema for the Commit-A executable inventory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.evidence import release_controller_action_bundle as bundle  # noqa: E402
from scripts.release_generator_support import (  # noqa: E402
    ManagedRoot,
    parse_check_mode,
    reconcile_generated_files,
)

OUTPUT = ROOT / "docs/schemas/release/release-controller-action-bundle-v1.schema.json"
MANAGED_PATTERNS = ("release-controller-action-bundle-*.schema.json",)


def schema_document() -> dict[str, Any]:
    """Return a schema whose prefix items close every executable path."""

    git_sha = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
    digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    member: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "path",
            "mode",
            "size_bytes",
            "git_blob_sha",
            "sha256",
        ],
        "properties": {
            "path": {"type": "string"},
            "mode": {"const": "100644"},
            "size_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": bundle.MAX_MEMBER_BYTES,
            },
            "git_blob_sha": git_sha,
            "sha256": digest,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://paulkov.github.io/dpone-release-controller/schemas/release/"
            "release-controller-action-bundle-v1.schema.json"
        ),
        "title": "dpone release controller Commit-A executable inventory v1",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema",
            "schema_version",
            "repository",
            "repository_id",
            "commit_sha",
            "members",
        ],
        "properties": {
            "schema": {"const": bundle.SCHEMA},
            "schema_version": {"const": bundle.SCHEMA_VERSION},
            "repository": {"const": bundle.REPOSITORY},
            "repository_id": {"const": bundle.REPOSITORY_ID},
            "commit_sha": git_sha,
            "members": {
                "type": "array",
                "minItems": len(bundle.EXECUTABLE_PATHS),
                "maxItems": len(bundle.EXECUTABLE_PATHS),
                "prefixItems": [
                    _member_at(member, path) for path in bundle.EXECUTABLE_PATHS
                ],
                "items": False,
            },
        },
    }


def generated_bytes() -> bytes:
    """Return stable human-reviewable schema bytes."""

    return (json.dumps(schema_document(), indent=2, sort_keys=True) + "\n").encode()


def managed_roots() -> tuple[ManagedRoot, ...]:
    """Return the action-schema namespace inside the shared schema directory."""

    return (ManagedRoot(OUTPUT.parent, MANAGED_PATTERNS),)


def generate(*, check: bool) -> int:
    """Verify or atomically update the exact managed action schema."""

    return reconcile_generated_files(
        {OUTPUT: generated_bytes()},
        managed_roots(),
        check=check,
        label="controller action schema",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    return generate(check=parse_check_mode(parser, argv))


def _member_at(member: Mapping[str, Any], path: str) -> dict[str, Any]:
    return {"allOf": [dict(member), {"properties": {"path": {"const": path}}}]}


if __name__ == "__main__":
    raise SystemExit(main())
