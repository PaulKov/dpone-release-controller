#!/usr/bin/env python3
"""Generate exact schemas and positive bytes for Commit-A JSON codecs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.evidence.release_controller_wire_catalog import JSON_CODECS  # noqa: E402
from tools.evidence.release_controller_schema_registry import (  # noqa: E402
    DELEGATED,
)
from tools.evidence import release_controller_wire_vectors as wire_vectors  # noqa: E402
from scripts.release_generator_support import (  # noqa: E402
    ManagedRoot,
    parse_check_mode,
    reconcile_generated_files,
)

SCHEMA_ROOT = ROOT / "docs/schemas/release-controller-wire-v1"
GOLDEN_ROOT = ROOT / "tests/fixtures/release-controller-wire-v1"


def generated_files() -> dict[Path, bytes]:
    """Return all deterministic outputs without touching the filesystem."""

    result: dict[Path, bytes] = {}
    for codec in JSON_CODECS:
        filename = f"{codec.schema_id}.json"
        schema_bytes = (
            json.dumps(codec.json_schema(), indent=2, sort_keys=True) + "\n"
        ).encode()
        result[SCHEMA_ROOT / filename] = schema_bytes
        result[GOLDEN_ROOT / filename] = codec.golden_bytes()
    for codec in DELEGATED:
        schema_bytes = (
            json.dumps(codec.schema_document(), indent=2, sort_keys=True) + "\n"
        ).encode()
        result[SCHEMA_ROOT / f"{codec.schema_id}.json"] = schema_bytes
    result.update(
        {
            GOLDEN_ROOT / name: body
            for name, body in wire_vectors.reference_files().items()
        }
    )
    return result


def generate(*, check: bool) -> int:
    """Verify or atomically update both exact wire-contract roots."""

    return reconcile_generated_files(
        generated_files(),
        managed_roots(),
        check=check,
        label="controller wire contracts",
    )


def managed_roots() -> tuple[ManagedRoot, ...]:
    """Return dedicated roots whose complete file inventories are generated."""

    return (ManagedRoot(SCHEMA_ROOT), ManagedRoot(GOLDEN_ROOT))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    return generate(check=parse_check_mode(parser, argv))


if __name__ == "__main__":
    raise SystemExit(main())
