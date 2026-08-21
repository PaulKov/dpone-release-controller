#!/usr/bin/env python3
"""Validate or canonicalize the checked public receipt-envelope v2 schema.

This command is intentionally not a schema generator.  The checked JSON
Schema is the language-neutral structural contract authority; the contract
registry binds its digest and the Python registry validates its closed shape.
``--check`` is read-only, while ``--write`` rewrites only that already-valid
document into canonical JSON bytes.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_generator_support import (  # noqa: E402
    ManagedRoot,
    parse_check_mode,
    reconcile_generated_files,
)
from tools.evidence import release_receipt_schema_registry as registry  # noqa: E402

OUTPUT = ROOT / "docs/schemas/release/release-receipt-envelope-v2.schema.json"
MANAGED_PATTERNS = ("release-receipt-envelope-*.schema.json",)


def validated_document() -> dict[str, Any]:
    """Return a validated copy of the checked public schema authority."""

    return registry.document()


def canonical_schema_bytes() -> bytes:
    """Return canonical bytes of the validated checked public schema."""

    return registry.schema_bytes()


def managed_roots() -> tuple[ManagedRoot, ...]:
    """Return the receipt-envelope namespace inside the shared schema root."""

    return (ManagedRoot(OUTPUT.parent, MANAGED_PATTERNS),)


def reconcile(*, check: bool) -> int:
    """Check or canonicalize the exact receipt-envelope schema inventory."""

    return reconcile_generated_files(
        {OUTPUT: canonical_schema_bytes()},
        managed_roots(),
        check=check,
        label="checked receipt envelope schema",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    return reconcile(check=parse_check_mode(parser, argv))


if __name__ == "__main__":
    raise SystemExit(main())
