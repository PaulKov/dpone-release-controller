"""Project the normative receipt-envelope v2 registry into public JSON Schema."""

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


def document() -> dict[str, Any]:
    """Return the validated production-owned schema registry document."""

    return registry.document()


def schema_bytes() -> bytes:
    """Return exact public projection bytes from the normative registry."""

    return registry.schema_bytes()


def managed_roots() -> tuple[ManagedRoot, ...]:
    """Return the receipt-envelope namespace inside the shared schema root."""

    return (ManagedRoot(OUTPUT.parent, MANAGED_PATTERNS),)


def generate(*, check: bool) -> int:
    """Verify or atomically update the exact receipt-envelope schema."""

    return reconcile_generated_files(
        {OUTPUT: schema_bytes()},
        managed_roots(),
        check=check,
        label="receipt envelope schema",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    return generate(check=parse_check_mode(parser, argv))


if __name__ == "__main__":
    raise SystemExit(main())
