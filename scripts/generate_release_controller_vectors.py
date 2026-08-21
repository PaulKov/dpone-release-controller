#!/usr/bin/env python3
"""Atomically regenerate reviewed controller/broker contract fixtures."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_generator_support import (  # noqa: E402
    ManagedRoot,
    parse_check_mode,
    reconcile_generated_files,
)

OUTPUTS: dict[Path, Callable[[], bytes]] = {
    Path("tests/fixtures/release-controller-route-profile-v1.json"): (
        lambda: _encoded("route")
    ),
    Path("tests/fixtures/release-controller-operation-profile-v2.json"): (
        lambda: _encoded("operation")
    ),
    Path(
        "tests/fixtures/release-controller-required-provider-profile-v1.json"
    ): lambda: _encoded("provider"),
    Path("tests/fixtures/release-candidate-stream-v1.json"): (
        lambda: _encoded("candidate")
    ),
}
MANAGED_PATTERNS = (
    "release-candidate-stream-*.json",
    "release-controller-operation-profile-*.json",
    "release-controller-required-provider-profile-*.json",
    "release-controller-route-profile-*.json",
)


def _encoded(name: str) -> bytes:
    if name == "route":
        from tools.evidence.release_controller_route_vectors import encoded
    elif name == "operation":
        from tools.evidence.release_controller_operation_vectors import encoded
    elif name == "provider":
        from tools.evidence.release_controller_provider_vectors import encoded
    else:
        from tools.evidence.release_candidate_stream_golden import (
            golden_bytes as encoded,
        )
    return encoded()


def generated_files() -> dict[Path, bytes]:
    """Return every deterministic controller vector keyed by absolute path."""

    return {ROOT / relative: producer() for relative, producer in OUTPUTS.items()}


def managed_roots() -> tuple[ManagedRoot, ...]:
    """Return vector-owned namespaces inside the shared fixture directory."""

    return (ManagedRoot(ROOT / "tests/fixtures", MANAGED_PATTERNS),)


def generate(*, check: bool) -> int:
    """Verify or atomically update the exact managed controller vectors."""

    return reconcile_generated_files(
        generated_files(),
        managed_roots(),
        check=check,
        label="controller vectors",
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    return generate(check=parse_check_mode(parser, argv))


if __name__ == "__main__":
    raise SystemExit(main())
