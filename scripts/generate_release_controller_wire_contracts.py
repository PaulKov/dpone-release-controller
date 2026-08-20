#!/usr/bin/env python3
"""Generate exact schemas and positive bytes for Commit-A JSON codecs."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.evidence.release_controller_wire_catalog import JSON_CODECS  # noqa: E402
from tools.evidence.release_controller_schema_registry import (  # noqa: E402
    DELEGATED,
)
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
    result.update(_delegated_goldens())
    return result


def _delegated_goldens() -> dict[Path, bytes]:
    """Build contextual/binary bytes through their production reference builders."""

    from tests.release_candidate_handoff_test_support import write_candidate
    from tests.test_release_candidate_provider import (
        FROZEN_CLOCK,
        _binding,
        _observation,
        _zip_tree,
    )
    from tests.test_release_controller_exchange import _receipt
    from tests.test_release_controller_preflight import _proof_exchange
    from tools.evidence import release_candidate_stream as candidate_stream
    from tools.evidence import release_candidate_stream_golden as candidate_golden
    from tools.evidence import release_candidate_stream_response as candidate_response
    from tools.evidence import release_controller_activation_proof as activation
    from tools.evidence import release_controller_exchange as exchange
    from tools.evidence.release_candidate_handoff import import_provider_candidate
    from tools.evidence.release_canonical import canonical_json_bytes

    result = {
        GOLDEN_ROOT / f"{activation.REQUEST_SCHEMA}.json": activation.request_bytes(),
        GOLDEN_ROOT
        / f"{activation.RESPONSE_SCHEMA}.json": _proof_exchange().response_bytes,
        GOLDEN_ROOT
        / f"{candidate_stream.REQUEST_SCHEMA}.json": candidate_golden.request().encoded(),
    }
    with tempfile.TemporaryDirectory() as directory:
        workspace = Path(directory)
        producer = workspace / "producer"
        producer.mkdir()
        write_candidate(producer)
        raw_zip = _zip_tree(producer)
        observation = _observation(raw_zip)
        imported = import_provider_candidate(
            _MemorySource(raw_zip),
            observation,
            _binding(raw_zip),
            workspace / "candidate",
            clock=FROZEN_CLOCK,
        )
        request_data = exchange.candidate_admit_request_bytes(imported)
        request = exchange.parse_candidate_admit_request(
            request_data, now=FROZEN_CLOCK.now()
        )
        response_data = exchange.candidate_admit_response_bytes(
            _receipt(request), expected=request
        )
        result.update(
            {
                GOLDEN_ROOT / f"{candidate_stream.RESPONSE_SCHEMA}.zip": raw_zip,
                GOLDEN_ROOT
                / f"{candidate_stream.RESPONSE_SCHEMA}.headers.json": canonical_json_bytes(
                    candidate_response.response_headers(observation)
                ),
                GOLDEN_ROOT
                / f"{exchange.CANDIDATE_ADMIT_REQUEST_SCHEMA}.json": request_data,
                GOLDEN_ROOT
                / f"{exchange.CANDIDATE_ADMIT_RESPONSE_SCHEMA}.json": response_data,
            }
        )
    return result


class _MemorySource:
    """One-shot deterministic provider archive source for golden generation."""

    def __init__(self, body: bytes) -> None:
        self.body = body

    def chunks(self, *, maximum_bytes: int):
        if len(self.body) > maximum_bytes:
            raise ValueError("golden provider body exceeds requested bound")
        yield self.body


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
