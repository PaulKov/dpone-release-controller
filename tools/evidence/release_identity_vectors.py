"""Generate the one shared positive cross-language release identity vector."""

from __future__ import annotations

import json
import sys
from typing import Any, Mapping

from tools.evidence import release_identity as identity
from tools.evidence.release_canonical import sha256_id

SCHEMA = "dpone.release-identity-golden-v1"
FIXTURE_CONTROLLER_WORKFLOW_ID = 316_322_127


def build_vectors() -> dict[str, Any]:
    """Return the exact positive payloads consumed by Python and TypeScript."""

    release = "v0.74.0"
    release_id = identity.release_identity_id(release)
    authority_payload = identity.release_authority_payload(
        release_identity_id=release_id,
        tag_object_sha="a" * 40,
        peeled_commit_sha="b" * 40,
        policy_sha256="sha256:" + ("c" * 64),
    )
    authority_id = sha256_id(identity.RELEASE_AUTHORITY_DOMAIN, authority_payload)
    candidate_payload = identity.candidate_payload(
        release_authority_id=authority_id,
        candidate_inventory_sha256="sha256:" + ("d" * 64),
    )
    attempt_payload = identity.attempt_payload(
        release_authority_id=authority_id,
        controller_workflow_id=FIXTURE_CONTROLLER_WORKFLOW_ID,
        controller_run_id=9_876_543_210,
        controller_run_attempt=2,
    )
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "release": _vector(
            identity.RELEASE_IDENTITY_DOMAIN,
            identity.release_identity_payload(release),
        ),
        "authority": _vector(identity.RELEASE_AUTHORITY_DOMAIN, authority_payload),
        "candidate": _vector(identity.CANDIDATE_DOMAIN, candidate_payload),
        "attempt": _vector(identity.ATTEMPT_DOMAIN, attempt_payload),
    }


def _vector(domain: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "domain": domain,
        "id": sha256_id(domain, payload),
        "payload": dict(payload),
    }


def fixture_bytes() -> bytes:
    """Encode stable reviewable bytes; IDs hash compact canonical JSON."""

    return (
        json.dumps(build_vectors(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def main() -> int:
    sys.stdout.buffer.write(fixture_bytes())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
