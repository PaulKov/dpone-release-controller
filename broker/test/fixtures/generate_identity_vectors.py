#!/usr/bin/env python3
"""Generate the cross-language release identity fixture with CPython bytes."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def identity(domain: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = {"domain": domain, "payload": payload}
    return {
        "domain": domain,
        "id": "sha256:" + hashlib.sha256(canonical(body)).hexdigest(),
        "payload": payload,
    }


release = identity(
    "dpone.release.identity.v2",
    {
        "repository_id": 1_255_975_556,
        "release": "v0.74.0",
        "projects": [
            "apache-airflow-providers-dpone",
            "dpone",
            "dpone-airflow-pack",
            "dpone-native-accel",
        ],
    },
)
authority = identity(
    "dpone.release.authority.v2",
    {
        "release_identity_id": release["id"],
        "tag_object_sha": "a" * 40,
        "peeled_commit_sha": "b" * 40,
        "policy_sha256": "sha256:" + "c" * 64,
        "protected_base_ref": "refs/heads/master",
    },
)
attempt = identity(
    "dpone.release.attempt.v2",
    {
        "release_authority_id": authority["id"],
        "controller_repository_id": 1_305_993_853,
        "controller_workflow_id": 316_322_127,
        "controller_run_id": 9_876_543_210,
        "controller_run_attempt": 2,
    },
)
candidate = identity(
    "dpone.release.candidate.v2",
    {
        "release_authority_id": authority["id"],
        "candidate_inventory_sha256": "sha256:" + "d" * 64,
    },
)
print(
    json.dumps(
        {
            "schema": "dpone.release-identity-golden-v1",
            "release": release,
            "authority": authority,
            "attempt": attempt,
            "candidate": candidate,
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
)
