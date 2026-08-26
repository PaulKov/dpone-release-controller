"""Stable identities and inventories shared by receipt-v2 fixtures."""

from __future__ import annotations

import hashlib
from typing import Any

from tools.evidence import release_identity


def digest(label: str) -> str:
    """Return a deterministic test-only SHA-256 identifier."""

    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


TAG = "v0.74.0"
VERSION = "0.74.0"
TAG_OBJECT_SHA = "a" * 40
COMMIT_SHA = "b" * 40
WORKFLOW_SHA = "c" * 40
ACTION_COMMIT_SHA = "d" * 40
ACTION_METADATA_BLOB_SHA = "e" * 40
ACTION_BUNDLE_SHA256 = digest("controller action bundle")
CANDIDATE_INVENTORY_SHA256 = digest("candidate inventory raw")
RELEASE_ID = release_identity.release_identity_id(TAG)
AUTHORITY_ID = release_identity.release_authority_id(
    release_identity_id=RELEASE_ID,
    tag_object_sha=TAG_OBJECT_SHA,
    peeled_commit_sha=COMMIT_SHA,
    policy_sha256=digest("policy"),
)
ATTEMPT_ID = release_identity.attempt_id(
    release_authority_id=AUTHORITY_ID,
    controller_workflow_id=316_322_127,
    controller_run_id=123_456_789,
    controller_run_attempt=2,
)
RECOVERY_ATTEMPT_ID = release_identity.attempt_id(
    release_authority_id=AUTHORITY_ID,
    controller_workflow_id=316_322_127,
    controller_run_id=223_456_789,
    controller_run_attempt=1,
)
QUEUE_ID = "sha256:" + "4" * 64
CANDIDATE_ID = release_identity.candidate_id(
    release_authority_id=AUTHORITY_ID,
    candidate_inventory_sha256=CANDIDATE_INVENTORY_SHA256,
)
LEASE_ID = "sha256:" + "6" * 64
RECOVERY_LEASE_ID = "sha256:" + "a" * 64
AUTHORIZATION_ID = "sha256:" + "7" * 64
RECOVERY_ID = "sha256:" + "8" * 64
DIST_FILES = (
    (
        "apache-airflow-providers-dpone",
        "apache_airflow_providers_dpone-0.74.0-py3-none-any.whl",
    ),
    ("apache-airflow-providers-dpone", "apache_airflow_providers_dpone-0.74.0.tar.gz"),
    ("dpone", "dpone-0.74.0-py3-none-any.whl"),
    ("dpone", "dpone-0.74.0.tar.gz"),
    ("dpone-airflow-pack", "dpone_airflow_pack-0.74.0-py3-none-any.whl"),
    ("dpone-airflow-pack", "dpone_airflow_pack-0.74.0.tar.gz"),
    ("dpone-native-accel", "dpone_native_accel-0.74.0-py3-none-any.whl"),
    ("dpone-native-accel", "dpone_native_accel-0.74.0.tar.gz"),
)


def distributions() -> list[dict[str, Any]]:
    """Return the canonical eight-file distribution inventory."""

    return [
        {
            "project": project,
            "version": VERSION,
            "filename": filename,
            "size_bytes": 100 + index,
            "sha256": digest(f"distribution/{filename}"),
        }
        for index, (project, filename) in enumerate(DIST_FILES)
    ]
