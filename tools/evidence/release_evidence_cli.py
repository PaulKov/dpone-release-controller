"""CLI for shape-B evidence store lease acquire (controller composition root)."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _load_sibling(module_name: str, filename: str) -> Any:
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


canonical = _load_sibling("dpone_agent_release_canonical", "release_canonical.py")
lease = _load_sibling("dpone_agent_release_lease_service", "release_lease_service.py")
store_mod = _load_sibling(
    "dpone_agent_release_evidence_store_b2", "release_evidence_store_b2.py"
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    acquire = sub.add_parser("acquire-lease", help="Append LEASE_ACQUIRED to the B2 stream")
    acquire.add_argument("--tag", required=True, help="Canonical release tag, e.g. v0.73.2")
    acquire.add_argument("--repository-id", required=True, type=int)
    acquire.add_argument("--ttl-seconds", type=int, default=300)
    acquire.add_argument("--retention-days", type=int, default=365)
    acquire.add_argument(
        "--policy-sha256",
        default="sha256:" + ("0" * 64),
        help="Frozen policy digest; bootstrap may use zeros until v2 cutover",
    )
    acquire.add_argument("--tag-object-sha", default="0" * 40)
    acquire.add_argument("--peeled-commit-sha", default="0" * 40)
    acquire.add_argument("--dry-memory", action="store_true", help="Use in-memory store")
    args = parser.parse_args(argv)

    if args.command != "acquire-lease":
        parser.error(f"unsupported command {args.command}")
        return 2

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    tag_ref = args.tag if args.tag.startswith("refs/tags/") else f"refs/tags/{args.tag}"
    release_identity_id = canonical.sha256_id(
        "dpone.release.identity.v2",
        {
            "repository_id": args.repository_id,
            "tag": args.tag.removeprefix("refs/tags/"),
            "projects": [
                "dpone",
                "dpone-native-accel",
                "dpone-airflow-pack",
                "apache-airflow-providers-dpone",
            ],
        },
    )
    release_authority_id = canonical.sha256_id(
        "dpone.release.authority.v2",
        {
            "release_id": release_identity_id,
            "tag_object_sha": args.tag_object_sha,
            "peeled_commit_sha": args.peeled_commit_sha,
            "policy_sha256": args.policy_sha256,
            "protected_base_ref": "refs/heads/master",
        },
    )
    workflow_path = ".github/workflows/release-controller.yml"
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    if "/.github/workflows/" in workflow_ref:
        workflow_path = ".github/workflows/" + workflow_ref.split("/.github/workflows/", 1)[1].split(
            "@", 1
        )[0]
    producer = {
        "kind": "github_actions_job",
        "repository_id": os.environ.get("GITHUB_REPOSITORY_ID", "1305993853"),
        "workflow_id": os.environ.get("DPONE_CONTROLLER_WORKFLOW_ID", "316322127"),
        "workflow_path": workflow_path,
        "workflow_sha": os.environ.get("GITHUB_SHA", "0" * 40),
        "run_id": os.environ.get("GITHUB_RUN_ID", "0"),
        "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
        "job_name": os.environ.get("GITHUB_JOB", "admit-and-lease"),
        "environment": os.environ.get("DPONE_CONTROLLER_ENVIRONMENT", "none"),
    }

    store: Any
    if args.dry_memory:
        store = store_mod.InMemoryEvidenceStore()
    else:
        store = store_mod.BackblazeB2EvidenceStore(
            store_mod.B2Credentials(
                key_id=_require_env("B2_APPLICATION_KEY_ID"),
                application_key=_require_env("B2_APPLICATION_KEY"),
                bucket_id=_require_env("B2_BUCKET_ID"),
                bucket_name=_require_env("B2_BUCKET_NAME"),
            )
        )

    try:
        receipt = lease.acquire_publication_lease(
            store,
            release_identity_id=release_identity_id,
            release_authority_id=release_authority_id,
            repository_id=args.repository_id,
            tag_ref=tag_ref,
            attempt_seed={
                "run_id": int(producer["run_id"]),
                "run_attempt": int(producer["run_attempt"]),
            },
            producer=producer,
            ttl_seconds=args.ttl_seconds,
            now_utc=now,
            retention_days=args.retention_days,
        )
    except lease.LeaseConflictError as exc:
        print(json.dumps({"status": "CONFLICT", "error": str(exc)}, sort_keys=True))
        return 3

    print(json.dumps({"status": "LEASE_ACQUIRED", "receipt": receipt}, sort_keys=True))
    return 0


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
