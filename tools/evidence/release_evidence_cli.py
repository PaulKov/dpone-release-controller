"""CLI for shape-B evidence store lease + attest/draft staging."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
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
store_mod = _load_sibling("dpone_agent_release_evidence_store_b2", "release_evidence_store_b2.py")
attest = _load_sibling("dpone_agent_release_attest_draft", "release_attest_draft.py")
stage = _load_sibling("dpone_agent_release_stage_draft", "release_stage_draft.py")
authorize = _load_sibling("dpone_agent_release_authorize", "release_authorize.py")
github = _load_sibling("dpone_agent_release_github_api", "release_github_api.py")

_DEFAULT_JOBS = {
    "acquire-lease": "admit-and-lease",
    "attest-draft-dry-run": "attest-and-draft",
    "stage-draft-live": "attest-and-draft",
    "authorize-publication": "authorize-publication",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    acquire = sub.add_parser("acquire-lease", help="Append LEASE_ACQUIRED to the B2 stream")
    _add_common_args(acquire)

    flow = sub.add_parser(
        "attest-draft-dry-run",
        help="Append MUTATION_INTENT→ATTESTATION→BUNDLE→DRAFT dry-run receipts",
    )
    _add_common_args(flow)
    flow.add_argument(
        "--bootstrap-dist",
        action="store_true",
        help="Use one synthetic wheel subject for bootstrap (no real artifacts)",
    )

    live = sub.add_parser(
        "stage-draft-live",
        help="Attest metadata + create real GitHub draft (no PyPI publish)",
    )
    _add_common_args(live)
    live.add_argument("--owner", default="PaulKov")
    live.add_argument("--repo", default="dpone")
    live.add_argument("--subject-file", required=True, type=Path)
    live.add_argument("--attestation-bundle", required=True, type=Path)
    live.add_argument("--attestation-url", default="")
    live.add_argument("--github-token-env", default="GITHUB_TOKEN")

    authz = sub.add_parser(
        "authorize-publication",
        help="Snapshot B bootstrap + AUTHORIZED receipt (no publish/PyPI)",
    )
    _add_common_args(authz)
    authz.add_argument("--owner", default="PaulKov")
    authz.add_argument("--repo", default="dpone")
    authz.add_argument("--github-token-env", default="GITHUB_TOKEN")
    authz.add_argument("--snapshot-gap-seconds", type=float, default=5.0)

    args = parser.parse_args(argv)
    store = _build_store(args)
    ids = _release_ids(args)
    producer = _producer(default_job=_DEFAULT_JOBS.get(args.command, args.command))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: UP017

    if args.command == "acquire-lease":
        try:
            receipt = lease.acquire_publication_lease(
                store,
                release_identity_id=ids["release_identity_id"],
                release_authority_id=ids["release_authority_id"],
                repository_id=args.repository_id,
                tag_ref=ids["tag_ref"],
                attempt_seed={
                    "run_id": int(str(producer["run_id"])),
                    "run_attempt": int(str(producer["run_attempt"])),
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

    if args.command == "attest-draft-dry-run":
        if not args.bootstrap_dist:
            parser.error("--bootstrap-dist is required until real candidate inventory wiring exists")
        distributions = [
            {
                "project": "dpone",
                "filename": f"dpone-{args.tag.removeprefix('refs/tags/')}-py3-none-any.whl",
                "size": 1,
                "sha256": "d" * 64,
            }
        ]
        try:
            result = attest.run_attest_and_draft_dry_run(
                store,
                release_identity_id=ids["release_identity_id"],
                release_authority_id=ids["release_authority_id"],
                repository_id=args.repository_id,
                tag_ref=ids["tag_ref"],
                producer=producer,
                now_utc=now,
                distributions=distributions,
                retention_days=args.retention_days,
            )
        except attest.StreamPrerequisiteError as exc:
            print(json.dumps({"status": "PREREQUISITE", "error": str(exc)}, sort_keys=True))
            return 4
        print(json.dumps(result, sort_keys=True))
        return 0

    if args.command == "stage-draft-live":
        subject_path: Path = args.subject_file
        bundle_path: Path = args.attestation_bundle
        if not subject_path.is_file():
            parser.error(f"subject file not found: {subject_path}")
        if not bundle_path.is_file():
            parser.error(f"attestation bundle not found: {bundle_path}")
        subject_bytes = subject_path.read_bytes()
        bundle_bytes = bundle_path.read_bytes()
        token = _require_env(args.github_token_env)
        api = github.GitHubApi(token=token)
        attestation = {
            "digest": "sha256:" + hashlib.sha256(bundle_bytes).hexdigest(),
            "bundle_sha256": "sha256:" + hashlib.sha256(bundle_bytes).hexdigest(),
            "bundle_bytes": len(bundle_bytes),
            "url": args.attestation_url,
            "predicate_type": "https://slsa.dev/provenance/v1",
        }
        try:
            result = stage.run_stage_draft_live(
                store,
                api,
                owner=args.owner,
                repo=args.repo,
                release_identity_id=ids["release_identity_id"],
                release_authority_id=ids["release_authority_id"],
                repository_id=args.repository_id,
                tag_ref=ids["tag_ref"],
                producer=producer,
                now_utc=now,
                subject_filename=subject_path.name,
                subject_bytes=subject_bytes,
                attestation=attestation,
                retention_days=args.retention_days,
            )
        except stage.StreamPrerequisiteError as exc:
            print(json.dumps({"status": "PREREQUISITE", "error": str(exc)}, sort_keys=True))
            return 4
        except stage.GitHubApiError as exc:
            print(json.dumps({"status": "GITHUB_ERROR", "error": str(exc)}, sort_keys=True))
            return 5
        print(json.dumps(result, sort_keys=True))
        return 0

    if args.command == "authorize-publication":
        token = _require_env(args.github_token_env)
        api = github.GitHubApi(token=token)
        try:
            result = authorize.run_authorize_publication(
                store,
                api,
                owner=args.owner,
                repo=args.repo,
                release_identity_id=ids["release_identity_id"],
                release_authority_id=ids["release_authority_id"],
                repository_id=args.repository_id,
                tag_ref=ids["tag_ref"],
                producer=producer,
                now_utc=now,
                retention_days=args.retention_days,
                snapshot_gap_seconds=args.snapshot_gap_seconds,
            )
        except authorize.StreamPrerequisiteError as exc:
            print(json.dumps({"status": "PREREQUISITE", "error": str(exc)}, sort_keys=True))
            return 4
        except authorize.AuthorizationError as exc:
            print(json.dumps({"status": "AUTHORIZATION_ERROR", "error": str(exc)}, sort_keys=True))
            return 6
        except authorize.GitHubApiError as exc:
            print(json.dumps({"status": "GITHUB_ERROR", "error": str(exc)}, sort_keys=True))
            return 5
        print(json.dumps(result, sort_keys=True))
        return 0

    parser.error(f"unsupported command {args.command}")
    return 2


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tag", required=True, help="Canonical release tag, e.g. v0.73.2")
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--ttl-seconds", type=int, default=300)
    parser.add_argument("--retention-days", type=int, default=365)
    parser.add_argument(
        "--policy-sha256",
        default="sha256:" + ("0" * 64),
        help="Frozen policy digest; bootstrap may use zeros until v2 cutover",
    )
    parser.add_argument("--tag-object-sha", default="0" * 40)
    parser.add_argument("--peeled-commit-sha", default="0" * 40)
    parser.add_argument("--dry-memory", action="store_true", help="Use in-memory store")


def _release_ids(args: argparse.Namespace) -> dict[str, Any]:
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
    return {
        "tag_ref": tag_ref,
        "release_identity_id": release_identity_id,
        "release_authority_id": release_authority_id,
    }


def _build_store(args: argparse.Namespace) -> Any:
    if args.dry_memory:
        return store_mod.InMemoryEvidenceStore()
    return store_mod.BackblazeB2EvidenceStore(
        store_mod.B2Credentials(
            key_id=_require_env("B2_APPLICATION_KEY_ID"),
            application_key=_require_env("B2_APPLICATION_KEY"),
            bucket_id=_require_env("B2_BUCKET_ID"),
            bucket_name=_require_env("B2_BUCKET_NAME"),
        )
    )


def _producer(*, default_job: str) -> dict[str, Any]:
    workflow_path = ".github/workflows/release-controller.yml"
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    if "/.github/workflows/" in workflow_ref:
        workflow_path = ".github/workflows/" + workflow_ref.split("/.github/workflows/", 1)[1].split("@", 1)[0]
    return {
        "kind": "github_actions_job",
        "repository_id": os.environ.get("GITHUB_REPOSITORY_ID", "1305993853"),
        "workflow_id": os.environ.get("DPONE_CONTROLLER_WORKFLOW_ID", "316322127"),
        "workflow_path": workflow_path,
        "workflow_sha": os.environ.get("GITHUB_SHA", "0" * 40),
        "run_id": os.environ.get("GITHUB_RUN_ID", "0"),
        "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
        "job_name": os.environ.get("GITHUB_JOB", default_job),
        "environment": os.environ.get("DPONE_CONTROLLER_ENVIRONMENT", "none"),
    }


def _require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
