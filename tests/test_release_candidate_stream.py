"""Closed request/header/body tests for the private candidate stream."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tests.release_candidate_handoff_test_support import write_candidate
from tests.test_release_candidate_provider import (
    FROZEN_NOW,
    _binding,
    _observation,
    _zip_tree,
)
from tools.evidence.release_candidate_contract import CandidateHandoffError
from tools.evidence.release_candidate_stream import (
    CONTENT_TYPE,
    CandidateReaderAuthority,
    CandidateStreamRequest,
)
from tools.evidence.release_candidate_stream_golden import golden_bytes
from tools.evidence.release_candidate_stream_response import (
    open_candidate_stream,
    response_headers,
)

AUTHORITY = CandidateReaderAuthority(
    service_identity=(
        "cloudflare-worker:account-01/dpone-release-candidate-reader@candidate-reader-version-01"
    ),
    service_version_id="candidate-reader-version-01",
)
FIXTURE = Path("tests/fixtures/release-candidate-stream-v1.json")


class MemoryResponse:
    """Deterministic one-shot HTTP response fixture."""

    status_code = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.observation = _observation(body)
        self.headers = response_headers(self.observation)

    def chunks(self, *, maximum_bytes: int):
        for offset in range(0, len(self.body), 97):
            yield self.body[offset : offset + 97]


class CandidateStreamTests(unittest.TestCase):
    def test_cross_language_fixture_is_current(self) -> None:
        self.assertEqual(FIXTURE.read_bytes(), golden_bytes())

    def test_request_has_only_frozen_candidate_selectors(self) -> None:
        body = _raw_zip()
        request = CandidateStreamRequest.from_binding(_binding(body)).document()
        self.assertEqual(
            set(request),
            {
                "schema",
                "schema_version",
                "tag",
                "expected_peeled_commit_sha",
                "candidate_run_id",
                "candidate_run_attempt",
                "candidate_artifact_id",
                "candidate_artifact_digest",
            },
        )
        self.assertNotIn("tag_object_sha", request)
        self.assertNotIn("policy_sha256", request)
        self.assertNotIn("candidate_id", request)

    def test_headers_are_verified_before_one_shot_body_stream(self) -> None:
        body = _raw_zip()
        response = MemoryResponse(body)
        stream = open_candidate_stream(
            response,
            _binding(body),
            expected_request_id=response.observation.broker_request_id,
            authority=AUTHORITY,
            now=FROZEN_NOW,
        )
        received = b"".join(stream.chunks(maximum_bytes=len(body)))
        self.assertEqual(
            hashlib.sha256(received).digest(), hashlib.sha256(body).digest()
        )
        with self.assertRaisesRegex(CandidateHandoffError, "already consumed"):
            list(stream.chunks(maximum_bytes=len(body)))

    def test_no_redirect_url_or_credential_leaves_the_broker(self) -> None:
        body = _raw_zip()
        headers = response_headers(_observation(body))
        rendered = "\n".join(f"{key}:{value}" for key, value in headers.items())
        self.assertNotIn("source-url", rendered.lower())
        self.assertNotIn("https://", rendered)
        self.assertEqual(headers["content-type"], CONTENT_TYPE)

    def test_status_header_authority_and_digest_drift_fail_closed(self) -> None:
        body = _raw_zip()
        cases = {
            "status": ("status_code", 206),
            "request": ("x-dpone-request-id", "another-request"),
            "service": (
                "x-dpone-candidate-reader-service-version-id",
                "another-version",
            ),
            "content-type": ("content-type", "application/zip"),
            "content-length": ("content-length", str(len(body) + 1)),
            "digest": (
                "x-dpone-provider-observation-sha256",
                "sha256:" + ("0" * 64),
            ),
            "redirect": ("location", "https://example.invalid/private"),
            "extra-app-header": ("x-dpone-unreviewed", "true"),
        }
        for name, (key, value) in cases.items():
            with self.subTest(name=name):
                response = MemoryResponse(body)
                if key == "status_code":
                    response.status_code = value
                else:
                    response.headers[key] = value
                with self.assertRaises(CandidateHandoffError):
                    open_candidate_stream(
                        response,
                        _binding(body),
                        expected_request_id=response.observation.broker_request_id,
                        authority=AUTHORITY,
                        now=FROZEN_NOW,
                    )

    def test_truncated_and_oversized_body_fail_during_stream(self) -> None:
        body = _raw_zip()
        for replacement in (body[:-1], body + b"x"):
            with self.subTest(size=len(replacement)):
                response = MemoryResponse(body)
                response.body = replacement
                stream = open_candidate_stream(
                    response,
                    _binding(body),
                    expected_request_id=response.observation.broker_request_id,
                    authority=AUTHORITY,
                    now=FROZEN_NOW,
                )
                with self.assertRaises(CandidateHandoffError):
                    b"".join(stream.chunks(maximum_bytes=len(body)))


def _raw_zip() -> bytes:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        write_candidate(root)
        return _zip_tree(root)


if __name__ == "__main__":
    unittest.main()
