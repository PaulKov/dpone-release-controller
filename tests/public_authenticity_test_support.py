"""Shared synthetic inputs for public-authenticity unit tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from tools.public_authenticity.verifier import (
    PublicAuthenticityPolicy,
)


class PublicAuthenticityFixtureMixin:
    """Create synthetic files and a closed policy without live credentials."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact = self._write("closure.zip", b"public-archive")
        self.bundle = self._write("bundle.jsonl", b"signed-bundle")
        self.trusted_root = self._write("trusted-root.jsonl", b"trusted-root")
        self.gh = self._write("gh", b"pinned-gh-binary")
        self.gh.chmod(0o700)
        self.policy = PublicAuthenticityPolicy(
            artifact_sha256=hashlib.sha256(b"public-archive").hexdigest(),
            bundle_sha256=hashlib.sha256(b"signed-bundle").hexdigest(),
            trusted_root_sha256=hashlib.sha256(b"trusted-root").hexdigest(),
            repository="PaulKov/dpone-release-controller",
            signer_workflow=(
                "PaulKov/dpone-release-controller/.github/workflows/"
                "release-controller.yml"
            ),
            signer_digest="a" * 40,
            source_digest="b" * 40,
            source_ref="refs/tags/v1.2.3",
            gh_binary_sha256=hashlib.sha256(b"pinned-gh-binary").hexdigest(),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, name: str, body: bytes) -> Path:
        path = self.root / name
        path.write_bytes(body)
        return path

    @staticmethod
    def _success_output() -> bytes:
        return json.dumps(
            [
                {
                    "attestation": {
                        "mediaType": (
                            "application/vnd.dev.sigstore.bundle+json;version=0.3"
                        )
                    },
                    "verificationResult": {
                        "signature": {
                            "certificate": {
                                "buildSignerDigest": "a" * 40,
                                "issuer": "https://token.actions.githubusercontent.com",
                                "runnerEnvironment": "github-hosted",
                                "sourceRepositoryDigest": "b" * 40,
                                "sourceRepositoryOwnerURI": (
                                    "https://github.com/PaulKov"
                                ),
                                "sourceRepositoryRef": "refs/tags/v1.2.3",
                                "sourceRepositoryURI": (
                                    "https://github.com/PaulKov/"
                                    "dpone-release-controller"
                                ),
                                "subjectAlternativeName": (
                                    "https://github.com/PaulKov/"
                                    "dpone-release-controller/.github/workflows/"
                                    "release-controller.yml@refs/tags/v1.2.3"
                                ),
                            }
                        },
                        "statement": {
                            "predicateType": "https://slsa.dev/provenance/v1",
                            "subject": [
                                {
                                    "digest": {
                                        "sha256": hashlib.sha256(
                                            b"public-archive"
                                        ).hexdigest()
                                    },
                                    "name": "public-closure.zip",
                                }
                            ],
                        },
                        "verifiedIdentity": {
                            "issuer": {"issuer": "", "regexp": ".*"},
                            "runnerEnvironment": "github-hosted",
                            "subjectAlternativeName": {
                                "subjectAlternativeName": (
                                    "https://github.com/PaulKov/"
                                    "dpone-release-controller/.github/workflows/"
                                    "release-controller.yml@refs/tags/v1.2.3"
                                )
                            },
                        },
                        "verifiedTimestamps": [
                            {
                                "timestamp": "2026-08-21T00:00:00Z",
                                "type": "Tlog",
                                "uri": "https://rekor.sigstore.dev/log/1",
                            }
                        ],
                    },
                }
            ],
            separators=(",", ":"),
        ).encode()
