"""Canonical cross-language vector for the candidate broker stream."""

from __future__ import annotations

from typing import Any

from tools.evidence.release_candidate_provider import ProviderArtifactObservation
from tools.evidence.release_candidate_stream import (
    METHOD,
    PATH,
    CandidateStreamRequest,
)
from tools.evidence.release_candidate_stream_response import response_headers
from tools.evidence.release_canonical import canonical_json_bytes

SCHEMA = "dpone.release-candidate-stream-contract-vector.v1"


def document(
    request: CandidateStreamRequest,
    observation: ProviderArtifactObservation,
) -> dict[str, Any]:
    """Return exact request/body and normalized response-header examples."""

    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "request": {
            "method": METHOD,
            "path": PATH,
            "headers": {
                "accept": ("application/vnd.dpone.release-candidate-artifact.v1+zip"),
                "content-type": "application/json",
                "x-request-id": observation.broker_request_id,
                "authorization": "Bearer <fresh OIDC; never persisted>",
            },
            "body": request.document(),
            "replay": {
                "oidc_jti_single_use": True,
                "response_body_single_use": True,
                "network_retry_requires_fresh_oidc_and_request_id": True,
            },
        },
        "response": {
            "status": 200,
            "headers": response_headers(observation),
            "body": "raw GitHub Actions artifact ZIP byte stream",
            "raw_url_exposed": False,
        },
    }


def encoded(
    request: CandidateStreamRequest,
    observation: ProviderArtifactObservation,
) -> bytes:
    """Return exact vector bytes shared with the private broker."""

    return canonical_json_bytes(document(request, observation))
