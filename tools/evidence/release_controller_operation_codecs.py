"""Exact workflow step executors for every Commit-A operation profile."""

from dataclasses import replace

from tools.evidence.release_controller_operation_contract import (
    ActionCodec,
    OperationProfile,
)
from tools.evidence.release_controller_operation_factory import (
    materialization_codec,
    selector_codec,
)
from tools.evidence.release_controller_operation_admission import (
    ATTEST_CREATE,
    CANDIDATE_IMPORT,
)
from tools.evidence.release_controller_operation_lifecycle import (
    codecs as lifecycle_codecs,
)
from tools.evidence.release_controller_operation_draft import DRAFT_STAGE
from tools.evidence.release_controller_operation_publication import (
    codecs as publication_codecs,
)
from tools.evidence.release_controller_operation_static import (
    OPERATIONS as STATIC_OPERATIONS,
)


def build() -> tuple[ActionCodec, ...]:
    """Return a closed, ordered codec table with no route-derived fallback."""

    return (
        selector_codec(
            "attest-create",
            "attest-create",
            tuple(call.phase for call in ATTEST_CREATE.ordered_calls),
        ),
        materialization_codec(
            "candidate-import",
            "candidate-import",
            tuple(call.phase for call in CANDIDATE_IMPORT.ordered_calls),
        ),
        selector_codec(
            "draft-stage",
            "draft-stage",
            tuple(call.phase for call in DRAFT_STAGE.ordered_calls),
        ),
        *lifecycle_codecs(),
        *publication_codecs(),
        *(_static_codec(profile) for profile in STATIC_OPERATIONS),
    )


def _static_codec(profile: OperationProfile) -> ActionCodec:
    """Expose the recovery phase only as a non-authoritative scheduling hint."""

    codec = selector_codec(
        profile.operation_id,
        profile.operation_id,
        tuple(call.phase for call in profile.ordered_calls),
    )
    if profile.operation_id != "recovery":
        return codec
    return replace(
        codec,
        output_names=("resume_phase",),
        output_authority="UX_HINT_ONLY",
    )


ACTION_CODECS = build()
