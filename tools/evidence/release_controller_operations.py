"""Public facade for the modular Commit-A operation profile.

Definitions are split by bounded domain so changes to draft recovery, package
publication, closure, or generic admission cannot silently expand another
operation's authority.
"""

from tools.evidence.release_controller_operation_admission import (
    ATTEST_CREATE,
    CANDIDATE_IMPORT,
)
from tools.evidence.release_controller_operation_lifecycle import (
    LEASE_ACQUIRE,
    LEASE_SENTINEL,
    RECOVERY_LEASE_ACQUIRE,
    TERMINAL_ASSERT,
)
from tools.evidence.release_controller_operation_codecs import ACTION_CODECS
from tools.evidence.release_controller_operation_draft import DRAFT_STAGE
from tools.evidence.release_controller_operation_factory import (
    BROKER_ACTION_REF,
    CANDIDATE_ADMIT_PATH,
    LEASE_ACTION_REF,
    LOCAL_CANDIDATE_VERIFIER,
    MATERIALIZATION_INPUTS,
    PYPI_ACTION,
    PYPI_ACTION_REF,
    SCHEMA,
    SCHEMA_VERSION,
)
from tools.evidence.release_controller_operation_publication import (
    GITHUB_PUBLISH,
    PYPI_OBSERVE,
    PYPI_PREPARE,
    PYPI_PUBLISH,
)
from tools.evidence.release_controller_operation_static import (
    OPERATIONS as STATIC_OPERATIONS,
)
from tools.evidence.release_controller_operation_validator import (
    OperationProfileError,
    validate as _validate,
)

OPERATIONS = (
    ATTEST_CREATE,
    CANDIDATE_IMPORT,
    DRAFT_STAGE,
    GITHUB_PUBLISH,
    LEASE_ACQUIRE,
    LEASE_SENTINEL,
    RECOVERY_LEASE_ACQUIRE,
    PYPI_OBSERVE,
    PYPI_PREPARE,
    PYPI_PUBLISH,
    TERMINAL_ASSERT,
    *STATIC_OPERATIONS,
)
OPERATION_BY_ID = {profile.operation_id: profile for profile in OPERATIONS}
ACTION_CODECS_BY_OPERATION = {
    operation_id: tuple(
        codec for codec in ACTION_CODECS if codec.operation_id == operation_id
    )
    for operation_id in OPERATION_BY_ID
}


def validate() -> None:
    """Validate the current facade tables, including patched audit copies."""

    _validate(OPERATIONS, ACTION_CODECS)


validate()

__all__ = [
    "ACTION_CODECS",
    "ACTION_CODECS_BY_OPERATION",
    "ATTEST_CREATE",
    "BROKER_ACTION_REF",
    "CANDIDATE_ADMIT_PATH",
    "CANDIDATE_IMPORT",
    "DRAFT_STAGE",
    "GITHUB_PUBLISH",
    "LEASE_ACQUIRE",
    "LEASE_ACTION_REF",
    "LEASE_SENTINEL",
    "LOCAL_CANDIDATE_VERIFIER",
    "MATERIALIZATION_INPUTS",
    "OPERATIONS",
    "OPERATION_BY_ID",
    "OperationProfileError",
    "PYPI_ACTION",
    "PYPI_ACTION_REF",
    "PYPI_OBSERVE",
    "PYPI_PREPARE",
    "PYPI_PUBLISH",
    "TERMINAL_ASSERT",
    "RECOVERY_LEASE_ACQUIRE",
    "SCHEMA",
    "SCHEMA_VERSION",
    "validate",
]
