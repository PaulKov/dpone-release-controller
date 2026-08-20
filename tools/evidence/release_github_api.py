"""Quarantined pre-broker GitHub client.

Provider reads and mutations now use split App identities behind exact broker
routes with API version 2026-03-10; Actions never receives an App credential.
"""

from __future__ import annotations

from typing import Any, Never

from tools.evidence.release_legacy_writer_guard import disabled


class GitHubApiError(RuntimeError):
    """Retained only for dormant import compatibility."""


class GitHubApi:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        disabled("legacy GitHub API client")


def ensure_lightweight_tag(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("controller tag creation")


def resolve_default_branch_sha(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy GitHub provider read")


def get_release(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy GitHub release read")


def create_or_get_draft_release(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy GitHub draft mutation")


def upload_release_asset(*args: Any, **kwargs: Any) -> Never:
    del args, kwargs
    return disabled("legacy GitHub asset mutation")
