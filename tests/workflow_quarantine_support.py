"""Small structural helpers for the checked GitHub Actions quarantine contract."""

from __future__ import annotations

import re


def exact_workflow_job(text: str, job_id: str) -> str:
    """Return one top-level job block, rejecting plain or quoted duplicate IDs."""

    lines = text.splitlines(keepends=True)
    escaped_job_id = re.escape(job_id)
    job_id_declaration = re.compile(
        rf"^  (?:{escaped_job_id}|'(?:{escaped_job_id})'|\"(?:{escaped_job_id})\")"
        r"\s*:[^\n]*(?:\n)?$"
    )
    starts = [
        index for index, line in enumerate(lines) if job_id_declaration.fullmatch(line)
    ]
    if len(starts) != 1:
        raise AssertionError(
            f"expected exactly one active {job_id!r} job, found {len(starts)}"
        )

    start = starts[0]
    end = len(lines)
    top_level_job = re.compile(
        r"^  (?:[A-Za-z0-9_-]+|'[A-Za-z0-9_-]+'|\"[A-Za-z0-9_-]+\")"
        r"\s*:[^\n]*(?:\n)?$"
    )
    for index in range(start + 1, len(lines)):
        if top_level_job.fullmatch(lines[index]):
            end = index
            break
    return "".join(lines[start:end])
