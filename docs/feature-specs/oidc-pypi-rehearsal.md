# OIDC PyPI release rehearsal

## Status

**APPROVED — backlog implementation, 2026-08-26.**

## Scope

The controller adds a manual, no-publish rehearsal for an existing annotated
dpone tag. It checks out the immutable tag, builds exactly four projects and
eight archives, seals a SHA-256 inventory, redownloads that artifact, and
performs a fresh wheel installation plus `pip check` and `dpone --help`.

It has no `id-token: write`, no environment, no PyPI endpoint, no token, and
no mutation outside GitHub Actions artifacts. It proves the build-to-install
leg; it does not certify a PyPI Trusted Publisher, TestPyPI, or production.

## Failure semantics

Malformed version/tag, missing or extra archive, checksum mismatch, artifact
redownload mismatch, dependency failure, or CLI failure makes the workflow
fail. Retrying never authorizes production publication.
