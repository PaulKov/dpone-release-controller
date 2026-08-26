# OIDC PyPI release rehearsal

## Status

**APPROVED — backlog implementation, 2026-08-26.**

## Scope

The controller adds a manual, no-publish rehearsal for an existing annotated
dpone tag. It checks out the immutable tag, builds exactly four projects and
eight archives, seals a SHA-256 inventory, redownloads that artifact, and
performs the source archive gate and a fresh wheel installation plus `pip check`
and `dpone --help`. Only after all those checks pass, it emits a second,
version-scoped `dpone.pypi-rehearsal-receipt.v1` artifact. That receipt records
the run identity, exact archive hashes and checks performed; no `PASS` receipt
is created for a failed rehearsal.

It has no `id-token: write`, no environment, no PyPI endpoint, no token, and
no mutation outside GitHub Actions artifacts. It proves the build-to-install
leg; it does not certify a PyPI Trusted Publisher, TestPyPI, or production.

## Failure semantics

Malformed version/tag, missing or extra archive, checksum mismatch, artifact
redownload mismatch, dependency failure, or CLI failure makes the workflow
fail. Retrying never authorizes production publication.
