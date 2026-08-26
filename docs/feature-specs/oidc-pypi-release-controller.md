# OIDC PyPI release controller

## Status

**APPROVED — PaulKov, 2026-08-26.** This specification supersedes the
quarantine-only release posture for the narrowly scoped PyPI publication path.

## User journey

A maintainer enters an exact semantic version in the controller's manual
workflow. The controller checks out only `refs/tags/v<version>` from
`PaulKov/dpone`, proves that the checked project version is identical, builds
the four workspace distributions, and verifies their metadata. A separate
artifact-only job publishes those exact files to PyPI using GitHub OIDC. A
final tokenless job compares the SHA-256 hashes in PyPI's version-specific API
with an immutable manifest created from the build output. It retries only for
short public-index propagation and fails closed on any missing, extra, or
mismatched file.

## Non-goals

- No PyPI API token, GitHub App token, B2 credential, or broker route.
- No caller-provided repository, ref, SHA, artifact path, or package name.
- No GitHub Release, deployment, canary, or mutation other than PyPI upload.
- No automatic trigger: every run is manually dispatched.

## Security and failure semantics

- Default workflow permissions are empty. Build has `contents: read`; publish
  has only `id-token: write` and never checks out or executes source code. The
  public verification job has no permissions and no checkout.
- The publish job consumes the immutable build artifact, runs in environment
  `pypi`, and uses a full-SHA-pinned PyPA publishing action.
- A version/tag/metadata mismatch, missing distribution, duplicate archive,
  invalid archive, or PyPI rejection fails the run. `skip-existing` is not
  allowed.
- PyPI must trust exactly `PaulKov/dpone-release-controller`, workflow file
  `pypi-release.yml`, and environment `pypi` before any production dispatch.

## Validation and rollback

The workflow source is enforced by a dependency-free structural test and the
existing controller CI. Before the first real publication, run the controller
on TestPyPI or use a deliberate dry-run validation of the build artifact. The
rollback for a failed publication is to stop subsequent dispatches; PyPI files
are immutable and cannot be overwritten. If publication partially succeeds,
the manifest identifies the exact files that require operator reconciliation;
never retry with `skip-existing` or substitute artifacts.
