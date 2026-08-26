# Retrospective PyPI verification for v0.74.27

## Status

**APPROVED — PaulKov, 2026-08-26.**

## Problem and scope

The successful controller run `32963303606` published `v0.74.27` before the
current `verify-published` job existed. The release is public, but its original
run has no producer-generated post-publication hash receipt. This feature adds
a narrowly scoped, read-only verifier that creates that missing retrospective
evidence without rebuilding, republishing, moving a tag, or changing PyPI.

The supported subject is fixed for the first invocation:

- dpone tag: `v0.74.27`;
- dpone commit: `62f1631d5088d26ad4da9ab67156e61c0456b866`;
- controller run: `32963303606`;
- retained build artifact: `dpone-pypi-0.74.27`.

The verifier is generic only over explicit, validated inputs so it can later be
used for another historical release. It does not become an alternate publisher
or a release-approval mechanism.

## User journey

An operator downloads the named retained GitHub Actions artifact without
altering it, records its provider artifact metadata, and invokes the verifier.
The verifier reads the closed eight-file archive set, queries the four
version-specific PyPI JSON endpoints, compares names, yanked state, sizes and
SHA-256 values, and writes a canonical JSON receipt and a human-readable
summary. The verifier itself performs an isolated installation; its output is
hashed and included in the receipt.

The result is `PASS` only when every binding and public file matches. Network
unavailability after bounded retries is `UNVERIFIED`; malformed, missing,
extra, yanked or mismatched files are `FAIL`. Neither status authorizes a
republish or changes the historical workflow outcome.

## Public contract

The additive developer command is:

```text
python -m tools.retro_pypi_verification \
  --tag v0.74.27 \
  --commit-sha <exact-tag-commit> \
  --controller-run-id 32963303606 \
  --artifact-id <GitHub-artifact-id> \
  --artifact-zip <unaltered-artifact.zip> \
  --artifact-sha256 <provider-or-local-archive-digest> \
  --output <receipt.json>
```

It exits `0` for `PASS`, `1` for `FAIL` or `UNVERIFIED`, and `2` for invalid
inputs. It always creates an isolated temporary venv from the verified wheel
archives, runs `pip check` and `dpone --help`, and writes `fresh_install.log`
beside the receipt. The JSON schema is `dpone.retro-pypi-verification.v1`. Its identity
contains the tag, commit, controller run, artifact digest, exact eight archive
hashes, observations, and query time. Output replacement is atomic.

## Algorithm and failure semantics

1. Validate the tag, commit SHA, run id, artifact id and artifact digest syntax.
2. Query only fixed, read-only GitHub endpoints through `gh api`, and require
   that the annotated tag resolves to the supplied commit and that the
   controller run completed successfully as the dispatch-triggered PyPI
   publisher before its artifact metadata can match the supplied id, name, size
   and digest.
3. Open the artifact ZIP without extracting symlinks or executing any content.
4. Require exactly the four projects and two non-yanked archive names for the
   declared version; hash their bytes.
5. Fetch each PyPI version endpoint with bounded retries only for transport or
   transient server failures.
6. Require PyPI's file set, SHA-256 values and non-yanked state to equal the
   immutable artifact inventory.
7. Create a temporary venv, install exactly the four validated wheel archives,
   then require successful `pip check` and `dpone --help`; atomically record
   the producer-generated transcript beside the receipt.
8. Record every observation and atomically write the canonical receipt.

No retry occurs for a semantic mismatch. Repeating the verifier with identical
inputs is deterministic apart from the explicitly recorded observation time.

## Security, compatibility and rollback

The verifier is stdlib-only apart from the authenticated `gh` CLI used only for
fixed read-only GitHub API endpoints. It has no publish capability, invokes no
GitHub mutation API, and never follows artifact symlinks.
Existing release behavior is unchanged. To recover from a failed verification,
preserve the receipt, investigate the original source of the mismatch, and do
not recreate or overwrite PyPI files.

## Validation

Unit and contract tests cover closed inventory, version/tag binding, missing or
extra archive, digest mismatch, yanked public file, malformed payload, timeout
exhaustion and atomic output. A live operator execution is required for the
real retained artifact and PyPI endpoints; unavailable artifact or network
evidence remains `UNVERIFIED`.
