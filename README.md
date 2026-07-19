# dpone-release-controller

External privileged composition root for dpone release-trust **shape B**
([ADR 0028](https://github.com/PaulKov/dpone/blob/master/docs/adr/0028-frozen-release-policy-and-publication-boundary.md),
`docs/feature-design-release-trust-boundary-v0732.md`).

## Status

**PROVISIONING / NOT ACTIVATED.** This repository is an inventory and scaffold
artifact. It must not be treated as the live Trusted Publisher or as proof that
ADR 0028 / policy v2 is active in `PaulKov/dpone`.

Target repository: `PaulKov/dpone` (id `1255975556`).

## Required before activation

1. GitHub App + installation IDs with the exact permission matrix from the
   feature design (target read + limited contents write for draft/publish only).
2. Protected environments: `release-attest`, `pypi`, `github-release`.
3. PyPI Trusted Publisher rebound from the candidate repo to this controller
   workflow filename for all four projects.
4. Append-only evidence store (`store_id`) with OIDC-bound writer scope.
5. Fresh GO review + atomic policy v1→v2 cutover in `PaulKov/dpone`.

## Non-goals (current scaffold)

- No candidate checkout of `PaulKov/dpone` on mutation jobs.
- No PyPI upload, attestation, or GitHub Release mutation until GO.
- Current `PaulKov/dpone` `.github/workflows/release.yml` remains the live
  publisher until cutover.
