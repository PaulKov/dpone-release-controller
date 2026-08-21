# Public closure authenticity anchor — proposed / HOLD

Status: **PROPOSED / INACTIVE / HOLD**. This contract neither generates a
public closure nor activates a controller, broker route, provider adapter, A0,
A1, or C5 cutover.

The future public archive is authenticated with a GitHub Artifact Attestation
over its exact SHA-256 subject digest. For a public repository this is a
Sigstore bundle whose certificate identity is derived from GitHub Actions OIDC
and whose timestamp includes a verified transparency-log witness. A self-ID,
archive digest, sidecar commitment, TLS response, or successful HTTP request is
not an authenticity anchor.

## Closed verification policy

`tools/public_authenticity/verifier.py` performs
content-pinned, offline-input verification. It requires all of the following
exact A0-owned inputs:

- repository `PaulKov/dpone-release-controller`;
- signer workflow path and its immutable signer digest;
- source ref `refs/tags/vMAJOR.MINOR.PATCH` and source commit as certificate
  claims;
- SLSA provenance predicate and GitHub Actions OIDC issuer;
- the exact archive, downloaded Sigstore bundle, and trusted-root document,
  each with an A0-pinned SHA-256;
- an absolute GitHub CLI binary whose raw SHA-256 is content-pinned; and
- rejection of self-hosted runners.

The invocation always supplies `--bundle`, `--custom-trusted-root`,
`--hostname github.com`, and `--digest-alg sha256`; it never asks `gh` to fetch
an attestation or trusted root. The subprocess receives no inherited token,
proxy, config, home, or path environment, and both output streams are bounded.
This is not an OS-level network sandbox: a future A0 ceremony must separately
run this verifier inside a reviewed no-network boundary and retain that
air-gapped execution record. The result is admitted only when exactly one verified
attestation is returned with a certificate, the exact artifact subject,
expected SAN and issuer, a `Tlog` timestamp, and the required predicate. The
resulting observation binds raw hashes of the artifact, bundle, trusted root,
verifier binary, stdout, and stderr.

The serialized observation is not self-authenticating input and must never be
accepted from a caller. A future A0 admission path must invoke this verifier
itself and durably retain the raw pinned inputs and verifier streams alongside
the resulting projection.

The certificate `source_ref` and `source_digest` claims do not prove that the
Git ref is an annotated tag or bind its tag-object SHA. A0 must independently
record and verify the annotated tag object, its peeled commit, protection and
no-bypass evidence; neither proof substitutes for the other.

The trusted root must be acquired out-of-band during a dated pre-A0 ceremony,
reviewed, and stored as immutable evidence. A root checked into this candidate
or silently refreshed by the workflow is not authority. A future activation
change must additionally prove that the production workflow itself cannot be
modified by the release job and that its GitHub environment has independent
approval with no administrator bypass.

## Remaining HOLD gates

The following work is deliberately absent:

1. no production workflow creates or uploads a public archive;
2. no GitHub attestation action is installed or authorized;
3. no live archive, bundle, trusted root, reviewed `gh` version/digest,
   annotated tag-object proof, source ref, or commit has been accepted into A0;
4. no broker route can construct an authenticated public value;
5. no target runtime consumes this observation; and
6. no provider mutation, C5 switch, A1 append, or canary ran.

These gates require separate human review and live provider evidence. Unit
tests patch a private module dependency; the production API exposes no runner
injection. Test success cannot substitute for a pinned real-`gh` golden, an
OS-level no-network execution record, or Sigstore verification.
