# dpone-release-controller

External release-controller repository planned for `PaulKov/dpone`.

## Status

**ACTIVATION CANDIDATE / NOT YET DISPATCHED.** The legacy writer remains
quarantined and this repository still provides no proof that historical
provider-side authority has been revoked. The sole new publication path is
[`pypi-release.yml`](.github/workflows/pypi-release.yml): a manually started,
tag-bound, OIDC-only PyPI publisher. It must not be dispatched until PyPI is
configured to trust its exact repository, workflow filename, and `pypi`
environment identity.

The dependency-closed domain model remains isolated from publication. The
controller exposes no provider adapter, compatibility mode, or broker route.
Its permanent CLI tombstone cannot publish. The OIDC workflow is intentionally
separate from those modules and has a smaller authority boundary:

- the historical `.github/workflows/release-controller.yml` writer is removed;
- `pypi-release.yml` accepts only a semantic version, checks out
  `PaulKov/dpone` at its matching immutable `v<version>` tag, and passes only
  built artifacts to its publish job;
- only that publish job receives `id-token: write`; it has no checkout and no
  PyPI, GitHub App, or B2 secret;
- the only quarantine marker runs on a push to `master`, has no token
  permissions, performs no checkout, and cannot be manually dispatched;
- every historical evidence/provider module remains removed from the current
  tree;
- the reviewed domain layer is standard-library-only, acyclic, and has no
  provider or subprocess import;
- `tools/evidence/release_evidence_cli.py` is a permanent fail-closed tombstone;
- the bootstrap stamp and evidence-store configuration prototype are removed;
- the GitHub App manifest requests metadata read access only; and
- the one-click GitHub App creation form is removed.

The marker and CI still create ordinary GitHub Actions run logs. They do not
access secrets, mint OIDC or App tokens, upload artifacts, or mutate GitHub,
PyPI, Backblaze B2, the target repository, or a release evidence stream.

## Self-service verification

The emergency quarantine assertions remain standard-library-only. The complete
offline conformance suite additionally uses the exact locked development tools
from `pyproject.toml` and `uv.lock`. Run it with uv 0.11.28 on Python 3.11 and
3.12:

```console
$ uv sync --frozen
$ uv run --frozen ruff check .
$ uv run --frozen ruff format --check .
$ uv run --frozen python -B -m compileall -q scripts tests tools
$ uv run --frozen python -B -m unittest discover -s tests -v
$ for producer in scripts/generate_*.py; do uv run --frozen python -B "${producer}" --check; done
$ uv run --frozen python -B scripts/canonicalize_release_receipt_schema.py --check
$ uv run --frozen python -B -m tools.evidence.release_receipt_vectors --check
```

The tombstone help path is read-only. Any other invocation exits with status 2:

```console
$ python3 -B tools/evidence/release_evidence_cli.py --help
$ python3 -B tools/evidence/release_evidence_cli.py acquire-lease
```

The stacked-review boundaries and their dependency direction are documented in
[`docs/controller-stack.md`](docs/controller-stack.md).

Normative registry manifests and positive-vector sources live under
[`contracts/`](contracts/). Generators consume production-owned model or vector
sources; implementation modules do not import fixtures from `tests/`. The
receipt-envelope JSON Schema is intentionally different: its checked public
file is the language-neutral structural authority, and the registry binds that
file's digest and runtime kind inventory. The receipt-schema canonicalizer
validates and canonicalizes those checked bytes; it does not synthesize schema
structure from another model. Public schemas remain descriptive artifacts while
the runtime and public-closure gates are held.

The recovered broker is isolated under `broker/` and remains on the same
provider-mutation HOLD. Its self-service validation uses the exact runtime from
`broker/.node-version`, pnpm 11.19.0, the frozen lockfile, and disabled package
lifecycle scripts:

```console
$ cd broker
$ test "$(node --version)" = "v$(cat .node-version)"
$ corepack enable
$ corepack install --global pnpm@11.19.0
$ pnpm install --frozen-lockfile --ignore-scripts
$ CI=true pnpm check
```

These commands validate only local source and declarative simulations. They do
not authorize any `--apply`, upload, deployment, provisioning, provider, or
control-plane network action. The package-manager setup and frozen dependency
install may download pinned artifacts from their public registries; those
downloads require no provider credentials. Run the local gate from a
credential-free shell. CI runs the same broker gate with read-only repository
permissions, empty Node injection variables, no credentials persistence, and
no package-manager cache.

## Required operational quarantine evidence

The code patch is necessary but cannot change provider state. Before declaring
the controller fully quarantined, an administrator and an independent reviewer
must record evidence that:

1. historical workflow id `316322127` remains disabled or retired, queued and
   in-progress runs are cancelled, and historical run `29735872648` cannot be
   re-run with its original workflow and credentials;
2. the retired B2 application key, GitHub App private key/client secret, and
   any other long-lived writer credentials are revoked or rotated;
3. the installed broad-write GitHub App is suspended, uninstalled, or reduced
   to approved read-only permissions;
4. `master` and future release environments require independent review and
   disallow administrator bypass; and
5. GitHub Actions secrets and variables are inventoried and stale release
   authority is removed.

Historical refs and retained Actions runs can still contain the removed code.
Deleting it from the default branch does not revoke credentials or prevent
every eligible historical re-run, so the controls above are mandatory.

## Activation boundary

The OIDC publisher is enabled only when PyPI has a Trusted Publisher bound to
`PaulKov/dpone-release-controller`, `pypi-release.yml`, and environment
`pypi`. Its manual input selects a version, never a repository/ref/SHA or
artifact path. Failed and duplicate uploads fail the run; PyPI artifacts are
immutable. Historical provider credentials and the legacy writer remain
outside this new authority path and must still be revoked or reduced.

See [`docs/live-inventory.md`](docs/live-inventory.md) for historical inventory
that must be re-observed before any future cutover.
