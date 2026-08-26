# dpone-release-controller

External release-controller repository planned for `PaulKov/dpone`.

## Status

**EMERGENCY QUARANTINE / NOT ACTIVATED.** The current source tree contains no
release writer and provides no proof that provider-side authority has been
revoked. Production release policy remains unchanged in `PaulKov/dpone`.

This replacement stack contains a dormant, dependency-closed domain model for
review. It deliberately contains no executable controller, activation switch,
provider adapter, or compatibility mode. The domain modules cannot be reached
from either checked-in workflow or from the permanent CLI tombstone:

- the historical `.github/workflows/release-controller.yml` writer is removed;
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

The checks use only the Python standard library:

```console
$ python3 -B -m unittest discover -s tests -v
$ python3 -B -m compileall -q tests tools
$ python3 -m json.tool github-app-manifest.json >/dev/null
```

The tombstone help path is read-only. Any other invocation exits with status 2:

```console
$ python3 -B tools/evidence/release_evidence_cli.py --help
$ python3 -B tools/evidence/release_evidence_cli.py acquire-lease
```

The stacked-review boundaries and their dependency direction are documented in
[`docs/controller-stack.md`](docs/controller-stack.md).

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

Restoring any writer requires a separate RFC and separately reviewed PR. That
change must define normative contracts, independent conformance vectors,
least-privilege credentials, provider preparation and rollback, public
authenticity, protected human approval, fault recovery, and exact-head rehearsal.
This quarantine PR cannot be converted into an activation by changing an input,
repository variable, manifest value, or local flag.

See [`docs/live-inventory.md`](docs/live-inventory.md) for historical inventory
that must be re-observed before any future cutover.
