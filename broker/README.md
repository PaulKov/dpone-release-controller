# Release authority broker — publication candidate on HOLD

> **PROVIDER MUTATION HOLD:** `DPONE_PROVIDER_MUTATION_HOLD_V1` is active. This candidate cannot
> upload, deploy, bootstrap, provision a provider secret, or run the WORM authority ceremony.
> `--apply`, repository-defined environment/configuration flags, local credentials, and dependency
> injection cannot lift it.

This directory is a fail-closed Cloudflare release-authority broker candidate. It is suitable for
source review and offline verification, not for deployment. The shared guard in
`scripts/provider-mutation-hold.mjs` executes before production code invokes a real provider
adapter, parses or uses CLI options, or reads ceremony secrets. Module loading may establish static
import bindings, and native direct-entry detection may inspect only `process.argv[1]` before the
exported production `main` is called. That detection does not parse or use the command's option
vector. The exact first statement of each production `main` enters the HOLD; only after that
unconditional guard could it create its own frozen snapshot of `process.argv.slice(2)`. Lifting the HOLD
requires a reviewed source change and the cutover evidence listed below.

## Self-service verification

Use Node `24.19.0` from `.node-version` and pnpm `11.19.0` from the exact `packageManager`
field. The `engines.node` range is compatibility metadata, not the verified runtime pin:

```sh
pnpm install --frozen-lockfile
pnpm privacy:check
pnpm check
```

`privacy:check` is offline. It reads every discovered publication file as exact UTF-8, rejects
unclassified file types and non-regular entries, verifies the exact review-template inventory and
synthetic identifier classification, and checks stale identifiers, forbidden secret-artifact names,
and high-confidence credential patterns. It is not a replacement for organization-wide repository
secret scanning.

## Command safety matrix

| Command or mode                                                          | Current behavior                                                  |
| ------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| `pnpm config:check`, `privacy:check`, tests, lint, typecheck, formatting | Allowed; offline/configuration checks only                        |
| Primitive-JSON simulation tests                                          | Allowed; in-memory declarative traces only                        |
| `bootstrap:live`, with or without `--apply`                              | Held before option snapshot/parsing/use or adapter invocation     |
| GitHub App key command, with or without `--apply`                        | Held before option snapshot/parsing/use or PEM access             |
| Cloudflare observer token command, with or without `--verify`            | Held before option snapshot/parsing/use, token read, or write     |
| `version:upload` and `version:deploy`                                    | Held before option snapshot/parsing/use, config, or provider use  |
| WORM authority command, including former dry/recovery modes              | Held before option snapshot/parsing/use, secrets, journal, or I/O |

Every exported production engine and lower mutation helper is independently guarded, including
bootstrap materialization/smoke, version upload/deploy, WORM provider requery/upload, and journal
reservation/write surfaces. The former production dry paths are unreachable while the HOLD is
active. Semantic coverage uses primitive-JSON, in-memory trace models with no filesystem,
subprocess, fetch, callback port, or provider client. Those models are review aids, not
authorization evidence for the quarantined production implementation.

`config:check` first runs `scripts/verify-provider-quarantine.mjs` as a trusted, builtins-only
bootstrap. That root cannot self-hash. Before any policy or parser module is imported, it rejects
symlink/non-regular inputs and verifies the exact bytes and complete import-source inventory of the
21-file policy closure, plus `package.json`, `pnpm-lock.yaml`, and `.node-version`. It then loads the
direct-pinned `espree@11.2.0` and `eslint-scope@9.1.2` policy closure and validates strict
ECMAScript syntax, the exact production module/export/import map, all 77 runtime mutation
boundaries, every effect-module data initializer, the reviewed HOLD function AST, typed
ambient/filesystem/I/O capability ownership, package commands, and each primitive-JSON simulation's
full Program AST before the larger verifier starts. This syntactic quarantine
proves only the checked-in source under a trusted pinned Node startup and trusted installed parser
dependencies. It does not cover `NODE_OPTIONS`, preload/custom-loader execution, a malicious or
prototype-poisoned runtime, adapter correctness, Cloudflare readiness, provider state, or a
malicious simultaneous edit of the trusted bootstrap and checked source. Every bootstrap,
policy, or production change therefore requires independent review even when regenerated
inventories agree.

## Identifier taxonomy

The tracked `wrangler.*.live.jsonc` files are **publication review templates**, not live deployment
configuration. Their exact header and placeholders are enforced:

| Class                                                              | Tracked representation                     | Meaning                                  |
| ------------------------------------------------------------------ | ------------------------------------------ | ---------------------------------------- |
| Cloudflare account and zone IDs                                    | All-zero fixed-width values                | Synthetic and unresolved                 |
| B2 bucket IDs and mTLS digest                                      | All-zero fixed-width values                | Synthetic and unresolved                 |
| Access application/policy IDs                                      | RFC example UUIDs                          | Synthetic                                |
| GitHub App/installation IDs                                        | Reserved high-number review-template range | Synthetic                                |
| Hostname                                                           | Reserved `.invalid` name                   | Non-routable placeholder                 |
| Immutable service identities                                       | `INJECTED_BY_..._CEREMONY` sentinels       | Must be derived during a future ceremony |
| Worker/service/repository names                                    | Plain public protocol topology             | Non-secret, intentionally reviewable     |
| Exact GitHub owner/repository/ruleset constants in source fixtures | Public provider identifiers                | Protocol pins, not credentials           |

No Cloudflare token, GitHub App private key, B2 application key, RPC key, Access principal secret,
or provider bearer belongs in source, fixtures, logs, reports, or a committed Wrangler variable.

## Historical receipt fixture

`test/fixtures/release-receipt-envelope-v2.schema.json` is the exact historical broker receipt pin
verified by `config:check`. It intentionally preserves the pre-HOLD receipt contract, including two
public-closure variants later removed or quarantined by the clean controller line. It is only a
fixture/config-integrity input in this candidate: it grants no runtime authority and does not mean
that runtime closure or public mutation is enabled. Never rewrite or regenerate it locally.

Admin activation v2 is likewise candidate-only. Its codec is not imported by ingress, replay,
registry, provider, or deployment runtime; the existing admin handler remains v1.

## Local secret hygiene

- Keep private inputs outside the repository in a mode-`0600` directory.
- Never place secrets on a command line or in Wrangler `vars`; use the documented file/stdin
  boundaries only after a separately reviewed cutover.
- `.gitignore` covers common env, PEM/key, credential JSON, bootstrap report, policy evidence, and
  ceremony journal names. Treat that as a last guard, not authorization to create secrets here.
- Before publication, run `pnpm privacy:check` and the organization secret scanner over full Git
  history. Rotate and purge any credential that ever entered Git, even if a later commit removed it.

## Criteria to lift HOLD

All items require independent review in one non-public cutover change:

1. Replace every synthetic template value with provider-observed identifiers and record their
   provenance; do not publish the resulting control-plane bundle.
2. Verify the custom hostname, zone, Access/mTLS policy, isolated GitHub Apps, B2 restrictions,
   immutable service graph, and exact current deployments into WORM-backed activation evidence.
3. Freeze authentication, replay, activation state transitions, provider-effect recovery, and a
   separately approved new public-projection contract. The controller's internal `CLOSED` state is
   not public closure authority; retired closure/check selectors cannot be reused.
4. Replace the quarantine only with a newly reviewed production adapter and direct provider-effect
   tests in an isolated cutover change; changing the guard alone is insufficient. Do not add an
   environment, flag, local-file, test-model, or dependency-injection authorization bypass.
5. Re-run the zero-effect HOLD regressions before the lift and the complete provider preflight in
   the exclusive approved ceremony window after it.

See `docs/architecture.md`, `docs/threat-model.md`, `docs/runbook.md`, and
`docs/recovery-provenance.md` for the design, forensic/authored boundary, and future ceremony
sequence.
