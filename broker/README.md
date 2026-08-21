# Release authority broker — publication candidate on HOLD

> **PROVIDER MUTATION HOLD:** `DPONE_PROVIDER_MUTATION_HOLD_V1` is active. This candidate cannot
> upload, deploy, bootstrap, provision a provider secret, or run the WORM authority ceremony.
> `--apply`, environment variables, local credentials, and dependency injection cannot lift it.

This directory is a fail-closed Cloudflare release-authority broker candidate. It is suitable for
source review and offline verification, not for deployment. The shared guard in
`scripts/provider-mutation-hold.mjs` executes before production code binds a real provider adapter
or reads ceremony secrets. Lifting it requires a reviewed source change and the cutover evidence
listed below.

## Self-service verification

Use the pinned Node and pnpm versions declared in `package.json`:

```sh
pnpm install --frozen-lockfile
pnpm privacy:check
pnpm check
```

`privacy:check` is offline. It verifies the exact review-template inventory, synthetic identifier
classification, stale-document denylist, forbidden secret-artifact names, and high-confidence
credential patterns. It is not a replacement for organization-wide repository secret scanning.

## Command safety matrix

| Command or mode                                                          | Provider effect                              | Current behavior                                      |
| ------------------------------------------------------------------------ | -------------------------------------------- | ----------------------------------------------------- |
| `pnpm config:check`, `privacy:check`, tests, lint, typecheck, formatting | None                                         | Allowed                                               |
| `pnpm bootstrap:live -- ...` without `--apply`                           | None; local plan only                        | Allowed                                               |
| GitHub App key command without `--apply`                                 | None; local PEM conversion/fingerprint check | Allowed, but reads the named private file             |
| Cloudflare observer token verification                                   | None; local evidence validation/report       | Allowed, but reads the named token file               |
| `bootstrap:live ... --apply`                                             | Cloudflare deployment                        | Rejected with `PROVIDER_MUTATION_HOLD` before effects |
| `version:upload ... --apply`                                             | Cloudflare version upload                    | Rejected before config/provider access                |
| `version:deploy ... --apply`                                             | Cloudflare traffic change                    | Rejected before config/provider access                |
| GitHub App key command with `--apply`                                    | Secret-bearing Cloudflare version            | Rejected before reading the PEM                       |
| WORM authority command with `--apply` or `--recover`                     | Provider queries/uploads and local journal   | Rejected before secret reads or journal reservation   |

The semantic bootstrap and WORM recovery suites use explicit fake effect ports. Those engines bind
no real `spawn`, `fetch`, client, or provider adapter by default; production-bound `main` functions
remain guarded.

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
4. Replace the unconditional guard only through source review; do not add an environment, flag,
   local-file, or dependency-injection authorization bypass.
5. Re-run the zero-effect HOLD regressions before the lift and the complete provider preflight in
   the exclusive approved ceremony window after it.

See `docs/architecture.md`, `docs/threat-model.md`, `docs/runbook.md`, and
`docs/recovery-provenance.md` for the design, forensic/authored boundary, and future ceremony
sequence.
