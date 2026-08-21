# Broker recovery and authored-candidate provenance

> **Status: review candidate on provider-mutation HOLD.** This document records source recovery
> provenance. It is not Cloudflare evidence, deployment evidence, activation authority, or approval
> to lift `DPONE_PROVIDER_MUTATION_HOLD_V1`.

The broker source was reconstructed outside any repository because no authoritative broker Git
worktree survived in the available host view. Recovery and semantic completion are deliberately
separated below. A reviewer must not describe the entire candidate as a byte-for-byte historical
snapshot.

## Frozen forensic base (v6)

The immutable v6 forensic candidate contains 494 non-dependency regular files and 3,614,842 bytes.
Its ordered source-manifest SHA-256 is:

```text
9525898d6b87384393a2ad82218a375a05417e6e682d6b9cd6feec58dc5563b4
```

It was reconstructed from preserved successful patch events, complete file dumps, deterministic
formatting checkpoints, and one content-addressed archive member. An independent read-only audit
reproduced all 494 manifest entries before and after its checks and mapped every v4-to-v6 delta to
an evidence artifact. v6 remains frozen and is never edited to make a later gate green.

The forensic base intentionally retained known unfinished states: an absent historical receipt
fixture, admin-ingress edge cases, activation-recovery semantics, bootstrap export parity, a WORM
ceremony monolith with incomplete B2-observer binding, lint debt, and module-size failures. Passing
focused tests did not authorize silently removing those HOLDs.

## Authored completion layer (v7)

v7 was copied from frozen v6 and contains reviewable authored changes. These changes are not
claimed as recovered historical bytes:

- activation-operation recovery now permits the exact current `DISPATCHED_HOLD` transition while
  retaining current-issuance, roster, and record-time fences;
- Cloudflare request chronology binds `issued_at <= requested_at <= committed_at`;
- the candidate-only admin v2 codec owns canonical bytes, classifies malformed UTF-8/JSON exactly,
  rejects transport/session selectors, and remains unwired from runtime;
- bootstrap Durable Object export comparison supports the reviewed split-module layout;
- the WORM ceremony is split into cohesive modules and binds the exact immutable B2-observer
  service identity through upload, requery, recovery, terminal recovery, and report output;
- runtime-closure tests reuse a dedicated fixture module instead of an oversized duplicate;
- publication review templates contain only classified synthetic provider identifiers;
- one unconditional source-owned provider-mutation HOLD precedes production adapter binding,
  secret reads, temporary state, subprocesses, fetches, and provider clients;
- the accepted ten-file registry-schema-v2 slice was recovered by replaying its two exact
  successful documentation patches and formatter checkpoints; all other nine files already
  matched, and the ordered aggregate again equals
  `75b049d04cea061e2de37bad0ed8f1704f1f41f2910e3daa361d647774998ee5`;
- lint and documentation were updated without changing provider state.

Semantic effect/recovery suites use explicit fake effect ports. Candidate engines have no default
real provider adapter. Production-bound `main` functions remain guarded; flags, environment
variables, local files, credentials, and dependency injection cannot release the HOLD.

## Exact historical receipt fixture

The broker pins `test/fixtures/release-receipt-envelope-v2.schema.json` to:

```text
c6a36e3b8bdf1cb9b52029be375587d9be824f32eaf3ebd0d37a23775572e641
```

The 263,201-byte file was reproduced in isolated scratch storage by replaying the preserved
controller recovery chronology. The replay independently reached every recorded checkpoint in
order (baseline `410f…`, then `ca924…`, `f964…`, `24e85…`, and final `c6a36…`) before the bytes were
copied verbatim and rehashed in v7. It must not be formatted, regenerated, or repinned as a cleanup.

The fixture preserves a pre-HOLD contract, including public-closure receipt variants subsequently
removed or quarantined by the clean controller line. It is an integrity input only. Runtime closure
and public mutation remain unavailable pending a separately approved public-projection contract.

## Verification and publication boundary

Before review, run from the candidate root:

```sh
pnpm install --frozen-lockfile
pnpm privacy:check
pnpm check
pnpm audit --prod --audit-level high
```

The final v7 manifest and gate-log hashes must be generated only after all writers stop and an
independent read-only audit reproduces them. The manifest excludes dependency/build caches such as
`node_modules`, `.wrangler`, coverage, and distribution output; it includes every other regular
source, fixture, documentation, config, and policy file in byte-sorted path order.

No recovery or v7 completion step contacted Cloudflare, GitHub provider APIs, B2, PyPI, or a
deployment endpoint. No provider command was run with an effective mutation path. A later Git
commit may preserve this source review candidate, but it cannot substitute for a dated provider
observation, accepted A0/A1 activation evidence, or the explicit source change required to lift the
mutation HOLD.

## Provenance limitations

- The forensic base is content-addressed local recovery evidence, not a commit reachable from an
  authoritative broker remote.
- The exact historical receipt was reconstructed from preserved patch/generator chronology, not
  copied from the current quarantined controller commit.
- v7 security and semantic fixes require ordinary code review because they are authored changes.
- A remote destination and repository ownership must be confirmed before push or merge-request
  creation. Creating or repurposing a repository is outside this recovery evidence.
