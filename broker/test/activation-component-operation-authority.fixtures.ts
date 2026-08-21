import { ConfidentialActivationComponentResolver } from "../src/activation-component-resolver";
import { prepareActivationComponentEnvelopeEffect } from "../src/activation-component-confirmation";
import type { ConfirmedActivationProvisionAuthority } from "../src/activation-component-operation-authority-contract";
import { bindActivationProvisionAuthority } from "../src/activation-component-operation-authority";
import type { ConfirmedActivationComponentJournalAuthority } from "../src/activation-component-journal-contract";
import type { ResolvedActivationComponentSet } from "../src/activation-component-resolver-contract";
import type { WormExactObjectEffectPins } from "../src/worm-exact-object-effect-contract";
import {
  confirmComponents,
  confirmManifest,
  manifestResultBytes,
  sealManifest,
  type SelectedContinuationFixture,
} from "./activation-component-journal-continuation.fixtures";
import {
  journalClock,
  journalStore,
  prepareJournalSession,
  stagePreparedJournalSession,
} from "./activation-component-journal.fixtures";
import {
  fixtureReader,
  resolverFixtureForComponentSet,
  type ActivationComponentResolverFixture,
} from "./activation-component-resolver.fixtures";
import { productionValidA0Fixture } from "./activation-component-payload.fixtures";

export interface ActivationProvisionAuthorityFixture {
  readonly authority: ConfirmedActivationProvisionAuthority;
  readonly journal: ConfirmedActivationComponentJournalAuthority;
  readonly resolved: ResolvedActivationComponentSet;
  readonly resolverFixture: ActivationComponentResolverFixture;
  readonly selected: SelectedContinuationFixture;
}

/** Build matching real journal and resolver brands from the same production-valid component set. */
export async function activationProvisionAuthorityFixture(
  storage: DurableObjectStorage,
  variant = 0,
  currentResolverWorkerVersionId?: string,
): Promise<ActivationProvisionAuthorityFixture> {
  const selected = await selectOperationFixture(storage, variant);
  const completed = await completeOperationFixture(selected, currentResolverWorkerVersionId);
  return {
    ...completed,
    authority: await bindActivationProvisionAuthority(completed.journal, completed.resolved),
  };
}

/** Build a valid final journal whose persisted WORM pins diverge from its resolved inventory. */
export async function activationProvisionAuthorityPinTransplantFixture(
  storage: DurableObjectStorage,
  pins: WormExactObjectEffectPins,
): Promise<Pick<ActivationProvisionAuthorityFixture, "journal" | "resolved">> {
  const selected = await selectOperationFixture(storage, 0, pins);
  const completed = await completeOperationFixture(selected);
  return { journal: completed.journal, resolved: completed.resolved };
}

async function selectOperationFixture(
  storage: DurableObjectStorage,
  variant: number,
  persistedPins?: WormExactObjectEffectPins,
): Promise<SelectedContinuationFixture> {
  const clock = journalClock();
  const store = journalStore(storage, clock);
  const prepared = await prepareJournalSession(store, variant);
  await stagePreparedJournalSession(store, prepared);
  if (persistedPins === undefined) {
    const selection = await store.selectAndSeal(prepared.session.sessionId);
    if (selection.outcome !== "SEALED") throw new Error("operation authority selection failed");
    return { clock, prepared, sealed: selection.sealed, store };
  }
  const effects = await Promise.all(
    prepared.envelopes.map(({ canonicalBytes }) =>
      prepareActivationComponentEnvelopeEffect(
        prepared.session.descriptor.canonicalBytes,
        canonicalBytes,
        persistedPins,
      ),
    ),
  );
  persistSelectedPins(storage, prepared.session.sessionId, effects, persistedPins);
  return {
    clock,
    prepared,
    sealed: Object.freeze({
      effects: Object.freeze(effects),
      pins: Object.freeze({ ...persistedPins }),
      session: await store.session(prepared.session.sessionId),
    }),
    store,
  };
}

async function completeOperationFixture(
  selected: SelectedContinuationFixture,
  currentResolverWorkerVersionId?: string,
): Promise<Omit<ActivationProvisionAuthorityFixture, "authority">> {
  await confirmComponents(selected, undefined, resolverComponentVersion);
  const manifestSeal = await sealManifest(selected);
  const manifestResult = manifestResultBytes(
    manifestSeal,
    "4_z-activation-component-manifest-0001",
  );
  const confirmation = await confirmManifest(selected, manifestSeal, manifestResult);
  if (confirmation.outcome !== "CONFIRMED") {
    throw new Error("operation authority manifest confirmation failed");
  }

  const source = await productionValidA0Fixture();
  const resolverFixture = await resolverFixtureForComponentSet({
    input: Object.freeze({
      descriptor: selected.prepared.session.descriptor,
      envelopes: Object.freeze(selected.prepared.envelopes),
    }),
    source,
  });
  assertBytesEqual(confirmation.authority.canonicalPointerBytes, resolverFixture.pointerBytes);
  const resolverConfig =
    currentResolverWorkerVersionId === undefined
      ? source.config
      : {
          ...source.config,
          workerServiceIdentity:
            `cloudflare-worker:${source.config.cloudflareAccountId}/current-resolver@` +
            currentResolverWorkerVersionId,
          workerVersionId: currentResolverWorkerVersionId,
        };
  const resolved = await new ConfidentialActivationComponentResolver(
    fixtureReader(resolverFixture),
    resolverConfig,
  ).resolve(resolverFixture.pointerBytes);
  return {
    journal: confirmation.authority,
    resolved,
    resolverFixture,
    selected,
  };
}

function persistSelectedPins(
  storage: DurableObjectStorage,
  sessionId: string,
  effects: readonly { readonly effectId: string }[],
  pins: WormExactObjectEffectPins,
): void {
  storage.transactionSync(() => {
    storage.sql.exec(
      `UPDATE activation_component_selection_v2
       SET selected_session_id = ?, state = 'COMPONENT_EFFECTS_SEALED',
           worm_service_identity = ?, worm_version_id = ?,
           observer_service_identity = ?, observer_version_id = ?
       WHERE singleton = 1 AND state = 'OPEN'`,
      sessionId,
      pins.executorServiceIdentity,
      pins.executorVersionId,
      pins.observerServiceIdentity,
      pins.observerVersionId,
    );
    storage.sql.exec(
      `UPDATE activation_component_sessions_v2 SET state = 'SELECTED'
       WHERE session_id = ? AND state = 'STAGED'`,
      sessionId,
    );
    effects.forEach(({ effectId }, ordinal) => {
      storage.sql.exec(
        `UPDATE activation_component_session_entries_v2 SET effect_id = ?, status = 'SEALED'
         WHERE session_id = ? AND ordinal = ? AND status = 'STAGED'`,
        effectId,
        sessionId,
        ordinal,
      );
    });
  });
}

function resolverComponentVersion(ordinal: number): string {
  return `4_z-activation-component-${String(ordinal).padStart(2, "0")}`;
}

function assertBytesEqual(left: Uint8Array, right: Uint8Array): void {
  if (left.byteLength !== right.byteLength) throw new Error("operation pointer size mismatch");
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) throw new Error("operation pointer bytes mismatch");
  }
}
