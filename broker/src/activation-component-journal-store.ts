import { ActivationComponentJournalAdmission } from "./activation-component-journal-admission";
import { ActivationComponentJournalAuthorityReader } from "./activation-component-journal-authority";
import { ActivationComponentJournalConfirmation } from "./activation-component-journal-confirmation";
import type {
  ActivationComponentManifestConfirmation,
  ActivationComponentManifestSeal,
  ConfirmedActivationComponentJournalAuthority,
  ActivationComponentJournalInitialInput,
  ActivationComponentJournalReissueInput,
  ActivationComponentJournalSession,
  ActivationComponentSetSelection,
  ActivationComponentSetSemanticValidator,
  SealedActivationComponentSet,
  UnresolvedActivationComponentEffects,
} from "./activation-component-journal-contract";
import { ActivationComponentJournalManifestLifecycle } from "./activation-component-journal-manifest";
import { ActivationComponentJournalQueries } from "./activation-component-journal-queries";
import { initializeActivationComponentJournalSchema } from "./activation-component-journal-schema";
import { ActivationComponentJournalSelection } from "./activation-component-journal-selection";
import { ActivationComponentJournalStaging } from "./activation-component-journal-staging";
import type { WormExactObjectEffectPins } from "./worm-exact-object-effect-contract";

/**
 * Pure candidate journal facade. It stages, seals, and confirms the exact
 * component/manifest authority, but has no route, resolver, writer, or observer port.
 */
export class ActivationComponentJournalStore {
  private readonly admission: ActivationComponentJournalAdmission;
  private readonly confirmation: ActivationComponentJournalConfirmation;
  private readonly manifest: ActivationComponentJournalManifestLifecycle;
  private readonly reader: ActivationComponentJournalAuthorityReader;
  private readonly selection: ActivationComponentJournalSelection;
  private readonly staging: ActivationComponentJournalStaging;

  public constructor(
    storage: DurableObjectStorage,
    workerVersionId: string,
    validator: ActivationComponentSetSemanticValidator,
    now: () => number = Date.now,
  ) {
    initializeActivationComponentJournalSchema(storage, workerVersionId);
    const queries = new ActivationComponentJournalQueries(storage.sql);
    this.reader = new ActivationComponentJournalAuthorityReader(queries, workerVersionId);
    this.confirmation = new ActivationComponentJournalConfirmation(storage, queries, this.reader);
    this.manifest = new ActivationComponentJournalManifestLifecycle(storage, queries, this.reader);
    this.admission = new ActivationComponentJournalAdmission(
      storage,
      queries,
      this.reader,
      workerVersionId,
      now,
    );
    this.staging = new ActivationComponentJournalStaging(storage, queries, this.reader, now);
    this.selection = new ActivationComponentJournalSelection(
      storage,
      queries,
      this.reader,
      validator,
      now,
    );
  }

  public beginInitial(
    input: ActivationComponentJournalInitialInput,
  ): Promise<ActivationComponentJournalSession> {
    return this.admission.beginInitial(input);
  }

  public abandonExpired(sessionId: string): Promise<ActivationComponentJournalSession> {
    return this.admission.abandonExpired(sessionId);
  }

  public reissueExpired(
    input: ActivationComponentJournalReissueInput,
  ): Promise<ActivationComponentJournalSession> {
    return this.admission.reissueExpired(input);
  }

  public stageEnvelope(
    sessionId: string,
    canonicalEnvelopeBytes: Uint8Array,
  ): Promise<ActivationComponentJournalSession> {
    return this.staging.stageEnvelope(sessionId, canonicalEnvelopeBytes);
  }

  public selectAndSeal(sessionId: string): Promise<ActivationComponentSetSelection> {
    return this.selection.selectAndSeal(sessionId);
  }

  public sealedPlans(
    sessionId: string,
    expectedPins?: WormExactObjectEffectPins,
  ): Promise<SealedActivationComponentSet> {
    return this.selection.sealedPlans(sessionId, expectedPins);
  }

  public unresolvedComponentEffects(
    sessionId: string,
    expectedPins?: WormExactObjectEffectPins,
  ): Promise<UnresolvedActivationComponentEffects> {
    return this.confirmation.unresolved(sessionId, expectedPins);
  }

  public confirmComponentEffect(
    sessionId: string,
    effectId: string,
    canonicalResultBytes: Uint8Array,
  ): Promise<UnresolvedActivationComponentEffects> {
    return this.confirmation.confirm(sessionId, effectId, canonicalResultBytes);
  }

  public sealManifestEffect(sessionId: string): Promise<ActivationComponentManifestSeal> {
    return this.manifest.seal(sessionId);
  }

  public confirmManifestEffect(
    sessionId: string,
    effectId: string,
    canonicalResultBytes: Uint8Array,
  ): Promise<ActivationComponentManifestConfirmation> {
    return this.manifest.confirm(sessionId, effectId, canonicalResultBytes);
  }

  public confirmedAuthority(
    sessionId: string,
  ): Promise<ConfirmedActivationComponentJournalAuthority> {
    return this.manifest.confirmed(sessionId);
  }

  public async session(sessionId: string): Promise<ActivationComponentJournalSession> {
    return (await this.reader.load(sessionId)).session;
  }
}
