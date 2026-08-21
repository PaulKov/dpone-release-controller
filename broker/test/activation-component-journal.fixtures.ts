import { canonicalBytes, sha256Hex } from "../src/canonical";
import {
  ACTIVATION_COMPONENT_KINDS,
  type ActivationComponentPayloadInput,
} from "../src/activation-component-contract";
import type {
  ActivationComponentJournalInitialInput,
  ActivationComponentJournalSession,
  ActivationComponentSetSemanticDecision,
  ActivationComponentSetSemanticValidator,
} from "../src/activation-component-journal-contract";
import { ActivationComponentJournalStore } from "../src/activation-component-journal-store";
import { ClosedActivationComponentSetSemanticValidator } from "../src/activation-component-semantic-validator";
import { buildActivationComponentEnvelope } from "../src/activation-component-envelope";
import { SERVICE_AUTHORITY_DEFINITIONS, SERVICE_AUTHORITY_ROLES } from "../src/service-authority";
import type { WormExactObjectEffectPins } from "../src/worm-exact-object-effect-contract";
import {
  VALID_A0_ACCOUNT_ID,
  VALID_A0_WORKER_VERSION,
} from "./activation-component-authority.fixtures";
import { VALID_A0_CONFIG, productionValidA0Fixture } from "./activation-component-payload.fixtures";
import { decodePayload } from "./activation-component-semantic.fixtures";
import { uuid } from "./activation-schema-topology.fixtures";

export const JOURNAL_NOW = Date.parse("2026-08-19T12:00:00.000Z");
export const JOURNAL_WORKER_VERSION = VALID_A0_WORKER_VERSION;
const EXECUTOR_VERSION = authorityVersion("worm_mirror");
const OBSERVER_VERSION = authorityVersion("worm_version_observer");

export const JOURNAL_EFFECT_PINS: WormExactObjectEffectPins = Object.freeze({
  executorServiceIdentity: `cloudflare-worker:${VALID_A0_ACCOUNT_ID}/${SERVICE_AUTHORITY_DEFINITIONS.worm_mirror.service}@${EXECUTOR_VERSION}`,
  executorVersionId: EXECUTOR_VERSION,
  observerServiceIdentity: `cloudflare-worker:${VALID_A0_ACCOUNT_ID}/${SERVICE_AUTHORITY_DEFINITIONS.worm_version_observer.service}@${OBSERVER_VERSION}`,
  observerVersionId: OBSERVER_VERSION,
});

let baseJournalPayloads: Promise<readonly ActivationComponentPayloadInput[]> | undefined;

export interface JournalClock {
  milliseconds: number;
  readonly now: () => number;
}

export interface PreparedJournalSession {
  readonly envelopes: readonly Awaited<ReturnType<typeof buildActivationComponentEnvelope>>[];
  readonly payloads: readonly ActivationComponentPayloadInput[];
  readonly session: ActivationComponentJournalSession;
}

export function journalClock(milliseconds = JOURNAL_NOW): JournalClock {
  const clock: JournalClock = {
    milliseconds,
    now: () => clock.milliseconds,
  };
  return clock;
}

export function acceptingJournalValidator(): ActivationComponentSetSemanticValidator {
  return new ClosedActivationComponentSetSemanticValidator(VALID_A0_CONFIG);
}

export function journalRejectDecision(): ActivationComponentSetSemanticDecision {
  return Object.freeze({ outcome: "REJECT" });
}

export async function journalPayloads(
  variant = 0,
): Promise<readonly ActivationComponentPayloadInput[]> {
  baseJournalPayloads ??= productionValidA0Fixture().then(({ componentPayloads }) =>
    componentPayloads.map(snapshotPayload),
  );
  const base = await baseJournalPayloads;
  return base.map((payload) => {
    if (variant === 0 || payload.componentKind !== "oidc") return snapshotPayload(payload);
    const document = decodePayload(payload.canonicalPayloadBytes);
    const rehearsals = document.rehearsals;
    if (rehearsals === null || typeof rehearsals !== "object" || Array.isArray(rehearsals)) {
      throw new Error("journal OIDC rehearsal fixture missing");
    }
    const rehearsal = Object.values(rehearsals)[0];
    if (rehearsal === null || typeof rehearsal !== "object" || Array.isArray(rehearsal)) {
      throw new Error("journal OIDC rehearsal row missing");
    }
    rehearsal.jti_sha256 = taggedDigest(10_000 + variant);
    return {
      canonicalPayloadBytes: canonicalBytes(document),
      componentKind: payload.componentKind,
    };
  });
}

export async function journalInitialInput(
  payloads: readonly ActivationComponentPayloadInput[],
): Promise<ActivationComponentJournalInitialInput> {
  return {
    components: await Promise.all(
      payloads.map(async ({ canonicalPayloadBytes, componentKind }) => ({
        componentKind,
        payloadSha256: `sha256:${await sha256Hex(canonicalPayloadBytes)}`,
      })),
    ),
  };
}

/** Cheap valid roster for admission/capacity tests that never stage payload bytes. */
export function syntheticJournalInput(variant: number): ActivationComponentJournalInitialInput {
  return {
    components: ACTIVATION_COMPONENT_KINDS.map((componentKind, ordinal) => ({
      componentKind,
      payloadSha256: taggedDigest(variant * 100 + ordinal + 1),
    })),
  };
}

export async function prepareJournalSession(
  store: ActivationComponentJournalStore,
  variant = 0,
): Promise<PreparedJournalSession> {
  const payloads = await journalPayloads(variant);
  const session = await store.beginInitial(await journalInitialInput(payloads));
  const envelopes = await Promise.all(
    payloads.map(({ canonicalPayloadBytes, componentKind }) =>
      buildActivationComponentEnvelope(
        session.descriptor.canonicalBytes,
        componentKind,
        canonicalPayloadBytes,
      ),
    ),
  );
  return { envelopes, payloads, session };
}

export async function stagePreparedJournalSession(
  store: ActivationComponentJournalStore,
  prepared: PreparedJournalSession,
): Promise<ActivationComponentJournalSession> {
  let session = prepared.session;
  for (const envelope of prepared.envelopes) {
    session = await store.stageEnvelope(session.sessionId, envelope.canonicalBytes);
  }
  return session;
}

export function journalStore(
  storage: DurableObjectStorage,
  clock: JournalClock,
  validator: ActivationComponentSetSemanticValidator = acceptingJournalValidator(),
): ActivationComponentJournalStore {
  return new ActivationComponentJournalStore(storage, JOURNAL_WORKER_VERSION, validator, clock.now);
}

export function journalCount(storage: DurableObjectStorage, table: string): number {
  return storage.sql
    .exec<{ readonly count: number }>(`SELECT COUNT(*) AS count FROM ${table}`)
    .one().count;
}

function taggedDigest(value: number): string {
  return `sha256:${value.toString(16).padStart(64, "0")}`;
}

function snapshotPayload(input: ActivationComponentPayloadInput): ActivationComponentPayloadInput {
  return {
    canonicalPayloadBytes: Uint8Array.from(input.canonicalPayloadBytes),
    componentKind: input.componentKind,
  };
}

function authorityVersion(role: "worm_mirror" | "worm_version_observer"): string {
  const index = SERVICE_AUTHORITY_ROLES.indexOf(role);
  if (index < 0) throw new Error(`journal ${role} fixture missing`);
  return uuid(index + 10);
}
