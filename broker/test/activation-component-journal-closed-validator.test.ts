import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ActivationComponentJournalStore } from "../src/activation-component-journal-store";
import { ClosedActivationComponentSetSemanticValidator } from "../src/activation-component-semantic-validator";
import { productionValidA0Fixture } from "./activation-component-payload.fixtures";
import {
  mutatedComponentSetFixture,
  productionValidComponentSetFixture,
} from "./activation-component-semantic.fixtures";

afterEach(async () => {
  await reset();
});

describe("activation component journal with its closed semantic validator", () => {
  it("derives and persists both WORM pins only from the validated authority inventory", async () => {
    const fixture = await productionValidComponentSetFixture();
    const executor = requiredAuthority(fixture.source, "worm_mirror");
    const observer = requiredAuthority(fixture.source, "worm_version_observer");
    const expectedPins = {
      executorServiceIdentity: executor.service_identity,
      executorVersionId: executor.worker_version_id,
      observerServiceIdentity: observer.service_identity,
      observerVersionId: observer.worker_version_id,
    };
    const validator = new ClosedActivationComponentSetSemanticValidator(fixture.source.config);
    const decision = await validator.validate(fixture.input);
    expect(decision).toEqual({ outcome: "ACCEPT", pins: expectedPins });
    if (decision.outcome !== "ACCEPT") throw new Error("expected semantic acceptance");
    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.pins)).toBe(true);

    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-closed-pins-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationComponentJournalStore(
        state.storage,
        fixture.source.config.workerVersionId,
        validator,
        () => Date.parse(fixture.source.request.observedAt),
      );
      const session = await store.beginInitial({
        components: fixture.input.descriptor.components,
      });
      for (const envelope of fixture.input.envelopes) {
        await store.stageEnvelope(session.sessionId, envelope.canonicalBytes);
      }

      const selected = await store.selectAndSeal(session.sessionId);
      if (selected.outcome !== "SEALED") throw new Error("expected sealed selection");
      expect(selected.sealed.pins).toEqual(expectedPins);
      expect(selected.sealed.effects.map(({ pins }) => pins)).toEqual(
        selected.sealed.effects.map(() => expectedPins),
      );
      expect(
        state.storage.sql
          .exec<{
            observer_service_identity: string;
            observer_version_id: string;
            worm_service_identity: string;
            worm_version_id: string;
          }>(
            `SELECT observer_service_identity, observer_version_id,
                    worm_service_identity, worm_version_id
             FROM activation_component_selection_v2 WHERE singleton = 1`,
          )
          .one(),
      ).toEqual({
        observer_service_identity: expectedPins.observerServiceIdentity,
        observer_version_id: expectedPins.observerVersionId,
        worm_service_identity: expectedPins.executorServiceIdentity,
        worm_version_id: expectedPins.executorVersionId,
      });
    });
  });

  it("ignores the removed injectable semantic-check argument at runtime", async () => {
    const fixture = await productionValidComponentSetFixture();
    let injectedCheckCalled = false;
    const validator = Reflect.construct(ClosedActivationComponentSetSemanticValidator, [
      fixture.source.config,
      async () => {
        injectedCheckCalled = true;
        throw new Error("forged semantic authority");
      },
    ]) as ClosedActivationComponentSetSemanticValidator;

    await expect(validator.validate(fixture.input)).resolves.toMatchObject({
      outcome: "ACCEPT",
    });
    expect(injectedCheckCalled).toBe(false);
  });

  it("rejects an invalid fifteenth component before selecting or sealing any effect", async () => {
    const source = await productionValidA0Fixture();
    const invalid = await mutatedComponentSetFixture(
      "trusted_publishers",
      (document) => {
        document.unreviewed = true;
      },
      source,
    );
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-journal-closed-invalid-last-0001");

    await runInDurableObject(stub, async (_instance, state) => {
      const store = new ActivationComponentJournalStore(
        state.storage,
        source.config.workerVersionId,
        new ClosedActivationComponentSetSemanticValidator(source.config),
        () => Date.parse(source.request.observedAt),
      );
      const session = await store.beginInitial({
        components: invalid.input.descriptor.components,
      });
      expect(session.descriptor.canonicalBytes).toEqual(invalid.input.descriptor.canonicalBytes);
      for (const envelope of invalid.input.envelopes) {
        await store.stageEnvelope(session.sessionId, envelope.canonicalBytes);
      }

      await expect(store.selectAndSeal(session.sessionId)).resolves.toMatchObject({
        outcome: "REJECTED",
        session: {
          stagedCount: 0,
          state: "REJECTED",
          terminalCode: "ACTIVATION_COMPONENT_SET_SEMANTIC_INVALID",
        },
      });
      expect(
        state.storage.sql
          .exec<{ readonly count: number }>(
            `SELECT COUNT(*) AS count FROM activation_component_session_entries_v2
             WHERE session_id = ? AND effect_id IS NOT NULL`,
            session.sessionId,
          )
          .one().count,
      ).toBe(0);
      expect(
        state.storage.sql
          .exec<{
            readonly selected_session_id: string | null;
            readonly state: string;
          }>(`SELECT selected_session_id, state FROM activation_component_selection_v2`)
          .one(),
      ).toEqual({ selected_session_id: null, state: "OPEN" });
    });
  });
});

function requiredAuthority(
  source: Awaited<ReturnType<typeof productionValidA0Fixture>>,
  role: "worm_mirror" | "worm_version_observer",
) {
  const authority = source.authorityExpectation.authorities.find(
    ({ authority_role }) => authority_role === role,
  );
  if (authority === undefined) throw new Error(`missing ${role} fixture authority`);
  return authority;
}
