import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  bindActivationProvisionAuthority,
  snapshotConfirmedActivationProvisionAuthority,
} from "../src/activation-component-operation-authority";
import { JOURNAL_EFFECT_PINS } from "./activation-component-journal.fixtures";
import {
  activationProvisionAuthorityFixture,
  activationProvisionAuthorityPinTransplantFixture,
} from "./activation-component-operation-authority.fixtures";

afterEach(async () => {
  await reset();
});

describe("confirmed activation provision authority boundaries", () => {
  it("rejects a journal/resolver set transplant before minting operation authority", async () => {
    let left: Awaited<ReturnType<typeof activationProvisionAuthorityFixture>> | undefined;
    let right: Awaited<ReturnType<typeof activationProvisionAuthorityFixture>> | undefined;
    await runInDurableObject(
      env.AUTH_REPLAY_LEDGER.getByName("component-operation-transplant-left-0001"),
      async (_instance, state) => {
        left = await activationProvisionAuthorityFixture(state.storage, 0);
      },
    );
    await runInDurableObject(
      env.AUTH_REPLAY_LEDGER.getByName("component-operation-transplant-right-0001"),
      async (_instance, state) => {
        right = await activationProvisionAuthorityFixture(state.storage, 1);
      },
    );
    const stableLeft = required(left);
    const stableRight = required(right);

    await expect(
      bindActivationProvisionAuthority(stableLeft.journal, stableRight.resolved),
    ).rejects.toThrow("ACTIVATION_COMPONENT_OPERATION_AUTHORITY_INVALID");
    await expect(
      bindActivationProvisionAuthority(stableRight.journal, stableLeft.resolved),
    ).rejects.toThrow("ACTIVATION_COMPONENT_OPERATION_AUTHORITY_INVALID");
  }, 30_000);

  it("rejects persisted journal WORM pins transplanted against resolved semantics", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-pin-transplant-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const driftedPins = Object.freeze({
        ...JOURNAL_EFFECT_PINS,
        executorServiceIdentity: JOURNAL_EFFECT_PINS.executorServiceIdentity.replace(
          "/dpone-release-worm-mirror@",
          "/transplanted-worm-mirror@",
        ),
      });
      const fixture = await activationProvisionAuthorityPinTransplantFixture(
        state.storage,
        driftedPins,
      );

      expect(fixture.journal.pins).toEqual(driftedPins);
      await expect(
        bindActivationProvisionAuthority(fixture.journal, fixture.resolved),
      ).rejects.toThrow("ACTIVATION_COMPONENT_OPERATION_AUTHORITY_INVALID");
    });
  }, 30_000);

  it("requires both independent input brands and rejects every structural forgery", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-input-brand-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await activationProvisionAuthorityFixture(state.storage);
      const journalForgeries = structuralForgeries(fixture.journal);
      const resolverForgeries = structuralForgeries(fixture.resolved);

      for (const journal of journalForgeries) {
        await expect(bindActivationProvisionAuthority(journal, fixture.resolved)).rejects.toThrow(
          "ACTIVATION_COMPONENT_JOURNAL_CONFIRMED_AUTHORITY_INVALID",
        );
      }
      for (const resolved of resolverForgeries) {
        await expect(bindActivationProvisionAuthority(fixture.journal, resolved)).rejects.toThrow(
          "ACTIVATION_COMPONENT_RESOLVER_INVALID",
        );
      }
    });
  }, 30_000);

  it("rejects literal, spread, prototype, proxy, constructor, and serialized output forgeries", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-output-brand-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const { authority } = await activationProvisionAuthorityFixture(state.storage);
      const serialized = JSON.parse(JSON.stringify(authority)) as unknown;
      for (const forgery of [...structuralForgeries(authority), serialized]) {
        await expect(snapshotConfirmedActivationProvisionAuthority(forgery)).rejects.toThrow(
          "ACTIVATION_COMPONENT_OPERATION_AUTHORITY_INVALID",
        );
      }
    });
  }, 30_000);

  it("owns both accepted input snapshots before hashing and ignores caller byte mutations", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-input-ownership-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const fixture = await activationProvisionAuthorityFixture(state.storage);
      const journalPointer = fixture.journal.canonicalPointerBytes;
      const journalDescriptor = fixture.journal.canonicalDescriptorBytes;
      const resolvedProjection = fixture.resolved.canonicalProjectionBytes;
      const pending = bindActivationProvisionAuthority(fixture.journal, fixture.resolved);
      journalPointer.fill(0);
      journalDescriptor.fill(0);
      resolvedProjection.fill(0);

      await expect(pending).resolves.toMatchObject({
        componentAuthoritySha256: fixture.authority.componentAuthoritySha256,
        provisionIntentSha256: fixture.authority.provisionIntentSha256,
        trust: "CONFIRMED_COMPONENT_OPERATION_AUTHORITY",
      });
    });
  }, 30_000);

  it("does not expose mutable pin, commitment, descriptor, session, or component documents", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("component-operation-output-ownership-0001");
    await runInDurableObject(stub, async (_instance, state) => {
      const { authority } = await activationProvisionAuthorityFixture(state.storage);
      expect(Object.isFrozen(authority)).toBe(true);
      expect(Object.isFrozen(authority.componentAuthority)).toBe(true);
      expect(Object.isFrozen(authority.descriptor)).toBe(true);
      expect(Object.isFrozen(authority.session)).toBe(true);
      expect(Object.isFrozen(authority.pins.providerReads)).toBe(true);
      expect(Object.isFrozen(authority.pins.providerReads.controllerAction)).toBe(true);
      expect(() => {
        (authority.componentAuthority as Record<string, unknown>).forged = true;
      }).toThrow();
      expect(() => {
        (authority.pins.providerReads.controllerAction as { serviceName: string }).serviceName =
          "forged";
      }).toThrow();
      await expect(snapshotConfirmedActivationProvisionAuthority(authority)).resolves.toMatchObject(
        {
          provisionIntentSha256: authority.provisionIntentSha256,
        },
      );
    });
  }, 30_000);
});

function structuralForgeries(input: object): readonly unknown[] {
  class StructuralForgery {
    public readonly marker = true;
  }
  const prototype = Reflect.getPrototypeOf(input);
  const descriptor =
    prototype === null ? undefined : Reflect.getOwnPropertyDescriptor(prototype, "constructor");
  const constructorValue: unknown = descriptor?.value as unknown;
  const Constructor =
    typeof constructorValue === "function"
      ? (constructorValue as new (...args: unknown[]) => object)
      : undefined;
  const fromConstructor = Constructor === undefined ? {} : Object.assign(new Constructor(), input);
  return [
    { ...input },
    Object.assign(Object.create(prototype) as object, input),
    new Proxy(input, {}),
    fromConstructor,
    Object.assign(new StructuralForgery(), input),
  ];
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("operation authority fixture missing");
  return value;
}
