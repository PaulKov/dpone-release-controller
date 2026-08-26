import { env } from "cloudflare:workers";
import { reset, runInDurableObject } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import {
  ADMIN_REPLAY_LEDGER_NAME,
  effectReplayBindingBody,
  replayObservationBody,
  replayRequestBody,
} from "../src/auth-replay-ledger";
import { sha256Hex } from "../src/canonical";

afterEach(async () => {
  await reset();
});

describe("Durable Object replay consumption", () => {
  it("atomically rejects concurrent reuse of one verified bearer", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("replay-race-0001");
    const body = replayRequestBody(
      `sha256:${"a".repeat(64)}`,
      Math.floor(Date.now() / 1000) + 300,
      "admin-request-race-0001",
      `sha256:${"b".repeat(64)}`,
    );
    const outcomes = await runInDurableObject(stub, async (instance) =>
      Promise.allSettled([instance.consumeOnce(body), instance.consumeOnce(body)]),
    );
    expect(outcomes.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((item) => item.status === "rejected")).toHaveLength(1);
  });

  it("accepts concurrent byte-identical admin retries exactly once plus one replay", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName(ADMIN_REPLAY_LEDGER_NAME);
    const token = `sha256:${"c".repeat(64)}`;
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const body = replayRequestBody(
      token,
      expiresAt,
      "admin-request-exact-race-0001",
      `sha256:${"d".repeat(64)}`,
    );
    const outcomes = await runInDurableObject(stub, async (instance) =>
      Promise.all([instance.consumeIdempotentExact(body), instance.consumeIdempotentExact(body)]),
    );
    expect(outcomes).toEqual(
      expect.arrayContaining([
        { consumed: true, replayed: false, requestId: "admin-request-exact-race-0001" },
        { consumed: true, replayed: true, requestId: "admin-request-exact-race-0001" },
      ]),
    );
  });

  it("rejects every admin replay binding drift with status 409", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName(ADMIN_REPLAY_LEDGER_NAME);
    const token = `sha256:${"e".repeat(64)}`;
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const body = replayRequestBody(
      token,
      expiresAt,
      "admin-request-exact-drift-0001",
      `sha256:${"f".repeat(64)}`,
    );
    await runInDurableObject(stub, async (instance) => {
      await expect(instance.consumeIdempotentExact(body)).resolves.toMatchObject({
        replayed: false,
      });
      await expect(instance.consumeIdempotentExact(body)).resolves.toMatchObject({
        replayed: true,
      });

      const drifted = [
        replayRequestBody(
          `sha256:${"9".repeat(64)}`,
          expiresAt,
          "admin-request-exact-drift-0001",
          `sha256:${"f".repeat(64)}`,
        ),
        replayRequestBody(
          token,
          expiresAt,
          "admin-request-exact-drift-0001",
          `sha256:${"0".repeat(64)}`,
        ),
        replayRequestBody(
          token,
          expiresAt,
          "admin-request-exact-drift-0002",
          `sha256:${"f".repeat(64)}`,
        ),
        replayRequestBody(
          token,
          expiresAt + 1,
          "admin-request-exact-drift-0001",
          `sha256:${"f".repeat(64)}`,
        ),
      ];
      for (const value of drifted) {
        await expect(instance.consumeIdempotentExact(value)).rejects.toMatchObject({
          code: "OIDC_REPLAY",
          status: 409,
        });
      }
    });
  });

  it("forbids exact-idempotent policy outside the admin ledger", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1");
    await runInDurableObject(stub, async (instance) => {
      expect(() =>
        instance.consumeIdempotentExact(
          replayRequestBody(
            "provider-jti-policy-scope-0001",
            Math.floor(Date.now() / 1000) + 300,
            "provider-request-policy-scope-0001",
            `sha256:${"1".repeat(64)}`,
          ),
        ),
      ).toThrow("AUTH_REPLAY_POLICY_FORBIDDEN");
    });
  });

  it("rejects an expired replay authority before SQLite admission", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("replay-expired-0001");
    await runInDurableObject(stub, async (instance) => {
      await expect(
        instance.consumeOnce(
          replayRequestBody(
            `sha256:${"f".repeat(64)}`,
            Math.floor(Date.now() / 1000) - 1,
            "admin-request-expired-0001",
            `sha256:${"1".repeat(64)}`,
          ),
        ),
      ).rejects.toThrow("OIDC_EXPIRED");
    });
  });

  it("rejects one GitHub jti reused across release and route bindings", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1");
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const jti = "provider-jti-cross-route-00000001";
    await runInDurableObject(stub, async (instance) => {
      await instance.consume(
        replayRequestBody(
          jti,
          expiresAt,
          "release-a-ledger-request-0001",
          `sha256:${"2".repeat(64)}`,
        ),
      );
      await expect(
        instance.consume(
          replayRequestBody(
            jti,
            expiresAt,
            "release-b-governance-request-0001",
            `sha256:${"3".repeat(64)}`,
          ),
        ),
      ).rejects.toThrow("OIDC_REPLAY");
    });
  });

  it("consumes a fresh recovery JTI once and rejects replay or normal-path reuse", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1");
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const jti = "provider-jti-proof-recovery-0001";
    const requestId = "activation-proof-recovery-request-0001";
    await runInDurableObject(stub, async (instance) => {
      await instance.consumeOnce(
        replayRequestBody(jti, expiresAt, requestId, `sha256:${"a".repeat(64)}`),
      );
      const outcomes = await Promise.allSettled([
        instance.consumeOnce(
          replayRequestBody(jti, expiresAt, requestId, `sha256:${"a".repeat(64)}`),
        ),
        instance.consumeOnce(
          replayRequestBody(
            jti,
            expiresAt,
            "activation-proof-normal-request-0001",
            `sha256:${"b".repeat(64)}`,
          ),
        ),
      ]);
      expect(outcomes).toEqual([
        expect.objectContaining({ status: "rejected" }),
        expect.objectContaining({ status: "rejected" }),
      ]);
      for (const outcome of outcomes) {
        if (outcome.status === "fulfilled") throw new Error("replay unexpectedly accepted");
        expect(outcome.reason).toMatchObject({ code: "OIDC_REPLAY" });
      }
    });
  });

  it("rejects one Access assertion reused from provision to finalize", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName(ADMIN_REPLAY_LEDGER_NAME);
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const assertionHash = `sha256:${"4".repeat(64)}`;
    await runInDurableObject(stub, async (instance) => {
      await instance.consumeIdempotentExact(
        replayRequestBody(
          assertionHash,
          expiresAt,
          "activation-provision-request-0001",
          `sha256:${"5".repeat(64)}`,
        ),
      );
      await expect(
        instance.consumeIdempotentExact(
          replayRequestBody(
            assertionHash,
            expiresAt,
            "activation-finalize-request-0001",
            `sha256:${"6".repeat(64)}`,
          ),
        ),
      ).rejects.toThrow("OIDC_REPLAY");
    });
  });

  it("reconciles a sealed JTI dispatch from hashes without replaying the bearer", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1");
    const jti = "provider-jti-reconcile-00000001";
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const requestId = "provider-request-reconcile-0001";
    const claimsDigest = `sha256:${"7".repeat(64)}`;
    await runInDurableObject(stub, async (instance) => {
      const observation = replayObservationBody(
        `sha256:${await sha256Hex(new TextEncoder().encode(jti))}`,
        expiresAt,
        requestId,
        claimsDigest,
      );
      expect(instance.observeConsumedExact(observation)).toEqual({ consumed: false, requestId });
      await instance.consumeOnce(replayRequestBody(jti, expiresAt, requestId, claimsDigest));
      expect(instance.observeConsumedExact(observation)).toEqual({ consumed: true, requestId });
      expect(() =>
        instance.observeConsumedExact({
          ...observation,
          claims_digest: `sha256:${"8".repeat(64)}`,
        }),
      ).toThrow("OIDC_REPLAY_RECONCILIATION_CONFLICT");
    });
  });

  it("prepares and commits one effect-linked JTI while rejecting cross-path reuse", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1");
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const jti = "provider-jti-effect-prepared-0001";
    const requestId = "provider-request-effect-prepared-0001";
    const binding = effectReplayBindingBody(
      `sha256:${await sha256Hex(new TextEncoder().encode(jti))}`,
      expiresAt,
      requestId,
      `sha256:${"9".repeat(64)}`,
      `sha256:${"a".repeat(64)}`,
    );
    await runInDurableObject(stub, async (instance) => {
      expect(instance.observePreparedEffectExact(binding).state).toBe("ABSENT");
      expect(instance.prepareEffectExact(binding).state).toBe("PREPARED");
      expect(instance.prepareEffectExact(binding).state).toBe("PREPARED");
      expect(instance.commitPreparedEffectExact(binding).state).toBe("CONSUMED");
      expect(instance.commitPreparedEffectExact(binding).state).toBe("CONSUMED");
      expect(instance.observePreparedEffectExact(binding).state).toBe("CONSUMED");
      await expect(
        instance.consumeOnce(
          replayRequestBody(jti, expiresAt, requestId, `sha256:${"b".repeat(64)}`),
        ),
      ).rejects.toThrow("OIDC_REPLAY");
      expect(() => instance.cancelPreparedEffectExact(binding)).toThrow(
        "OIDC_REPLAY_RECONCILIATION_CONFLICT",
      );
    });
  });

  it("retains a cancelled effect tombstone and fences a late original commit", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1");
    const binding = effectReplayBindingBody(
      `sha256:${"c".repeat(64)}`,
      Math.floor(Date.now() / 1000) + 300,
      "provider-request-effect-cancelled-0001",
      `sha256:${"d".repeat(64)}`,
      `sha256:${"e".repeat(64)}`,
    );
    await runInDurableObject(stub, async (instance) => {
      expect(instance.prepareEffectExact(binding).state).toBe("PREPARED");
      expect(instance.cancelPreparedEffectExact(binding).state).toBe("CANCELLED");
      expect(instance.cancelPreparedEffectExact(binding).state).toBe("CANCELLED");
      expect(instance.observePreparedEffectExact(binding).state).toBe("CANCELLED");
      expect(() => instance.commitPreparedEffectExact(binding)).toThrow(
        "OIDC_REPLAY_RECONCILIATION_CONFLICT",
      );
      expect(() => instance.prepareEffectExact(binding)).toThrow("OIDC_REPLAY");
    });
  });

  it("prunes only expired tombstones whose linked effect is durably terminal", async () => {
    const stub = env.AUTH_REPLAY_LEDGER.getByName("github-oidc-v1");
    const expiresAt = Math.floor(Date.now() / 1000) + 300;
    const binding = (seed: string) =>
      effectReplayBindingBody(
        `sha256:${seed.repeat(64)}`,
        expiresAt,
        `provider-request-terminal-${seed.repeat(8)}`,
        `sha256:${seed.repeat(64)}`,
        `sha256:${seed.repeat(64)}`,
      );
    await runInDurableObject(stub, async (instance, state) => {
      const eligible = binding("1");
      instance.prepareEffectExact(eligible);
      instance.cancelPreparedEffectExact(eligible);
      instance.markEffectJournalTerminalExact(eligible);

      const unlinked = binding("2");
      instance.prepareEffectExact(unlinked);
      instance.cancelPreparedEffectExact(unlinked);

      const prepared = binding("3");
      instance.prepareEffectExact(prepared);

      state.storage.sql.exec(
        `UPDATE oidc_effect_jti SET expires_at = 1,
           terminal_at = CASE WHEN state != 'PREPARED' THEN 1 ELSE terminal_at END,
           journal_terminal_at = CASE WHEN journal_terminal_at IS NOT NULL THEN 1 ELSE NULL END`,
      );
      instance.prepareEffectExact(binding("4"));

      const storedState = (seed: string) =>
        state.storage.sql
          .exec<{
            readonly state: string;
          }>("SELECT state FROM oidc_effect_jti WHERE jti_hash = ?", seed.repeat(64))
          .toArray()[0]?.state;
      expect(storedState("1")).toBeUndefined();
      expect(storedState("2")).toBe("CANCELLED");
      expect(storedState("3")).toBe("PREPARED");
    });
  });
});
