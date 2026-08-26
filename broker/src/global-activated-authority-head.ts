import { DurableObject } from "cloudflare:workers";

import { ActivatedAuthorityEffectCoordinator } from "./activated-authority-effect-coordinator";
import { ActivatedAuthorityEffectStore } from "./activated-authority-effect-store";
import {
  activatedAuthorityHeadKey,
  activatedAuthorityHeadRecordSha256,
  buildActivatedAuthorityHead,
  parseActivatedAuthorityHead,
} from "./activated-authority-head";
import {
  assertCurrentHeadMatchesRequest,
  buildCurrentHeadProof,
} from "./activated-authority-head-proof";
import {
  assertFreshHeadRequest,
  parseHeadAdvanceRequestCanonical,
  parseHeadReadRequestCanonical,
} from "./activated-authority-head-rpc";
import {
  ActivatedAuthorityHeadStore,
  type ActivatedAuthorityHeadRow,
} from "./activated-authority-head-store";
import { ActivatedAuthorityHeadWormClient } from "./activated-authority-head-worm-client";
import { verifyActivationSnapshot } from "./activation-snapshot-verifier";
import { B2VersionObserverClient } from "./b2-version-observer-client";
import { reconcileExactObject } from "./b2-exact-reconciliation";
import { canonicalBytes, canonicalJson, sha256Hex } from "./canonical";
import { requireLiveConfig } from "./config";
import { BrokerError, errorResponse } from "./errors";
import type { ActivationRecordView, ActivationWorm, JsonObject, LiveConfigEnv } from "./types";

export const GLOBAL_ACTIVATED_AUTHORITY_HEAD_NAME = "global:v1" as const;

/** Account-global CAS authority for the sole executable activated head. */
export class GlobalActivatedAuthorityHead extends DurableObject<LiveConfigEnv> {
  private readonly effectCoordinator: ActivatedAuthorityEffectCoordinator;
  private readonly effects: ActivatedAuthorityEffectStore;
  private readonly store: ActivatedAuthorityHeadStore;
  private serialTail: Promise<void> = Promise.resolve();

  public constructor(ctx: DurableObjectState, env: LiveConfigEnv) {
    super(ctx, env);
    this.store = new ActivatedAuthorityHeadStore(ctx.storage);
    this.effects = new ActivatedAuthorityEffectStore(ctx.storage);
    this.effectCoordinator = new ActivatedAuthorityEffectCoordinator(
      this.effects,
      this.store,
      env,
      (row, requestId, requestedAt, nowMs) => this.proofFor(row, requestId, requestedAt, nowMs),
    );
  }

  public advance(canonicalRequest: string): Promise<string> {
    const request = parseHeadAdvanceRequestCanonical(canonicalRequest);
    return this.exclusive(async () => {
      const now = Date.now();
      assertFreshHeadRequest(request.requestedAt, now);
      const verified = await verifyActivationSnapshot(
        request.snapshot,
        requireLiveConfig(this.env),
      );
      await Promise.all([
        this.requeryActivationWorm(verified.provisioned, verified.activation),
        this.requeryActivationWorm(verified.activated, verified.activation),
      ]);
      const requestDigest = await semanticAdvanceDigest(verified);
      let row = this.store.findByRequest(requestDigest);
      if (row === undefined) {
        const current = this.store.current();
        const generation = (current?.generation ?? 0) + 1;
        const committedAt = new Date(Date.now()).toISOString();
        const head = await buildActivatedAuthorityHead({
          activatedRecordId: verified.activated.recordId,
          activatedRecordSha256: verified.activated.digest,
          activatedServiceAuthoritiesSha256: verified.activatedServiceAuthoritiesSha256,
          activatedWorm: verified.activated.worm,
          committedAt,
          generation,
          ingressWorkerVersionId: verified.activation.workerVersionId,
          previous:
            current === undefined
              ? "GENESIS"
              : {
                  generation: current.generation,
                  record_id: current.record_id,
                  record_sha256: current.record_sha256,
                },
        });
        row = await this.store.reserveHead({
          activatedRecordId: verified.activated.recordId,
          activatedRecordSha256: verified.activated.digest,
          activatedServiceAuthoritiesSha256: verified.activatedServiceAuthoritiesSha256,
          committedAt,
          generation,
          head,
          ingressWorkerVersionId: verified.activation.workerVersionId,
          recordId: requireHeadString(head, "record_id"),
          recordSha256: await activatedAuthorityHeadRecordSha256(head),
          requestDigest,
        });
      }
      row = await this.completePending(row, verified.activation);
      this.assertCurrent(row);
      return canonicalJson(
        await this.proofFor(row, request.requestId, request.requestedAt, Date.now()),
      );
    });
  }

  public currentCanonical(canonicalRequest: string): Promise<string> {
    const request = parseHeadReadRequestCanonical(canonicalRequest);
    return this.exclusive(async () => {
      const now = Date.now();
      assertFreshHeadRequest(requireHeadString(request, "requested_at"), now);
      if (this.store.pending() !== undefined) {
        throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_ADVANCE_PENDING", 503, true);
      }
      const current = this.store.current();
      if (current === undefined) {
        throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_UNAVAILABLE", 503, true);
      }
      const proof = await this.proofFor(
        current,
        requireHeadString(request, "request_id"),
        requireHeadString(request, "requested_at"),
        now,
      );
      await assertCurrentHeadMatchesRequest(proof, request);
      return canonicalJson(proof);
    });
  }

  /** Atomically pins one activation-proof JTI effect to the current global head. */
  public reserveActivationProofEffect(canonicalRequest: string): Promise<string> {
    return this.exclusive(() => this.effectCoordinator.reserve(canonicalRequest));
  }

  /** Applies one exact reservation state transition; no public route exposes it. */
  public transitionActivationProofEffect(canonicalRequest: string): Promise<string> {
    return this.exclusive(() => this.effectCoordinator.transition(canonicalRequest));
  }

  /** Seals exact proof bytes before the one-shot replay-ledger dispatch. */
  public sealActivationProofEffect(
    canonicalRequest: string,
    canonicalResult: string,
  ): Promise<string> {
    return this.exclusive(() => this.effectCoordinator.seal(canonicalRequest, canonicalResult));
  }

  public override fetch(request: Request): Response {
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    return errorResponse(new BrokerError("INTERNAL_RPC_REQUIRED", 404, false), requestId);
  }

  private async completePending(
    row: ActivatedAuthorityHeadRow,
    activation: Awaited<ReturnType<typeof verifyActivationSnapshot>>["activation"],
  ): Promise<ActivatedAuthorityHeadRow> {
    const head = await rowHead(row);
    const wormService = requireFetcher(this.env.WORM_MIRROR, "WORM_MIRROR_UNAVAILABLE");
    const observerService = requireFetcher(
      this.env.WORM_VERSION_OBSERVER,
      "WORM_VERSION_OBSERVER_UNAVAILABLE",
    );
    if (row.mirror_state === "CONFIRMED") return row;
    if (row.mirror_state === "PREPARED") {
      this.store.markDispatched(row.generation);
      await new ActivatedAuthorityHeadWormClient(
        wormService,
        activation.privateServices.wormMirror,
        activation.privateServices.wormVersionObserver,
        {
          key: requireLiveConfig(this.env).wormRpcAuthKey,
          serviceIdentity: requireLiveConfig(this.env).workerServiceIdentity,
          versionId: requireLiveConfig(this.env).workerVersionId,
        },
      ).mirror(head);
    }
    const worm: ActivationWorm = await reconcileExactObject({
      bytes: canonicalBytes(head),
      committedAt: row.committed_at,
      digest: row.record_sha256,
      key: await activatedAuthorityHeadKey(head),
      observer: new B2VersionObserverClient(
        observerService,
        activation.privateServices.wormVersionObserver,
      ),
    });
    return this.store.confirm(row.generation, worm);
  }

  private async requeryActivationWorm(
    record: ActivationRecordView,
    activation: Awaited<ReturnType<typeof verifyActivationSnapshot>>["activation"],
  ): Promise<void> {
    const service = requireFetcher(
      this.env.WORM_VERSION_OBSERVER,
      "WORM_VERSION_OBSERVER_UNAVAILABLE",
    );
    const reconciled = await reconcileExactObject({
      bytes: canonicalBytes(record.envelope),
      committedAt: requireHeadString(record.envelope, "committed_at"),
      digest: record.digest,
      key: record.worm.key,
      observer: new B2VersionObserverClient(
        service,
        activation.privateServices.wormVersionObserver,
      ),
    });
    if (
      reconciled.versionId !== record.worm.versionId ||
      reconciled.retentionUntil !== record.worm.retentionUntil
    ) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_A1_WORM_MISMATCH", 503, false);
    }
  }

  private async proofFor(
    row: ActivatedAuthorityHeadRow,
    requestId: string,
    requestedAt: string,
    nowMs: number,
  ): Promise<JsonObject> {
    if (
      row.mirror_state !== "CONFIRMED" ||
      row.worm_key === null ||
      row.worm_version_id === null ||
      row.worm_retention_until === null
    ) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_ADVANCE_PENDING", 503, true);
    }
    const observedAt = new Date(nowMs).toISOString();
    return buildCurrentHeadProof({
      brokerAcceptedAt: observedAt,
      head: await rowHead(row),
      observedAt,
      requestId,
      requestedAt,
      worm: {
        digest: row.record_sha256,
        key: row.worm_key,
        retentionUntil: row.worm_retention_until,
        versionId: row.worm_version_id,
      },
    });
  }

  private assertCurrent(row: ActivatedAuthorityHeadRow): void {
    const current = this.store.current();
    if (
      this.store.pending() !== undefined ||
      current?.generation !== row.generation ||
      current.record_id !== row.record_id ||
      current.record_sha256 !== row.record_sha256
    ) {
      throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_STALE", 409, false);
    }
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.serialTail;
    let release: (() => void) | undefined;
    this.serialTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release?.();
    }
  }
}

async function rowHead(row: ActivatedAuthorityHeadRow): Promise<JsonObject> {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(row.canonical_bytes);
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_STORED_INVALID", 503, false);
  }
  const head = await parseActivatedAuthorityHead(decoded);
  if (text !== canonicalJson(head)) {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_STORED_NONCANONICAL", 503, false);
  }
  return head;
}

async function semanticAdvanceDigest(
  verified: Awaited<ReturnType<typeof verifyActivationSnapshot>>,
): Promise<string> {
  const body: JsonObject = {
    activated: {
      record_id: verified.activated.recordId,
      record_sha256: verified.activated.digest,
      worm: wormJson(verified.activated.worm),
    },
    activated_service_authorities_sha256: verified.activatedServiceAuthoritiesSha256,
    ingress_worker_version_id: verified.activation.workerVersionId,
    provisioned: {
      record_id: verified.provisioned.recordId,
      record_sha256: verified.provisioned.digest,
      worm: wormJson(verified.provisioned.worm),
    },
    schema: "dpone.activated-service-authority-head-candidate.v1",
    schema_version: 1,
  };
  return `sha256:${await sha256Hex(canonicalBytes(body))}`;
}

function wormJson(worm: ActivationWorm): JsonObject {
  return {
    digest: worm.digest,
    key: worm.key,
    retention_until: worm.retentionUntil,
    version_id: worm.versionId,
  };
}

function requireFetcher(value: Fetcher | undefined, code: string): Fetcher {
  if (value === undefined || typeof value.fetch !== "function") {
    throw new BrokerError(code, 503, true);
  }
  return value;
}

function requireHeadString(value: JsonObject, key: string): string {
  const candidate = value[key];
  if (typeof candidate !== "string") {
    throw new BrokerError("ACTIVATED_AUTHORITY_HEAD_INVALID", 503, false);
  }
  return candidate;
}
