import { ActivationRegistry } from "./activation-registry";
import { AuthReplayLedger } from "./auth-replay-ledger";
import { BrokerError, errorResponse, jsonResponse } from "./errors";
import { GlobalActivatedAuthorityHead } from "./global-activated-authority-head";
import { ReleaseLedger } from "./release-ledger";
import { requestId } from "./validation";

export { ActivationRegistry, AuthReplayLedger, GlobalActivatedAuthorityHead, ReleaseLedger };

interface BootstrapEnv {
  readonly CF_VERSION_METADATA?: WorkerVersionMetadata;
}

/**
 * One-use blank-account lifecycle entrypoint.
 *
 * Wrangler must deploy once to create SQLite Durable Object namespaces. This
 * entrypoint exports the final classes but deliberately exposes no activation,
 * receipt, provider, runtime, or administrative authority. After this one-use
 * lifecycle deploy, the paired ceremony directly uploads final ingress and
 * WORM versions with one new shared key and stages them without promoting.
 */
export const bootstrapIngress = {
  fetch(request: Request, env: BootstrapEnv): Response {
    let currentRequestId: string = crypto.randomUUID();
    try {
      currentRequestId = requestId(request);
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/livez" && url.search === "") {
        return jsonResponse({
          schema: "dpone.release-broker-bootstrap-liveness.v1",
          status: "bootstrap-deny",
          worker_version_id: env.CF_VERSION_METADATA?.id ?? "unavailable",
        });
      }
      throw new BrokerError("BROKER_BOOTSTRAP_DENY", 503, false);
    } catch (error) {
      return errorResponse(error, currentRequestId);
    }
  },
} satisfies ExportedHandler<BootstrapEnv>;

export default bootstrapIngress;
