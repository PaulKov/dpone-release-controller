import { DurableObject } from "cloudflare:workers";

import { BrokerError, errorResponse } from "./errors";
import type { Env } from "./types";

/** SQLite authority stream. Command handlers are added in the ledger slice. */
export class ReleaseLedger extends DurableObject<Env> {
  public constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS broker_schema (
        version INTEGER PRIMARY KEY CHECK(version = 1),
        installed_at INTEGER NOT NULL
      ) STRICT;
      INSERT OR IGNORE INTO broker_schema(version, installed_at) VALUES (1, unixepoch());
    `);
  }

  public override fetch(request: Request): Response {
    const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
    return errorResponse(new BrokerError("LEDGER_COMMAND_UNAVAILABLE", 503, false), requestId);
  }
}
