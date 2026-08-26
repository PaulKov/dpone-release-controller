import type { Env as BrokerEnv } from "../src/types";

declare global {
  namespace Cloudflare {
    interface Env extends BrokerEnv {}
  }
}

export {};
