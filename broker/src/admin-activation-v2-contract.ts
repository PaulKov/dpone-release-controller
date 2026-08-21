import type {
  ActivationComponentDigestInput,
  ActivationComponentKind,
} from "./activation-component-contract";
import type { JsonObject } from "./types";

/** Existing public URI retained by the candidate v2 ingress protocol. */
export const ADMIN_ACTIVATION_V2_PROVISION_PATH = "/v1/admin/activation/provision" as const;

/** Existing public URI retained by the candidate v2 ingress protocol. */
export const ADMIN_ACTIVATION_V2_FINALIZE_PATH = "/v1/admin/activation/finalize" as const;

/** Compact command envelope used only on the provision URI. */
export const ADMIN_ACTIVATION_V2_COMMAND_SCHEMA =
  "dpone.release-broker-admin-activation-command.v2" as const;

export const ADMIN_ACTIVATION_V2_COMMAND_MAX_BYTES = 4_096;

export const ADMIN_ACTIVATION_V2_COMMAND_ACTIONS = Object.freeze([
  "BEGIN",
  "REISSUE",
  "PROVISION",
] as const);

export type AdminActivationV2Path =
  | typeof ADMIN_ACTIVATION_V2_FINALIZE_PATH
  | typeof ADMIN_ACTIVATION_V2_PROVISION_PATH;

/** Trusted route context supplied explicitly by the future ingress adapter. */
export interface AdminActivationV2CodecContext {
  readonly expectedWorkerVersionId: string;
  readonly path: AdminActivationV2Path;
}

interface AdminActivationV2ParsedBase {
  /** A fresh owned copy is returned on every access. */
  readonly canonicalBytes: Uint8Array;
  readonly trust: "UNTRUSTED";
}

export interface AdminActivationV2Begin extends AdminActivationV2ParsedBase {
  readonly action: "BEGIN";
  readonly components: readonly ActivationComponentDigestInput[];
  readonly schema: typeof ADMIN_ACTIVATION_V2_COMMAND_SCHEMA;
}

export interface AdminActivationV2Reissue extends AdminActivationV2ParsedBase {
  readonly action: "REISSUE";
  readonly predecessorDescriptorId: string;
  readonly predecessorDescriptorSha256: string;
  readonly predecessorSessionId: string;
  readonly schema: typeof ADMIN_ACTIVATION_V2_COMMAND_SCHEMA;
}

export interface AdminActivationV2Stage extends AdminActivationV2ParsedBase {
  readonly action: "STAGE";
  readonly componentKind: ActivationComponentKind;
  readonly descriptorId: string;
  readonly descriptorSha256: string;
  readonly schema: "dpone.release-activation-component.v2";
  readonly setId: string;
  readonly workerVersionId: string;
}

export interface AdminActivationV2Provision extends AdminActivationV2ParsedBase {
  readonly action: "PROVISION";
  readonly schema: typeof ADMIN_ACTIVATION_V2_COMMAND_SCHEMA;
  readonly selectedSessionId: string;
}

export interface AdminActivationV2Finalize extends AdminActivationV2ParsedBase {
  readonly action: "FINALIZE";
  /** Exact six-field, deeply frozen v2 request document. */
  readonly request: JsonObject;
  readonly schema: "dpone.release-broker-finalize-request.v2";
  readonly workerVersionId: string;
}

/** Structural ingress result only. It grants no journal, replay, or provider authority. */
export type UntrustedAdminActivationV2Ingress =
  | AdminActivationV2Begin
  | AdminActivationV2Finalize
  | AdminActivationV2Provision
  | AdminActivationV2Reissue
  | AdminActivationV2Stage;
