export type CandidateJsonPrimitive = boolean | number | string | null;
export type CandidateJsonValue =
  | CandidateJsonPrimitive
  | CandidateJsonValue[]
  | { [key: string]: CandidateJsonValue };
export type CandidateJsonObject = Record<string, CandidateJsonValue>;

export type DigestSha256 = `sha256:${string}`;
export type GitSha = string;

export const SIDECAR_KINDS = Object.freeze([
  "ACTIVATION_A0",
  "ACTIVATION_A1",
  "ACTIVATION_PROOF",
  "RUNTIME_CLOSURE",
] as const);
export type SidecarKind = (typeof SIDECAR_KINDS)[number];
