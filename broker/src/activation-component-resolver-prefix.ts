import { ACTIVATION_COMPONENT_DIGEST, componentError } from "./activation-component-codec";

const RESOLVER_INVALID = "ACTIVATION_COMPONENT_RESOLVER_INVALID";
const WORKER_VERSION = /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u;

/** Derive the only manifest namespace that the confidential reader may inspect. */
export function activationComponentManifestNamespacePrefix(
  workerVersionId: string,
  setId: string,
): string {
  assertWorkerAndDigests(workerVersionId, [setId]);
  return `receipts/v2/activation-component-manifests/${workerVersionId}/${digestHex(setId)}/`;
}

/** Derive the only descriptor namespace that the confidential reader may inspect. */
export function activationComponentNamespacePrefix(
  workerVersionId: string,
  setId: string,
  descriptorId: string,
  descriptorSha256: string,
): string {
  assertWorkerAndDigests(workerVersionId, [setId, descriptorId, descriptorSha256]);
  return (
    `receipts/v2/activation-components/${workerVersionId}/${digestHex(setId)}/` +
    `${digestHex(descriptorId)}/${digestHex(descriptorSha256)}/`
  );
}

function assertWorkerAndDigests(workerVersionId: string, digests: readonly string[]): void {
  if (
    !WORKER_VERSION.test(workerVersionId) ||
    !digests.every((digest) => ACTIVATION_COMPONENT_DIGEST.test(digest))
  ) {
    throw componentError(RESOLVER_INVALID);
  }
}

function digestHex(digest: string): string {
  return digest.slice("sha256:".length);
}
