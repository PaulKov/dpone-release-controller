/** Stable public facade for immutable Cloudflare Worker version projections. */
export { projectWorkerVersionResources } from "./worker-version-resource-provider.mjs";
export {
  canonicalWorkerVersionResourceProjectionBytes,
  validateWorkerVersionResourceProjection,
} from "./worker-version-resource-validation.mjs";
