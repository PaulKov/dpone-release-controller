/**
 * Closed inventory of executable provider-mutation boundaries.
 *
 * Publication review templates are deliberately incapable of authorizing an
 * effect. Lifting this HOLD requires a reviewed source change to this module;
 * environment variables, CLI flags, dependency injection and local files are
 * intentionally not consulted.
 */
export const PROVIDER_MUTATION_ENTRYPOINTS = Object.freeze([
  "bootstrap-live-apply",
  "github-app-key-apply",
  "version-deploy",
  "version-upload",
  "worm-authority-apply",
]);

export const PROVIDER_MUTATION_HOLD_CODE = "PROVIDER_MUTATION_HOLD";
export const PROVIDER_MUTATION_HOLD_MARKER = "DPONE_PROVIDER_MUTATION_HOLD_V1";

const INVENTORY = new Set(PROVIDER_MUTATION_ENTRYPOINTS);

/** Always reject a provider effect before credentials, temporary state or I/O are touched. */
export function assertProviderMutationReleased(entrypoint) {
  const classified = typeof entrypoint === "string" && INVENTORY.has(entrypoint);
  const label = classified ? entrypoint : "unclassified-provider-mutation";
  const error = new Error(
    `${PROVIDER_MUTATION_HOLD_CODE}: ${label} is disabled by ${PROVIDER_MUTATION_HOLD_MARKER}`,
  );
  error.code = PROVIDER_MUTATION_HOLD_CODE;
  error.entrypoint = label;
  error.marker = PROVIDER_MUTATION_HOLD_MARKER;
  throw error;
}
