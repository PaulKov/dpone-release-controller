export const RESOLVED_ACTIVATION_COMPONENT_EXECUTION_SOURCE_TRUST =
  "RESOLVED_COMPONENT_EXECUTION_SOURCE" as const;

/**
 * Opaque local capability proving that the confidential resolver retained the
 * complete provider inventory needed for a future execution-authority replay.
 *
 * The scalar digest is informational. Consumers must pass the value back to a
 * private-brand snapshot function; neither this interface nor its trust label
 * authorizes reconstruction from caller-supplied data.
 */
export interface ResolvedActivationComponentExecutionSource {
  readonly projectionSha256: string;
  readonly trust: typeof RESOLVED_ACTIVATION_COMPONENT_EXECUTION_SOURCE_TRUST;
}
