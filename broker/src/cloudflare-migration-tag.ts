/**
 * Closed ASCII migration-tag alphabet shared by broker evidence and
 * provider-normalized Cloudflare worker resource projections.
 */
export const SAFE_CLOUDFLARE_MIGRATION_TAG = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
