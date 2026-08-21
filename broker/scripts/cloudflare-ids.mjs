/** Canonical lowercase UUID-shaped Cloudflare Worker version/deployment ID. */
export const CLOUDFLARE_UUID_SOURCE =
  "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
export const CLOUDFLARE_UUID = new RegExp(`^${CLOUDFLARE_UUID_SOURCE}$`, "u");
