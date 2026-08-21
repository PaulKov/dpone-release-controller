import bootstrap from "./bootstrap-private";
import { CloudflareEvidenceBatch } from "./private/cloudflare-evidence-batch-do";
import { WormExactObjectEffect } from "./private/worm-exact-object-effect-do";

// The blank-account lifecycle deploy exports the exact final journal class so
// Cloudflare applies its SQLite namespace migration before candidate-only
// version uploads. Fetch remains credential-free and fail-closed.
export { CloudflareEvidenceBatch, WormExactObjectEffect };

export default bootstrap;
