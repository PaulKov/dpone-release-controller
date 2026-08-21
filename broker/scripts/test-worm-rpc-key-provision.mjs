import { cleanupFixture } from "./test-worm-rpc-key-fixtures.mjs";
import { runProvisioningScenarios } from "./test-worm-rpc-key-provisioning-scenarios.mjs";
import { runRecoveryScenarios } from "./test-worm-rpc-key-recovery-scenarios.mjs";

try {
  runProvisioningScenarios();
  runRecoveryScenarios();
} finally {
  cleanupFixture();
}
