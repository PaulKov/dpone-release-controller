/** Stable public facade for service-authority activation contracts. */
export {
  RECEIPT_ROLE_BINDINGS,
  SERVICE_AUTHORITY_EXPECTATION_SCHEMA,
  assertServiceAuthorityExpectationMatchesBroker,
  materializeA1PrecommitDeployments,
  parseServiceAuthorityExpectation,
  type ServiceAuthorityExpectation,
} from "./service-authority-expectation";
export {
  SERVICE_AUTHORITY_OBSERVATION_SCHEMA,
  buildServiceAuthorityObservation,
} from "./service-authority-observation-build";
