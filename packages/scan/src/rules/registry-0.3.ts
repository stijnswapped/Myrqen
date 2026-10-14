import type { Rule } from "./context.js";
import { clientDomXss } from "./client-dom-xss.js";
import { clientOpenRedirect } from "./client-open-redirect.js";
import { commandInterpreterArgument } from "./command-interpreter-argument.js";
import { corsCredentialedAnyOrigin } from "./cors-credentialed-any-origin.js";
import { credentialRouteUnthrottled } from "./credential-route-unthrottled.js";
import { htmlContentTypeReflection } from "./html-content-type-reflection.js";
import { jwtConfiguration } from "./jwt-configuration.js";
import { locationHeaderRedirect } from "./location-header-redirect.js";
import { massAssignmentWholeBody } from "./mass-assignment-whole-body.js";
import { nosqlAggregationInjection } from "./nosql-aggregation-injection.js";
import { prototypePollutionPath } from "./prototype-pollution-path.js";
import { unsafeDeserializationLibraries } from "./unsafe-deserialization-libraries.js";

/**
 * The rules added for 0.3, each in its own module and each the complement of an
 * existing rule rather than a second opinion on the same line: every one declines
 * the shape its older neighbour already reports, so one defect stays one finding.
 *
 * Kept as one list so the engine's registry changes by a single line, and in the
 * same reading order the registry uses — injection, then what the application
 * writes and redirects to, then who may ask, then secrets, then limits.
 */
export const RULES_0_3: readonly Rule[] = Object.freeze([
  // Injection and interpretation
  commandInterpreterArgument,
  nosqlAggregationInjection,
  unsafeDeserializationLibraries,
  prototypePollutionPath,

  // What the application writes and redirects to
  htmlContentTypeReflection,
  clientDomXss,
  locationHeaderRedirect,
  clientOpenRedirect,

  // Who is allowed to ask
  massAssignmentWholeBody,
  corsCredentialedAnyOrigin,

  // Secrets and tokens
  jwtConfiguration,

  // Limits
  credentialRouteUnthrottled
]);
