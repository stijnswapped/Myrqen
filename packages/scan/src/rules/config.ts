import ts from "typescript";
import { calleeName, calleeTail, collect, expressionName } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, taintOrigin } from "../ast/taint.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/** Route paths that expose internals and are rarely meant to be public. */
/**
 * Paths whose purpose is to report on the deployment itself.
 *
 * The list is broader than "debug" because the name people actually use varies —
 * `runtime-status`, `diagnostics`, `sysinfo`, `_status` — and a route under
 * `internal/` is diagnostic whatever the last segment says. Narrowing this to the
 * literal word `debug` left a route returning the database URL and the migration
 * state entirely uncovered.
 *
 * The underscore forms are here for the same reason the underscore form of
 * `debug` is: file-based routers have no notion of a private route, so a team
 * marks one by prefixing the segment. `server/api/_internal/config.get.ts` is
 * served at `/api/_internal/config` exactly like any other route, and reading
 * the underscore as "not public" is the mistake the convention invites.
 */
const DEBUG_PATH =
  /\/(debug|_debug|dev|__dev|env|config|phpinfo|actuator|healthz\/detail|metrics\/raw|sysinfo|diagnostics?|dump|trace|pprof|varz|statusz|[a-z-]*-?status(?!\w)|_{0,2}internal(\/[\w-]+)*)(\/|$)/i;

/**
 * A `status` segment that hangs off a specific record is that record's state, not the
 * deployment's. `/api/device-links/:id/status` tells a caller whether their own link
 * was approved; `/status` tells anyone what the service is running. The path parameter
 * is what separates them, and without this the rule reports every polling endpoint in
 * every application that has one.
 */
const PER_RECORD_STATE = /\/[:*\[]/;

const SECRET_BEARING = /(secret|token|password|key|credential|env)/i;

/** A comparison against a role, permission, or scope — not merely a session. */
const ROLE_GATE = /\b(role|roles|isAdmin|is_admin|permission|permissions|scope|scopes|can|ability|claims|acl|rbac|staff|operator|superuser|owner)\b/i;

/**
 * Internal state a diagnostic route should not be handing out: configuration, the
 * process environment, database or queue internals, dependency versions, feature
 * flags. A route returning only `{ status: "ok" }` matches none of it.
 */
const INTERNAL_STATE =
  /(process\.env|\benv\b|config|migration|schema_migrations|pg_stat|connection|queue|flag|commit|version|uptime|memoryUsage|buildInfo|hostname|platform|arch)/i;

/**
 * Middleware registered beside the handler — `router.get(path, requireUser,
 * requireRole("ops"), handler)` — is part of the route's gate. Reading only the
 * handler body reported a route gated by its registration as gated not at all.
 */
const MIDDLEWARE_ROLE_GATE = /role|admin|permission|scope|staff|operator|superuser|authori[sz]e/i;
const MIDDLEWARE_AUTHENTICATION = /auth|session|requireUser|currentUser|signedIn|loggedIn|verifyToken|jwt/i;

function registrationMiddleware(context: RuleContext, handler: ts.Node | undefined): string {
  const call = handler?.parent;
  if (!call || !ts.isCallExpression(call) || !call.arguments.includes(handler as ts.Expression)) return "";
  return call.arguments
    .filter((argument) => argument !== handler && !ts.isStringLiteralLike(argument) && !ts.isTemplateExpression(argument))
    .map((argument) => argument.getText(context.file.source))
    .join(" ");
}

export const debugEndpoint: Rule = {
  id: "debug-endpoint",
  category: "debug_endpoint_exposure",
  describes: "diagnostic routes that expose configuration",
  run(context: RuleContext) {
    for (const route of context.routes) {
      if (!DEBUG_PATH.test(route.path)) continue;
      if (PER_RECORD_STATE.test(route.path) && !/\/(_{0,2}debug|_{0,2}internal|dump|trace|pprof)(\/|$)/i.test(route.path)) {
        continue;
      }
      const handler = route.node;
      const text = handler ? handler.getText(context.file.source) : "";
      // A liveness or public status endpoint is not a diagnostic exposure: it answers
      // "is this up" and reveals nothing. What makes a status route a finding is what
      // it puts in the body.
      if (!INTERNAL_STATE.test(text)) continue;
      const exposesSecrets = SECRET_BEARING.test(text) || /process\.env/.test(text);
      /**
       * A role check whose failure stops the handler is the fix, not a mitigation.
       * An operations dashboard that shows configuration to operators is doing its
       * job; the defect is showing it to everyone. Requiring a *role* rather than
       * merely a session matters here — being signed in is not being entitled.
       */
      const middleware = registrationMiddleware(context, handler);
      const roleGated =
        (ROLE_GATE.test(text) && /return|throw|notFound\(|redirect\(/.test(text)) || MIDDLEWARE_ROLE_GATE.test(middleware);
      if (roleGated) continue;
      const authenticated = /session|currentUser|requireUser|requireViewer|getUser/i.test(text) || MIDDLEWARE_AUTHENTICATION.test(middleware);
      if (authenticated && !exposesSecrets) continue;

      context.report({
        ruleId: "debug-endpoint",
        category: "debug_endpoint_exposure",
        title: `Diagnostic route ${route.path} is reachable${authenticated ? "" : " without authentication"}`,
        severity: exposesSecrets ? "high" : "medium",
        verification: "needs_review",
        summary: exposesSecrets
          ? `The handler for ${route.path} returns configuration or environment data, and its payload includes secret-bearing fields.`
          : `The handler for ${route.path} exposes internal state and no authentication check appears in it.`,
        impact:
          "Internal configuration shortens an attacker's path considerably, and when the payload carries credentials it is an immediate compromise of whatever they authorise.",
        remediation:
          "Remove the route from production builds, or require an administrative role and strip every secret-bearing field from the payload.",
        verificationPlan: "Request the route unauthenticated and confirm a 404 or 403 with no configuration in the body.",
        taxonomy: ["CWE-215", "CWE-489"],
        location: { file: context.file.relativePath, line: route.line },
        route: `${route.method} ${route.path}`,
        evidence: [
          {
            kind: "source",
            description: exposesSecrets
              ? "The diagnostic payload references environment or secret-named fields."
              : "The diagnostic route has no authentication expression in its handler.",
            location: `${context.file.relativePath}:${route.line}`
          }
        ],
        reasoning: `Route path matches a diagnostic naming convention; handler ${exposesSecrets ? "references secret-bearing configuration" : "contains no authentication expression"}.`
      });
    }
  }
};

/** Merging caller-controlled objects into targets reachable by prototype. */
