import ts from "typescript";
import { calleeName, calleeTail, collect, walk } from "../ast/helpers.js";
import { routeFromFilePath } from "../ast/routes.js";
import { routeOf } from "./attribution.js";
import { declarationFor } from "./browser-sources.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";
import { declaredDependencies } from "./project-manifest.js";

/**
 * A sign-in, sign-up, or reset endpoint in a project that has no rate limiter at all.
 *
 * `perimeter-credential-rate-limit` reports a credential route that lacks the limit
 * its siblings have — a contrast it can see in one file. It is silent, by design, in
 * a project that limits nothing, which is the commoner case and the worse one: there
 * is nothing to contrast with.
 *
 * Absence is hard to prove statically, so every condition here is chosen to fail
 * towards silence, and the finding is `low` and `needs_review`:
 *
 *  - The project's manifest must declare its dependencies, and none of them may be a
 *    rate limiter. With no manifest, absence is unknown, not established.
 *  - The module must not mention limiting in any spelling (`rateLimit`, `throttle`,
 *    `429`, `slowDown`, …) — a hand-rolled limiter counts as a limiter.
 *  - The route must be a POST-shaped registration whose path names a credential flow,
 *    and its handler must visibly do the expensive thing an attacker repeats: compare a
 *    password, check a one-time code, hash a new password, or mint a reset token.
 *
 * A limit enforced by a gateway, a CDN, or a reverse proxy is invisible here, which is
 * why the verification plan asks for a request burst rather than a code read.
 */
const LIMITER_PACKAGES = /^(?:express-rate-limit|rate-limiter-flexible|@fastify\/rate-limit|fastify-rate-limit|@upstash\/ratelimit|hono-rate-limiter|koa-ratelimit|koa2-ratelimit|express-slow-down|express-brute|@nestjs\/throttler|limiter|bottleneck|express-limiter|rate-limit-redis|@unkey\/ratelimit|next-rate-limit|@arcjet\/.+|arcjet|elysia-rate-limit|@hono-rate-limiter\/.+|p-throttle|async-ratelimiter|ratelimiter)$/;
const LIMIT_WORDS = /rate.?limit|ratelimit|throttl|slow.?down|bottleneck|leaky.?bucket|token.?bucket|too.?many.?(?:requests|attempts)|\b429\b|brute|lockout|max.?attempts|failed.?attempts|login.?attempts/i;
const WEB_FRAMEWORKS = /^(?:express|fastify|koa|hono|next|@nestjs\/core|h3|nitropack|elysia|@sveltejs\/kit|@remix-run\/node|polka|restify|@hapi\/hapi)$/;

const CREDENTIAL_PATH = /(?:^|\/)(?:login|log-in|signin|sign-in|authenticate|sessions?|token|otp|mfa|2fa|totp|verify-(?:otp|code|mfa))(?:\/|$)/i;
const ENROLMENT_PATH = /(?:^|\/)(?:signup|sign-up|register|registration|join)(?:\/|$)/i;
const RESET_PATH = /(?:^|\/)(?:forgot(?:-password)?|reset(?:-password)?|password\/(?:reset|forgot)|recover(?:y)?)(?:\/|$)/i;

const CREDENTIAL_CHECK = /\b(?:bcrypt|bcryptjs|argon2)\.(?:compare|compareSync|verify)\b|\b(?:verifyPassword|checkPassword|comparePassword|validatePassword|isPasswordValid|passwordMatches|verifyOtp|verifyTotp|verifyCode|checkOtp)\s*\(|\btimingSafeEqual\s*\(|\bscrypt(?:Sync)?\s*\(|\bpbkdf2(?:Sync)?\s*\(|\b(?:authenticator|totp|speakeasy\.totp)\.(?:check|verify)\b|passport\.authenticate\(\s*["'`]local/;
const ENROLMENT_WORK = /\b(?:bcrypt|bcryptjs|argon2)\.(?:hash|hashSync)\b|\bhashPassword\s*\(|\bscrypt(?:Sync)?\s*\(/;
const RESET_WORK = /\b(?:sendMail|sendEmail|sendResetEmail|sendPasswordReset\w*|mailer\.send|transporter\.sendMail|resend\.emails\.send|sgMail\.send)\s*\(|\brandomBytes\s*\(|\bcreateResetToken\s*\(/;

export const credentialRouteUnthrottled: Rule = {
  id: "credential-route-unthrottled",
  category: "missing_rate_limit_on_credentials",
  describes: "a credential endpoint in a project that declares no rate limiter and mentions none",
  run(context: RuleContext) {
    if (LIMIT_WORDS.test(context.file.text)) return;
    const dependencies = declaredDependencies(context.file);
    if (!dependencies) return;
    if ([...dependencies].some((name) => LIMITER_PACKAGES.test(name))) return;
    if (![...dependencies].some((name) => WEB_FRAMEWORKS.test(name))) return;

    const reported = new Set<number>();
    const consider = (node: ts.Node, path: string, handlerText: string, viaMiddleware: string): void => {
      const flow = flowOf(path, handlerText + viaMiddleware);
      if (!flow) return;
      const location = locationOf(context, node);
      if (reported.has(location.line)) return;
      reported.add(location.line);
      context.report({
        ruleId: "credential-route-unthrottled",
        category: "missing_rate_limit_on_credentials",
        title: `The ${flow} endpoint ${path} has no rate limit, and the project declares no limiter`,
        severity: "low",
        verification: "needs_review",
        summary: `This handler ${WORK[flow]} on every request, and nothing in this module or in the project's declared dependencies limits how often one client may ask. Unless a gateway in front of the application limits it, an attacker can repeat the request as fast as the server answers.`,
        impact: IMPACT[flow],
        remediation:
          "Limit attempts per account and per client address on this route — a middleware such as `express-rate-limit`, `@fastify/rate-limit`, or `@nestjs/throttler`, or the equivalent at the gateway — and return 429 once the budget is spent. For sign-in, add a per-account lockout or increasing delay so distributing the attack across addresses does not help.",
        verificationPlan:
          "Against a local instance with a test account only, send about 30 requests with a wrong credential in quick succession and confirm the later ones receive HTTP 429 or a lockout. Do not run this against an external target.",
        taxonomy: ["CWE-307", "CWE-799", "OWASP-A07"],
        location,
        ...routeOf(context, node),
        evidence: [
          sourceEvidence(context, node, `A ${flow} route; its handler ${WORK[flow]}.`),
          { kind: "dependency", description: "The project manifest declares no rate-limiting package, and this module never mentions limiting.", location: "package.json" }
        ],
        reasoning: `The route path matches a ${flow} flow, the handler performs ${flow === "sign-in" ? "a credential check" : flow === "sign-up" ? "password hashing" : "reset-token issuance"}, and neither the module text nor any declared dependency indicates a limiter.`
      });
    };

    // app.post("/login", ..., handler)
    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const tail = calleeTail(call);
      if (!["post", "put", "patch", "all"].includes(tail) || !ts.isPropertyAccessExpression(call.expression)) continue;
      const pathArgument = call.arguments[0];
      if (!pathArgument || !ts.isStringLiteralLike(pathArgument) || !pathArgument.text.startsWith("/")) continue;
      const handlers = call.arguments.slice(1);
      const handler = handlers[handlers.length - 1];
      if (!handler) continue;
      const body = handlerBody(handler);
      if (!body) continue;
      const middleware = handlers.slice(0, -1).map((argument) => argument.getText(context.file.source)).join(" ");
      consider(call, pathArgument.text, body.getText(context.file.source), middleware);
    }

    // Next.js: app/api/auth/login/route.ts exporting POST.
    const fileRoute = routeFromFilePath(context.file.relativePath);
    if (fileRoute && /\/route\.[cm]?[jt]s$/.test(context.file.relativePath)) {
      walk(context.file.source, (node) => {
        if (ts.isFunctionDeclaration(node) && node.name?.text === "POST" && node.body && exported(node)) {
          consider(node, fileRoute, node.body.getText(context.file.source), "");
        }
      });
    }
  }
};

type Flow = "sign-in" | "sign-up" | "password-reset";

const WORK: Record<Flow, string> = {
  "sign-in": "checks a credential",
  "sign-up": "hashes a new password and creates an account",
  "password-reset": "issues a reset token or sends a reset message"
};

const IMPACT: Record<Flow, string> = {
  "sign-in": "Unlimited guesses make password spraying and credential stuffing practical, and a one-time code of six digits falls to brute force in hours.",
  "sign-up": "Unlimited account creation lets one client mint accounts in bulk for spam or abuse, and each request costs a deliberately expensive password hash, which makes this route a cheap way to exhaust the server.",
  "password-reset": "Unlimited reset requests let anyone flood a victim's inbox and burn the application's email reputation, and make guessing a short reset code practical."
};

function flowOf(path: string, handlerText: string): Flow | null {
  if (CREDENTIAL_PATH.test(path) && CREDENTIAL_CHECK.test(handlerText)) return "sign-in";
  if (ENROLMENT_PATH.test(path) && ENROLMENT_WORK.test(handlerText)) return "sign-up";
  if (RESET_PATH.test(path) && (RESET_WORK.test(handlerText) || CREDENTIAL_CHECK.test(handlerText))) return "password-reset";
  return null;
}

function handlerBody(handler: ts.Expression): ts.Node | null {
  if (ts.isArrowFunction(handler) || ts.isFunctionExpression(handler)) return handler.body;
  if (ts.isIdentifier(handler)) {
    const declaration = declarationFor(handler);
    if (declaration && ts.isFunctionDeclaration(declaration) && declaration.body) return declaration.body;
    if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) {
      const init = declaration.initializer;
      if ((ts.isArrowFunction(init) || ts.isFunctionExpression(init)) && init.body) return init.body;
    }
  }
  // asyncHandler(async (req, res) => …)
  if (ts.isCallExpression(handler) && handler.arguments.length === 1) {
    const inner = handler.arguments[0]!;
    if ((ts.isArrowFunction(inner) || ts.isFunctionExpression(inner)) && /handler|wrap|catch/i.test(calleeName(handler))) return inner.body;
  }
  return null;
}

function exported(node: ts.FunctionDeclaration): boolean {
  return Boolean(node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword));
}
