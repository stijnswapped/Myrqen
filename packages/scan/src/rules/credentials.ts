import ts from "typescript";
import { calleeName, calleeTail, collect, expressionName, isConstantString, literalTextOf, walk } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, rootOf, taintOrigin } from "../ast/taint.js";
import { lineOf, type ParsedFile } from "../ast/parse.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext, routeFor } from "./context.js";

/**
 * How an application handles its own secrets: how it stores passwords, how it
 * compares credentials, where the unguessable values come from, how it decides a
 * token is genuine, and what it writes into a cookie.
 *
 * These rules replace the narrower checks in `crypto.ts` and `secrets.ts`; the
 * pairs are listed in SUPERSEDES so registration can retire the old ones rather
 * than report the same defect twice under two rule ids.
 */
export const SUPERSEDES: ReadonlyArray<{ retire: string; replacedBy: string }> = Object.freeze([
  { retire: "weak-token-generation", replacedBy: "predictable-security-value" },
  { retire: "weak-digest", replacedBy: "predictable-security-value / weak-password-storage / legacy-digest-algorithm" },
  { retire: "jwt-verification", replacedBy: "jwt-verification-bypass" },
  { retire: "insecure-cookie", replacedBy: "session-cookie-configuration" },
  { retire: "hardcoded-secret", replacedBy: "credential-literal" }
]);

/* ------------------------------------------------------------------ vocabulary */

/** Names that mean the value is a login credential rather than any other input. */
const PASSWORD_NAME = /pass(word|wd|phrase)|\bpwd\b|credentials?\b/i;

/** Names that mean the value must be unguessable to whoever receives it. */
const UNGUESSABLE_NAME =
  /(session|token|secret|nonce|csrf|xsrf|reset|verif(y|ication)|invit(e|ation)|api[_-]?key|apikey|password|passcode|otp|magic|challenge|credential|\bsid\b|\bsalt\b|recovery|activation|confirm|signature|handoff|onetime|one[_-]time)/i;

/** Names that mean an unpredictable value is a convenience, not a control. */
const BENIGN_RANDOM_NAME =
  /(jitter|backoff|retry|delay|sleep|animat|transition|shuffle|sample|placeholder|mock|stub|demo|fixture|colou?r|width|height|opacity|frame|dither|noise|spread|variance|percent|ratio|progress|jiggle|wobble|sprite|particle)/i;

/** Digest purposes that are not security decisions, so a legacy digest is fine. */
const NON_SECURITY_DIGEST = /(etag|cache|checksum|dedupe|dedup|shard|bucket|partition|gravatar|avatar|colou?r|icon|fingerprint_?ui|hash_?key|cache_?key|version)/i;

/** Names on either side of a comparison that make it a credential check. */
const SECRET_OPERAND = /(secret|token|signature|\bsig\b|hmac|\bmac\b|api[_-]?key|apikey|password|passcode|otp|digest|credential|bearer)/i;

/** Names that mean the value arrived with the request rather than from storage. */
const PRESENTED_NAME = /presented|provided|supplied|incoming|inbound|candidate|submitted|received|claimed|attempted|bearer|header/i;

/** Suffixes that mean the name is an identifier or a label, not the secret. */
const IDENTIFIER_SUFFIX = /(_id|Id|_ids|Ids|_name|Name|_index|Index|_count|Count|_type|Type|_kind|Kind|_length|Length|_size|Size|_prefix|Prefix|_at|At)$/;

/** Cookies whose theft or cross-site replay is a session compromise. */
const SESSION_COOKIE_NAME = /(sess|\bsid\b|_sid|auth|token|jwt|login|identity|refresh|access|remember|impersonat)/i;

/** Cookies that are readable by design and carry nothing an attacker can use. */
const NON_SENSITIVE_COOKIE =
  /(csrf|xsrf|theme|locale|lang|\btz\b|timezone|consent|banner|colou?r|layout|sidebar|font|currency|dismiss|tour|variant|utm|ab[_-]?test|preview[_-]?bar|cookie[_-]?notice)/i;

/** Keywords that are never a real credential, whatever the entropy looks like. */
const PLACEHOLDER_VALUE =
  /^(|x{3,}|\.{3,}|<[^>]+>|\{\{.*\}\}|\$\{.*\}|change[-_ ]?me|replace[-_ ]?me|your[-_ ].*|example|dummy|placeholder|todo|test|fake|sample|redacted|null|undefined|none|localhost)$/i;

/**
 * A real credential does not name itself. `alice-password-1` and `changeme` are
 * fixtures; reporting them teaches the reader that the rule cries wolf.
 */
const SELF_DESCRIBING_VALUE =
  /(password|passphrase|secret|token|apikey|api[-_]key|credential|changeme|example|sample|dummy|fixture|seed|placeholder|redacted)/i;

/** Prefixes that identify a public or publishable value, not a secret. */
const PUBLIC_VALUE_PREFIX = /^(pk_|pub_|price_|prod_|cus_|acct_|sub_|in_|pi_|seti_|whsec_test_|npm_public_|ghs_public_)/;

/** Credential shapes whose structure makes a coincidence implausible. */
const CREDENTIAL_SHAPES: ReadonlyArray<{ id: string; label: string; pattern: RegExp; live?: boolean }> = [
  { id: "stripe_live", label: "Stripe live secret key", pattern: /^(sk|rk)_live_[A-Za-z0-9]{10,}$/, live: true },
  { id: "stripe_test", label: "Stripe test secret key", pattern: /^(sk|rk)_test_[A-Za-z0-9]{10,}$/ },
  { id: "stripe_webhook", label: "Stripe webhook signing secret", pattern: /^whsec_[A-Za-z0-9]{20,}$/, live: true },
  { id: "openai", label: "OpenAI-style API key", pattern: /^sk-(proj-)?[A-Za-z0-9_-]{20,}$/, live: true },
  { id: "anthropic", label: "Anthropic API key", pattern: /^sk-ant-[A-Za-z0-9_-]{20,}$/, live: true },
  { id: "aws_access_key", label: "AWS access key id", pattern: /^(AKIA|ASIA)[0-9A-Z]{16}$/, live: true },
  { id: "google_api", label: "Google API key", pattern: /^AIza[0-9A-Za-z_-]{35}$/ },
  { id: "github_token", label: "GitHub token", pattern: /^gh[pousr]_[A-Za-z0-9]{20,}$/, live: true },
  { id: "slack_token", label: "Slack token", pattern: /^xox[abprs]-[A-Za-z0-9-]{10,}$/, live: true },
  { id: "jwt", label: "signed JSON Web Token", pattern: /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/ },
  { id: "private_key", label: "PEM private key", pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/, live: true },
  {
    id: "connection_string",
    label: "connection string with an inline password",
    pattern: /^[a-z0-9+.-]{2,20}:\/\/[^\s:@/]{1,64}:[^\s@/]{6,}@/i,
    live: true
  }
];

/** Password hashing work factors below which offline cracking is cheap. */
const MINIMUM_BCRYPT_COST = 10;
const MINIMUM_PBKDF2_ITERATIONS = 100_000;
const MINIMUM_SCRYPT_COST = 16_384;
/** Below the weakest tier OWASP still accepts for Argon2id (m=7168, t=5). */
const MINIMUM_ARGON2_MEMORY = 7_168;

const HTTP_METHOD_CALLS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all", "use"]);
const HTTP_METHOD_LITERALS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]);
const FRAMEWORK_RECEIVER = /^(app|router|server|api|fastify|route|r|instance|http)$/;

/* --------------------------------------------------- route attribution (local) */

/**
 * Route attribution for code that does not sit textually under its route.
 *
 * `routeFor` picks the nearest route declared *above* the sink, which is right
 * for a sink inside an inline handler and wrong for everything else in this
 * slice: a credential check lives in a middleware function declared above the
 * route that uses it, a token is minted in a helper two calls down, and a
 * hardcoded key sits at module scope in a file-routed module. A finding whose
 * `route` is empty cannot be re-tested against a running application, so the
 * attribution is resolved through the file's own handler registry instead.
 *
 * This belongs in `ast/routes.ts`; it is implemented here because that file is
 * owned elsewhere.
 */
interface HandlerRegistry {
  /** Handler name (as registered) to the route it serves. */
  routes: Map<string, string>;
  /** Handler name to the function node that implements it. */
  definitions: Map<string, ts.Node>;
  /** Function name to the names it calls. */
  calls: Map<string, Set<string>>;
}

const registryCache = new WeakMap<ts.SourceFile, HandlerRegistry>();

function registryFor(file: ParsedFile): HandlerRegistry {
  const cached = registryCache.get(file.source);
  if (cached) return cached;
  const registry: HandlerRegistry = { routes: new Map(), definitions: new Map(), calls: new Map() };
  collectDefinitions(file, registry);
  collectRegistrations(file, registry);
  collectRouteTables(file, registry);
  collectSwitchDispatch(file, registry);
  collectCallGraph(file, registry);
  registryCache.set(file.source, registry);
  return registry;
}

function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

function collectDefinitions(file: ParsedFile, registry: HandlerRegistry): void {
  walk(file.source, (node) => {
    if (ts.isFunctionDeclaration(node) && node.name) {
      registry.definitions.set(node.name.text, node);
      return;
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer && isFunctionLike(node.initializer)) {
      registry.definitions.set(node.name.text, node.initializer);
      return;
    }
    if (ts.isPropertyAssignment(node) && ts.isIdentifier(node.name) && isFunctionLike(node.initializer)) {
      registry.definitions.set(node.name.text, node.initializer);
      return;
    }
    // Fastify and Koa register named handlers on the instance:
    // `fastify.decorate("verifyPartnerToken", async (request, reply) => { ... })`.
    if (ts.isCallExpression(node) && /decorate|decorateRequest|register|addHandler|set/.test(calleeTail(node))) {
      const [name, implementation] = node.arguments;
      if (name && implementation && ts.isStringLiteralLike(name) && isFunctionLike(implementation)) {
        registry.definitions.set(name.text, implementation);
      }
    }
  });
}

/** Every handler name mentioned in a route registration's arguments. */
function harvestHandlerNames(argument: ts.Node, out: Set<string>, depth = 0): void {
  if (depth > 3) return;
  if (ts.isIdentifier(argument)) {
    out.add(argument.text);
    return;
  }
  if (ts.isPropertyAccessExpression(argument)) {
    out.add(argument.name.text);
    return;
  }
  if (ts.isArrayLiteralExpression(argument)) {
    for (const element of argument.elements) harvestHandlerNames(element, out, depth + 1);
    return;
  }
  if (ts.isObjectLiteralExpression(argument)) {
    for (const property of argument.properties) {
      if (ts.isPropertyAssignment(property)) harvestHandlerNames(property.initializer, out, depth + 1);
    }
  }
}

function collectRegistrations(file: ParsedFile, registry: HandlerRegistry): void {
  for (const call of collect(file.source, ts.isCallExpression)) {
    const tail = calleeTail(call).toLowerCase();
    if (!HTTP_METHOD_CALLS.has(tail)) continue;
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const receiver = call.expression.expression.getText(file.source);
    if (!FRAMEWORK_RECEIVER.test(receiver)) continue;
    const path = call.arguments[0] ? literalTextOf(call.arguments[0]!) : null;
    if (!path || !path.startsWith("/")) continue;

    const method = tail === "use" || tail === "all" ? "ANY" : tail.toUpperCase();
    const route = `${method} ${path}`;
    const names = new Set<string>();
    for (const argument of call.arguments.slice(1)) harvestHandlerNames(argument, names);
    for (const name of names) if (!registry.routes.has(name)) registry.routes.set(name, route);
  }
}

/** `const ROUTES = [{ method: "POST", path: "/portal/login", handler: signIn }]`. */
function collectRouteTables(file: ParsedFile, registry: HandlerRegistry): void {
  for (const literal of collect(file.source, ts.isObjectLiteralExpression)) {
    let path: string | null = null;
    let method = "ANY";
    let declaresMethod = false;
    let handlerKeys = 0;
    const handlers = new Set<string>();
    for (const property of literal.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const key = property.name.getText(file.source).replace(/['"]/g, "");
      const value = literalTextOf(property.initializer);
      if (/^(path|route|pathname|url)$/i.test(key) && value && value.startsWith("/")) path = value;
      else if (/^(method|verb)$/i.test(key) && value && HTTP_METHOD_LITERALS.has(value.toUpperCase())) {
        method = value.toUpperCase();
        declaresMethod = true;
      } else {
        if (/handler|fn|action|controller|callback|resolve|middleware/i.test(key)) handlerKeys += 1;
        harvestHandlerNames(property.initializer, handlers);
      }
    }
    // A cookie options object also carries `path: "/"`. A route table entry names
    // its method or its handler; requiring one of those keeps the two apart.
    if (!path || (!declaresMethod && handlerKeys === 0)) continue;
    for (const name of handlers) if (!registry.routes.has(name)) registry.routes.set(name, `${method} ${path}`);
  }
}

/** `switch (url.pathname) { case "/auth/password-reset": await requestReset(...) }`. */
function collectSwitchDispatch(file: ParsedFile, registry: HandlerRegistry): void {
  for (const clause of collect(file.source, ts.isCaseClause)) {
    const literal = literalTextOf(clause.expression);
    if (!literal) continue;
    const prefixed = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/\S*)$/.exec(literal);
    const path = prefixed ? prefixed[2]! : literal.startsWith("/") ? literal : null;
    if (!path) continue;
    const method = prefixed ? prefixed[1]! : methodGuardedIn(enclosingFunctionOf(clause) ?? file.source, file);

    const names = new Set<string>();
    for (const statement of clause.statements) {
      for (const call of collect(statement, ts.isCallExpression)) {
        const name = calleeTail(call);
        if (name) names.add(name);
      }
    }
    for (const name of names) if (!registry.routes.has(name)) registry.routes.set(name, `${method} ${path}`);
  }
}

/**
 * The single HTTP method a hand-rolled server accepts, from its own guard:
 * `if (request.method !== "POST") { respond(405) ... }` means every route this
 * dispatcher reaches is a POST.
 */
function methodGuardedIn(scope: ts.Node, file: ParsedFile): string {
  let found = "ANY";
  walk(scope, (node) => {
    if (found !== "ANY") return;
    if (!ts.isBinaryExpression(node)) return;
    const kind = node.operatorToken.kind;
    if (kind !== ts.SyntaxKind.ExclamationEqualsEqualsToken && kind !== ts.SyntaxKind.EqualsEqualsEqualsToken) return;
    for (const [subject, other] of [
      [node.left, node.right],
      [node.right, node.left]
    ] as const) {
      if (!/\b(method|verb)$/i.test(subject.getText(file.source))) continue;
      const value = literalTextOf(other);
      if (value && HTTP_METHOD_LITERALS.has(value.toUpperCase())) {
        found = value.toUpperCase();
        return;
      }
    }
  });
  return found;
}

function collectCallGraph(file: ParsedFile, registry: HandlerRegistry): void {
  for (const [name, node] of registry.definitions) {
    const callees = new Set<string>();
    walk(node, (inner) => {
      if (!ts.isCallExpression(inner)) return;
      const tail = calleeTail(inner);
      if (tail && tail !== name) callees.add(tail);
    });
    registry.calls.set(name, callees);
  }
}

function enclosingFunctionOf(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (isFunctionLike(current)) return current;
    current = current.parent;
  }
  return undefined;
}

/** The registered names of every function enclosing this node, innermost first. */
function enclosingHandlerNames(file: ParsedFile, node: ts.Node): string[] {
  const registry = registryFor(file);
  const byNode = new Map<ts.Node, string>();
  for (const [name, definition] of registry.definitions) if (!byNode.has(definition)) byNode.set(definition, name);

  const names: string[] = [];
  let current: ts.Node | undefined = node;
  while (current) {
    if (isFunctionLike(current)) {
      const name = byNode.get(current);
      if (name) names.push(name);
    }
    current = current.parent;
  }
  return names;
}

/**
 * The route a finding belongs to, following the file's own wiring when the sink
 * does not sit under its route registration.
 */
export function attributeRoute(context: RuleContext, node: ts.Node): string | undefined {
  const nearest = routeFor(context, node);
  if (nearest) return nearest;

  const registry = registryFor(context.file);
  const callers = new Map<string, Set<string>>();
  for (const [caller, callees] of registry.calls) {
    for (const callee of callees) {
      const bucket = callers.get(callee) ?? new Set<string>();
      bucket.add(caller);
      callers.set(callee, bucket);
    }
  }

  const queue = enclosingHandlerNames(context.file, node);
  const seen = new Set<string>(queue);
  for (let depth = 0; depth < 6 && queue.length > 0; depth += 1) {
    const generation = queue.splice(0, queue.length);
    for (const name of generation) {
      const route = registry.routes.get(name);
      if (route) return route;
    }
    for (const name of generation) {
      for (const caller of callers.get(name) ?? []) {
        if (seen.has(caller)) continue;
        seen.add(caller);
        queue.push(caller);
      }
    }
  }

  // Module-scope code in a file-routed module runs for that module's route.
  if (!enclosingFunctionOf(node) && context.routes.length > 0) {
    const paths = new Set(context.routes.map((hint) => hint.path));
    if (paths.size === 1) {
      const first = context.routes[0]!;
      return first.method === "ANY" ? first.path : `${first.method} ${first.path}`;
    }
  }
  return undefined;
}

function withRoute(context: RuleContext, node: ts.Node): { route?: string } {
  const route = attributeRoute(context, node);
  return route ? { route } : {};
}

/* -------------------------------------------------------------- shared helpers */

function unwrap(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isSatisfiesExpression(current) || ts.isTypeAssertionExpression(current) || ts.isAwaitExpression(current)) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/** The initializer a name was declared with anywhere in this file. */
function declaredValue(file: ParsedFile, name: string): ts.Expression | null {
  let found: ts.Expression | null = null;
  walk(file.source, (node) => {
    if (found) return;
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name && node.initializer) {
      found = node.initializer;
    }
  });
  return found;
}

/**
 * Follow a name to the value it holds. Options objects and cost factors are
 * routinely hoisted into a module constant, and a rule that reads only the call
 * site sees an identifier and concludes the flag is missing — which is exactly
 * the false positive that makes a cookie rule untrustworthy.
 */
function resolveValue(file: ParsedFile, node: ts.Node): ts.Node {
  let current = unwrap(node);
  for (let depth = 0; depth < 4; depth += 1) {
    if (!ts.isIdentifier(current)) return current;
    const declared = declaredValue(file, current.text);
    if (!declared) return current;
    current = unwrap(declared);
  }
  return current;
}

function numberValueOf(file: ParsedFile, node: ts.Node | undefined): number | null {
  if (!node) return null;
  const resolved = resolveValue(file, node);
  if (ts.isNumericLiteral(resolved)) return Number(resolved.text.replace(/_/g, ""));
  if (
    ts.isBinaryExpression(resolved) &&
    (resolved.operatorToken.kind === ts.SyntaxKind.AsteriskToken || resolved.operatorToken.kind === ts.SyntaxKind.LessThanLessThanToken)
  ) {
    const left = numberValueOf(file, resolved.left);
    const right = numberValueOf(file, resolved.right);
    if (left === null || right === null) return null;
    return resolved.operatorToken.kind === ts.SyntaxKind.AsteriskToken ? left * right : left << right;
  }
  return null;
}

/** The nearest name this expression's result is stored under. */
function assignmentTargetName(file: ParsedFile, node: ts.Node): string | null {
  let current: ts.Node | undefined = node;
  for (let depth = 0; current && depth < 8; depth += 1) {
    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) return current.name.text;
    if (ts.isPropertyAssignment(current)) return current.name.getText(file.source).replace(/['"]/g, "");
    if (ts.isShorthandPropertyAssignment(current)) return current.name.text;
    if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      return current.left.getText(file.source);
    }
    current = current.parent;
  }
  return null;
}

/**
 * Every name that describes what this value is *for*.
 *
 * A generator usually returns its value rather than assigning it — `return
 * Math.random().toString(36)` inside `buildToken()` — so the purpose lives in the
 * function's name and in the names its callers store the result under. Reading
 * only the assignment target misses the most common shape there is.
 */
function purposeNames(file: ParsedFile, node: ts.Node): string[] {
  const names: string[] = [];
  const direct = assignmentTargetName(file, node);
  if (direct) names.push(direct);

  const handlers = enclosingHandlerNames(file, node);
  names.push(...handlers);

  const registry = registryFor(file);
  for (const handler of handlers) {
    const definition = registry.definitions.get(handler);
    walk(file.source, (inner) => {
      if (!ts.isVariableDeclaration(inner) || !ts.isIdentifier(inner.name) || !inner.initializer) return;
      const initializer = unwrap(inner.initializer);
      if (!ts.isCallExpression(initializer)) return;
      if (calleeTail(initializer) !== handler) return;
      if (definition && initializer.getStart(file.source) >= definition.getStart(file.source) && initializer.getEnd() <= definition.getEnd()) {
        return;
      }
      names.push(inner.name.text);
    });
  }
  return names;
}

function anyMatches(names: readonly string[], pattern: RegExp): boolean {
  return names.some((name) => pattern.test(name));
}

/** The last dotted segment of an expression's name, for `key.secret_token`. */
function lastSegment(text: string): string {
  const cleaned = text.replace(/\?\.$/, "").trim();
  const index = cleaned.lastIndexOf(".");
  return index === -1 ? cleaned : cleaned.slice(index + 1);
}

/* ------------------------------------------------------------- digest analysis */

interface DigestSite {
  /** The `createHash("sha256")` / `createHmac(...)` call itself. */
  call: ts.CallExpression;
  algorithm: string;
  keyed: boolean;
  /** Every value fed in through `.update(...)`. */
  inputs: ts.Expression[];
  /** Where the digest ends up, and what the enclosing helper is called. */
  purposes: string[];
}

const LEGACY_DIGESTS = new Set(["md5", "sha1", "sha-1", "md4", "ripemd160", "rmd160"]);

function digestSites(context: RuleContext): DigestSite[] {
  const sites: DigestSite[] = [];
  for (const call of collect(context.file.source, ts.isCallExpression)) {
    const tail = calleeTail(call);
    if (tail !== "createHash" && tail !== "createHmac") continue;
    const algorithmNode = call.arguments[0];
    if (!algorithmNode) continue;
    const algorithm = literalTextOf(resolveValue(context.file, algorithmNode));
    if (!algorithm) continue;

    // Walk out through `.update(x).update(y).digest("hex")` to find the inputs.
    const inputs: ts.Expression[] = [];
    let outer: ts.Node = call;
    for (let depth = 0; depth < 8; depth += 1) {
      const parent: ts.Node | undefined = outer.parent;
      if (!parent) break;
      if (ts.isPropertyAccessExpression(parent) && parent.expression === outer) {
        outer = parent;
        continue;
      }
      if (ts.isCallExpression(parent) && parent.expression !== outer) break;
      if (!ts.isCallExpression(parent)) break;
      if (calleeTail(parent) === "update") inputs.push(...parent.arguments);
      outer = parent;
    }

    sites.push({
      call,
      algorithm: algorithm.toLowerCase(),
      keyed: tail === "createHmac",
      inputs,
      purposes: purposeNames(context.file, outer)
    });
  }
  return sites;
}

/**
 * Is every part of this value something an attacker can observe, enumerate, or
 * compute? A digest is only as unguessable as its inputs, so hashing a user id,
 * a counter and the clock produces a value that can be reconstructed offline —
 * while hashing a 256-bit random token is the correct way to store it.
 */
function isPredictableComposition(file: ParsedFile, node: ts.Node, depth = 0): boolean {
  if (depth > 6) return false;
  const resolved = unwrap(resolveValue(file, node));

  if (ts.isStringLiteralLike(resolved) || ts.isNumericLiteral(resolved) || ts.isNoSubstitutionTemplateLiteral(resolved)) return true;

  if (ts.isTemplateExpression(resolved)) {
    return resolved.templateSpans.every((span) => isPredictableComposition(file, span.expression, depth + 1));
  }
  if (ts.isBinaryExpression(resolved) && resolved.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return isPredictableComposition(file, resolved.left, depth + 1) && isPredictableComposition(file, resolved.right, depth + 1);
  }
  if (ts.isCallExpression(resolved)) {
    const name = calleeName(resolved);
    if (/^(Date\.now|performance\.now|process\.hrtime|Date\.parse)$/.test(name)) return true;
    if (/^(String|Number|BigInt|parseInt)$/.test(name)) {
      return resolved.arguments.every((argument) => isPredictableComposition(file, argument, depth + 1));
    }
    if (/^(toString|toISOString|getTime|valueOf|padStart|padEnd|slice|toLowerCase|toUpperCase)$/.test(calleeTail(resolved))) {
      const receiver = ts.isPropertyAccessExpression(resolved.expression) ? resolved.expression.expression : null;
      return receiver ? isPredictableComposition(file, receiver, depth + 1) : false;
    }
    return false;
  }
  if (ts.isNewExpression(resolved) && expressionName(resolved.expression) === "Date") return true;
  if (ts.isPropertyAccessExpression(resolved) || ts.isElementAccessExpression(resolved)) {
    // A row id, a tenant id, an email: all things an attacker knows or enumerates.
    return /(\bid$|_id$|Id$|email|name|slug|reference|number|index|count|seq|size|length|total|pid|host)/i.test(
      lastSegment(resolved.getText(file.source))
    );
  }
  if (ts.isIdentifier(resolved)) return isCounterLike(file, resolved.text);
  return false;
}

/** A module-level variable that is only ever incremented is a counter. */
function isCounterLike(file: ParsedFile, name: string): boolean {
  if (/(count|counter|seq|sequence|serial|index|idx|tick|nth|ordinal|issued|next)/i.test(name)) {
    let incremented = false;
    walk(file.source, (node) => {
      if (ts.isPostfixUnaryExpression(node) || ts.isPrefixUnaryExpression(node)) {
        if (node.operator === ts.SyntaxKind.PlusPlusToken && node.operand.getText(file.source) === name) incremented = true;
        return;
      }
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken &&
        node.left.getText(file.source) === name
      ) {
        incremented = true;
      }
    });
    return incremented;
  }
  return false;
}

/* ------------------------------------------------- weak password storage */

/** Key-derivation calls, with the argument position that carries the work factor. */
const KDF_COST: ReadonlyArray<{ match: RegExp; label: string; costArgument: number; minimum: number; unit: string }> = [
  { match: /^(bcrypt\.)?hash(Sync)?$/, label: "bcrypt", costArgument: 1, minimum: MINIMUM_BCRYPT_COST, unit: "rounds" },
  { match: /^pbkdf2(Sync)?$/, label: "PBKDF2", costArgument: 2, minimum: MINIMUM_PBKDF2_ITERATIONS, unit: "iterations" }
];

export const weakPasswordStorage: Rule = {
  id: "weak-password-storage",
  category: "weak_password_hashing",
  describes: "passwords stored as a fast digest or with a work factor below current practice",
  run(context: RuleContext) {
    for (const site of digestSites(context)) {
      const inputNames = site.inputs.map((input) => input.getText(context.file.source));
      const looksLikeAPassword = anyMatches([...inputNames, ...site.purposes], PASSWORD_NAME);
      if (!looksLikeAPassword) continue;
      // `bcrypt.compare(password, row.passwordHash)` is a verification, not storage.
      if (site.inputs.length === 0) continue;

      const digestName = site.keyed ? `HMAC-${site.algorithm.toUpperCase()}` : site.algorithm.toUpperCase();
      context.report({
        ruleId: "weak-password-storage",
        category: "weak_password_hashing",
        title: `A password is stored as a bare ${digestName} digest`,
        severity: "high",
        verification: "strong_evidence",
        summary: `The password is turned into a ${digestName} digest and stored. A general-purpose digest is designed to be fast, so it offers no resistance to offline guessing, and without a per-user salt two accounts that chose the same password produce the same stored value.`,
        impact:
          "If the user table is ever read — a backup, a log, an injection, a restored snapshot — the passwords are recoverable at billions of guesses per second on commodity hardware, and every account that reused its password elsewhere falls with it.",
        remediation:
          "Store the password with a memory-hard password hashing function: Argon2id (m=19456, t=2, p=1), scrypt (N=2^15), or bcrypt with a cost of at least 12. Each generates its own salt, so remove the hand-rolled one. Rehash on the next successful sign-in rather than migrating in place.",
        verificationPlan:
          "Read one stored value: a password hash from a proper KDF carries its algorithm and parameters in the string (`$argon2id$v=19$m=…`). A bare 64-character hex string confirms the digest. Confirm two accounts with the same password store different values.",
        taxonomy: ["CWE-916", "CWE-759", "OWASP-A02"],
        location: locationOf(context, site.call),
        ...withRoute(context, site.call),
        evidence: [
          sourceEvidence(context, site.call, `The password is hashed with ${digestName} rather than a password hashing function.`)
        ],
        reasoning: `createHash${site.keyed ? "/createHmac" : ""}("${site.algorithm}") receives ${inputNames.join(", ") || "a password"} and the result is stored as ${site.purposes[0] ?? "a password hash"}.`
      });
    }

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const name = calleeName(call);
      const tail = calleeTail(call);
      const spec = KDF_COST.find((candidate) => candidate.match.test(name) || candidate.match.test(tail));
      if (!spec) continue;

      const subject = call.arguments[0];
      if (!subject) continue;
      const purposes = [subject.getText(context.file.source), ...purposeNames(context.file, call)];
      if (!anyMatches(purposes, PASSWORD_NAME)) continue;

      const cost = numberValueOf(context.file, call.arguments[spec.costArgument]);
      if (cost === null || cost >= spec.minimum) continue;

      context.report({
        ruleId: "weak-password-kdf-cost",
        category: "weak_password_hashing",
        title: `${spec.label} is configured with ${cost} ${spec.unit}, far below current practice`,
        severity: "medium",
        verification: "strong_evidence",
        summary: `The password passes through ${spec.label}, which is the right family of function, but the work factor is ${cost} ${spec.unit} where at least ${spec.minimum} is needed today. The cost is what makes the function slow enough to matter, so setting it low removes most of the protection.`,
        impact:
          "An attacker with the password table tries orders of magnitude more candidates per second than the parameters intend, which brings weak and reused passwords back within reach of a commodity GPU.",
        remediation: `Raise the work factor to at least ${spec.minimum} ${spec.unit} and rehash each password on the next successful sign-in. Measure the resulting time on production hardware and target roughly 100 ms per hash.`,
        verificationPlan:
          "Time a sign-in against a warm database and confirm the hash step takes on the order of 100 ms, then read a stored value and confirm the encoded parameters match the intended cost.",
        taxonomy: ["CWE-916", "OWASP-A02"],
        location: locationOf(context, call),
        ...withRoute(context, call),
        evidence: [sourceEvidence(context, call, `${spec.label} work factor is ${cost}.`)],
        reasoning: `${spec.label} is called with a password and a ${spec.unit} value of ${cost}, below the minimum of ${spec.minimum}.`
      });
    }

    // scrypt and Argon2 carry their cost in an options object rather than a number.
    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const name = calleeName(call);
      const tail = calleeTail(call);
      const isScrypt = /^scrypt(Sync)?$/.test(tail);
      const isArgon = /argon2/i.test(name) && (tail === "hash" || tail === "hashSync");
      if (!isScrypt && !isArgon) continue;

      const subject = call.arguments[0];
      if (!subject) continue;
      if (!anyMatches([subject.getText(context.file.source), ...purposeNames(context.file, call)], PASSWORD_NAME)) continue;

      const options = call.arguments.map((argument) => resolveValue(context.file, argument)).find(ts.isObjectLiteralExpression);
      if (!options) continue;
      const property = (key: string): number | null => {
        for (const member of options.properties) {
          if (!ts.isPropertyAssignment(member)) continue;
          if (member.name.getText(context.file.source).replace(/['"]/g, "") !== key) continue;
          return numberValueOf(context.file, member.initializer);
        }
        return null;
      };

      const label = isScrypt ? "scrypt" : "Argon2";
      const cost = isScrypt ? (property("N") ?? property("cost")) : property("memoryCost");
      const minimum = isScrypt ? MINIMUM_SCRYPT_COST : MINIMUM_ARGON2_MEMORY;
      const unit = isScrypt ? "cost parameter N" : "memoryCost (KiB)";
      if (cost === null || cost >= minimum) continue;

      context.report({
        ruleId: "weak-password-kdf-cost",
        category: "weak_password_hashing",
        title: `${label} is configured with a ${unit} of ${cost}, below any accepted tier`,
        severity: "medium",
        verification: "strong_evidence",
        summary: `The password passes through ${label} with a ${unit} of ${cost}. That is below the weakest parameter set still considered adequate (${minimum}), so the function completes far faster than intended and the memory-hardness that defeats GPU cracking is largely absent.`,
        impact:
          "The stored hashes fall to offline guessing much faster than the choice of algorithm suggests, so a leaked table exposes weak and reused passwords.",
        remediation: `Raise the ${unit} to at least ${minimum} and rehash on the next successful sign-in. For Argon2id use m=19456, t=2, p=1; for scrypt use N=2^15, r=8, p=1.`,
        verificationPlan:
          "Read one stored hash and confirm the encoded parameters, then time a sign-in on production hardware and confirm the hash step is on the order of 100 ms.",
        taxonomy: ["CWE-916", "OWASP-A02"],
        location: locationOf(context, call),
        ...withRoute(context, call),
        evidence: [sourceEvidence(context, call, `${label} ${unit} is ${cost}.`)],
        reasoning: `${label} hashes a password with ${unit}=${cost}, below the minimum of ${minimum}.`
      });
    }
  }
};

/* --------------------------------------------- timing-unsafe secret comparison */

const EQUALITY_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken
]);

const NOT_A_VALUE = new Set(["undefined", "null", "NaN", "true", "false"]);

/**
 * Is this operand a runtime value that could be a secret, rather than a literal,
 * a length, or a type tag? Requiring both operands to be real values is what
 * keeps `token !== undefined` and `url.pathname === "/x"` out of the results.
 */
function isComparableValue(file: ParsedFile, node: ts.Expression): boolean {
  const resolved = unwrap(node);
  if (ts.isStringLiteralLike(resolved) || ts.isNumericLiteral(resolved) || ts.isTemplateExpression(resolved)) return false;
  if (ts.isTypeOfExpression(resolved) || ts.isPrefixUnaryExpression(resolved)) return false;
  if (ts.isIdentifier(resolved)) return !NOT_A_VALUE.has(resolved.text);
  if (ts.isPropertyAccessExpression(resolved)) {
    return !/^(length|size|byteLength|constructor)$/.test(resolved.name.text);
  }
  if (ts.isElementAccessExpression(resolved) || ts.isCallExpression(resolved)) return true;
  void file;
  return false;
}

/**
 * Is this expression a digest rather than the secret itself?
 *
 * Comparing two digests is the recommended fix, not the defect: recovering a
 * prefix of `SHA-256(secret)` a byte at a time does not invert the hash, and an
 * integrity check between a computed digest and a published one has no secret to
 * recover at all. Flagging those would contradict this rule's own remediation.
 */
function isDigestExpression(file: ParsedFile, node: ts.Expression): boolean {
  const resolved = unwrap(resolveValue(file, node));
  const text = resolved.getText(file.source);
  if (/\bcreate(Hash|Hmac)\s*\(/.test(text)) return true;
  if (!ts.isCallExpression(resolved)) return false;
  if (calleeTail(resolved) === "digest") return true;
  return /(^|\.)(sha1|sha224|sha256|sha384|sha512|md5|blake2b?|hash|hmac|digest|fingerprint|checksum)[A-Za-z0-9_]*$/i.test(
    calleeName(resolved)
  );
}

/** Does this name mean "the secret itself", rather than a label for it? */
function isSecretOperand(text: string): boolean {
  const segment = lastSegment(text);
  if (IDENTIFIER_SUFFIX.test(segment)) return false;
  return SECRET_OPERAND.test(segment);
}

/** Is the comparison's result what decides whether the request continues? */
function isDecisionSite(node: ts.Node): boolean {
  let current: ts.Node | undefined = node;
  for (let depth = 0; current && depth < 6; depth += 1) {
    const parent: ts.Node | undefined = current.parent;
    if (!parent) return false;
    if (ts.isIfStatement(parent) && parent.expression === current) return true;
    if (ts.isWhileStatement(parent) && parent.expression === current) return true;
    if (ts.isConditionalExpression(parent) && parent.condition === current) return true;
    if (ts.isReturnStatement(parent)) return true;
    if (ts.isVariableDeclaration(parent) && parent.initializer === current) return true;
    if (ts.isPrefixUnaryExpression(parent) && parent.operator === ts.SyntaxKind.ExclamationToken) {
      current = parent;
      continue;
    }
    if (ts.isBinaryExpression(parent) || ts.isParenthesizedExpression(parent)) {
      current = parent;
      continue;
    }
    return false;
  }
  return false;
}

function reportTimingUnsafe(context: RuleContext, node: ts.Node, subject: string, form: string): void {
  context.report({
    ruleId: "timing-unsafe-secret-comparison",
    category: "timing_unsafe_comparison",
    title: `Secret \`${subject}\` is compared with ${form}`,
    severity: "medium",
    verification: "strong_evidence",
    summary: `The presented value is checked against the stored secret using ${form}, which stops at the first byte that differs. The time the comparison takes therefore depends on how many leading bytes were correct, and that difference is measurable across enough requests.`,
    impact:
      "A caller who can submit guesses recovers the secret one byte at a time instead of searching the whole space, which turns an unguessable credential into a few thousand requests. The account or integration the secret protects is then fully accessible.",
    remediation:
      "Compare with crypto.timingSafeEqual over Buffers of equal length: reject on a length mismatch first (the lengths are not secret), then compare. Where the secret is stored, keep only a digest of it and compare digests, which makes both sides fixed-length.",
    verificationPlan:
      "Send a large number of guesses that share an increasing prefix with a known-valid secret and confirm the response-time distribution does not separate by prefix length. Combine with a check that the endpoint is rate limited.",
    taxonomy: ["CWE-208", "CWE-1254", "OWASP-A02"],
    location: locationOf(context, node),
    ...withRoute(context, node),
    evidence: [sourceEvidence(context, node, `The secret is compared with ${form} rather than a constant-time comparison.`)],
    reasoning: `A comparison with ${form} whose operand \`${subject}\` names a credential, used as the condition that admits or rejects the request.`
  });
}

export const timingUnsafeSecretComparison: Rule = {
  id: "timing-unsafe-secret-comparison",
  category: "timing_unsafe_comparison",
  describes: "credentials compared with a short-circuiting operator instead of a constant-time one",
  run(context: RuleContext) {
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);

      /**
       * A timing side channel needs an attacker who can iterate: one side of the
       * comparison has to be a value they submitted, and the other a value the
       * server holds. Requiring that shape is what keeps the rule off
       * `ts.SyntaxKind.PlusToken === node.operatorToken.kind` and off a digest
       * check between two values the caller cannot influence — both contain the
       * word "token" and neither is a credential check.
       */
      const attackerControlled = (operand: ts.Expression): boolean => {
        if (taintOrigin(operand, scope) !== null) return true;
        return PRESENTED_NAME.test(lastSegment(operand.getText(context.file.source)));
      };

      /**
       * Two values read from the same request are not a presented-versus-stored
       * check. `password !== confirmPassword` is a form validation, and the stored
       * side of a real check is frequently reached *through* the request object
       * (`req.app.locals.db`), so demanding that it be untainted would lose most
       * genuine findings rather than gain precision.
       */
      const sameSource = (left: ts.Expression, right: ts.Expression): boolean => {
        const leftRoot = rootOf(left);
        const rightRoot = rootOf(right);
        if (leftRoot !== null && leftRoot === rightRoot) return true;
        const leftOrigin = taintOrigin(left, scope);
        return leftOrigin !== null && leftOrigin === taintOrigin(right, scope);
      };

      for (const comparison of collect(fn, ts.isBinaryExpression)) {
        if (reported.has(comparison.getStart(context.file.source))) continue;
        if (!EQUALITY_OPERATORS.has(comparison.operatorToken.kind)) continue;
        if (!isComparableValue(context.file, comparison.left) || !isComparableValue(context.file, comparison.right)) continue;

        const leftText = comparison.left.getText(context.file.source);
        const rightText = comparison.right.getText(context.file.source);
        const subject = isSecretOperand(leftText) ? leftText : isSecretOperand(rightText) ? rightText : null;
        if (!subject) continue;
        if (!isDecisionSite(comparison)) continue;
        if (!attackerControlled(comparison.left) && !attackerControlled(comparison.right)) continue;
        if (sameSource(comparison.left, comparison.right)) continue;
        if (isDigestExpression(context.file, comparison.left) || isDigestExpression(context.file, comparison.right)) continue;

        reported.add(comparison.getStart(context.file.source));
        const form = comparison.operatorToken.getText(context.file.source);
        reportTimingUnsafe(context, comparison, subject, `\`${form}\``);
      }

      for (const call of collect(fn, ts.isCallExpression)) {
        if (reported.has(call.getStart(context.file.source))) continue;
        if (calleeTail(call) !== "localeCompare") continue;
        if (!ts.isPropertyAccessExpression(call.expression)) continue;
        const receiver = call.expression.expression;
        const argument = call.arguments[0];
        if (!argument) continue;
        const receiverText = receiver.getText(context.file.source);
        const argumentText = argument.getText(context.file.source);
        const subject = isSecretOperand(receiverText) ? receiverText : isSecretOperand(argumentText) ? argumentText : null;
        if (!subject) continue;
        if (!isDecisionSite(call)) continue;
        if (!attackerControlled(receiver) && !attackerControlled(argument)) continue;
        if (sameSource(receiver, argument)) continue;
        if (isDigestExpression(context.file, receiver) || isDigestExpression(context.file, argument)) continue;

        reported.add(call.getStart(context.file.source));
        reportTimingUnsafe(context, call, subject, "`.localeCompare`");
      }
    }
  }
};

/* ------------------------------------------- predictable security-bearing values */

/** Purposes where the value is handed to a caller and must be unguessable. */
const HANDED_OUT_SECRET =
  /(token|nonce|otp|passcode|invit(e|ation)|magic|reset|verif(y|ication)|challenge|session[_-]?id|sessionid|\bsid\b|csrf|xsrf|api[_-]?key|apikey|secret|recovery|activation|handoff)/i;

/** Purposes that are timestamps or durations rather than credentials. */
const TIME_LIKE = /(expir|\bttl\b|until|deadline|created|updated|issued[_-]?at|_at$|At$|timestamp|_ms$|_sec|seconds|minutes|hours|age$|window|interval|duration)/i;

/** Collections whose keys are session handles rather than ordinary records. */
const SESSION_STORE_NAME = /(session|sess\b|\bsid\b|_sid|logins?$|authenticated)/i;

/** Methods that write a value into such a collection under its own key. */
const SESSION_WRITE_METHOD = new Set(["set", "add", "put", "insert", "save", "store", "create", "setex", "hset"]);

function isSessionPurpose(purposes: readonly string[]): boolean {
  return anyMatches(purposes, /(session|\bsid\b|_sid|cookie|login|identity)/i);
}

function unguessablePurpose(purposes: readonly string[]): boolean {
  if (purposes.length === 0) return false;
  if (anyMatches(purposes, BENIGN_RANDOM_NAME)) return false;
  return anyMatches(purposes, UNGUESSABLE_NAME);
}

function wordPattern(name: string): RegExp {
  return new RegExp(`(^|[^A-Za-z0-9_$])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^A-Za-z0-9_$]|$)`);
}

/**
 * The cookie a Set-Cookie string writes, when the given binding is its value.
 *
 * `set-cookie: \`session=${token}; Path=/\`` names the cookie in the header text
 * rather than in an argument, so the shape has to be read out of the literal.
 */
function setCookieUse(file: ParsedFile, value: ts.Node, binding: string): string | null {
  const text = value.getText(file.source);
  const declared = /^[`'"]?\s*([A-Za-z0-9_.-]+)\s*=/.exec(text.replace(/^[`'"]/, ""));
  const cookieName = declared?.[1];
  if (!cookieName) return null;
  if (!SESSION_COOKIE_NAME.test(cookieName) || NON_SENSITIVE_COOKIE.test(cookieName)) return null;
  if (!wordPattern(binding).test(text)) return null;
  return `it is written into the \`${cookieName}\` cookie`;
}

/**
 * How the value is *used*, when that is what makes it a session identifier.
 *
 * A local called `token` that becomes a key in a map called `sessions` and is
 * then written into a cookie called `session` is a session identifier whatever
 * the binding is named. Use is stronger evidence than a variable name, and
 * classifying on the name alone puts the finding in the wrong class — which for
 * a reader means the wrong remediation and the wrong blast radius.
 */
function sessionUseOf(file: ParsedFile, candidates: readonly string[]): string | null {
  const bindings = candidates.filter((name) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name));
  if (bindings.length === 0) return null;
  let found: string | null = null;

  walk(file.source, (node) => {
    if (found) return;

    // `sessions.set(token, { userId })`, `sessionStore.put(sid, …)`, `redis.setex(sid, …)`.
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text;
      const receiver = node.expression.expression.getText(file.source);
      if (SESSION_WRITE_METHOD.has(method) && SESSION_STORE_NAME.test(lastSegment(receiver))) {
        const key = node.arguments[0]?.getText(file.source);
        if (key && bindings.includes(key)) {
          found = `it becomes the key of \`${receiver}.${method}()\``;
          return;
        }
      }
      // `reply.setCookie(SESSION_COOKIE, token, …)`, `res.cookie("sid", token)`.
      const tail = calleeTail(node);
      if (/cookie/i.test(calleeName(node)) && /^(cookie|setCookie|set|append)$/.test(tail)) {
        const first = node.arguments[0];
        const cookieName = first ? (literalTextOf(resolveValue(file, first)) ?? first.getText(file.source)) : "";
        const valueText = node.arguments[1]?.getText(file.source) ?? "";
        if (
          SESSION_COOKIE_NAME.test(cookieName) &&
          !NON_SENSITIVE_COOKIE.test(cookieName) &&
          bindings.some((binding) => wordPattern(binding).test(valueText))
        ) {
          found = `it is written into the \`${cookieName}\` cookie`;
          return;
        }
      }
      // `response.setHeader("set-cookie", `session=${token}; Path=/`)`.
      if (/^(setHeader|append|writeHead)$/.test(tail)) {
        const header = node.arguments[0] ? literalTextOf(node.arguments[0]!) : null;
        const payload = node.arguments[1];
        if (header && /^set-cookie$/i.test(header) && payload) {
          for (const binding of bindings) {
            const use = setCookieUse(file, payload, binding);
            if (use) {
              found = use;
              return;
            }
          }
        }
      }
      return;
    }

    // `{ "set-cookie": `session=${token}; Path=/` }` inside a headers object.
    if (ts.isPropertyAssignment(node)) {
      const key = node.name.getText(file.source).replace(/['"]/g, "");
      if (!/^set-cookie$/i.test(key)) return;
      for (const binding of bindings) {
        const use = setCookieUse(file, node.initializer, binding);
        if (use) {
          found = use;
          return;
        }
      }
      return;
    }

    // `sessions[token] = { userId }`.
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isElementAccessExpression(node.left)
    ) {
      const receiver = node.left.expression.getText(file.source);
      const key = node.left.argumentExpression.getText(file.source);
      if (SESSION_STORE_NAME.test(lastSegment(receiver)) && bindings.includes(key)) {
        found = `it becomes the key of \`${receiver}[]\``;
      }
    }
  });

  return found;
}

/**
 * One decision shared by every rule that looks at a generated value, so a single
 * defect can never be reported twice under two categories.
 */
interface SecurityPurpose {
  /** The value has to be unguessable to whoever receives it. */
  unguessable: boolean;
  /** It is specifically a session handle. */
  session: boolean;
  /** How the file shows that, when the evidence is a use rather than a name. */
  use: string | null;
}

function classifySecurityPurpose(file: ParsedFile, purposes: readonly string[]): SecurityPurpose {
  if (anyMatches(purposes, BENIGN_RANDOM_NAME)) return { unguessable: false, session: false, use: null };
  const use = sessionUseOf(file, purposes);
  const session = isSessionPurpose(purposes) || use !== null;
  return { unguessable: unguessablePurpose(purposes) || use !== null, session, use };
}

interface PredictableReport {
  node: ts.Node;
  purposes: string[];
  purpose: SecurityPurpose;
  source: string;
  detail: string;
}

function reportPredictable(context: RuleContext, finding: PredictableReport): void {
  const session = finding.purpose.session;
  const subject = finding.purposes[0] ?? "the value";
  const useNote = finding.purpose.use ? ` The value's role is settled by how it is used: ${finding.purpose.use}.` : "";
  context.report({
    ruleId: session ? "predictable-session-identifier" : "predictable-security-value",
    category: session ? "weak_session_identifier" : "insecure_randomness",
    title: session
      ? `Session identifier \`${subject}\` is derived from ${finding.source}`
      : `Security-bearing value \`${subject}\` is derived from ${finding.source}`,
    severity: "high",
    verification: "strong_evidence",
    summary: `\`${subject}\` has to be unguessable to whoever receives it, but it is produced from ${finding.source}. ${finding.detail}${useNote}`,
    impact: session
      ? "An attacker who can reconstruct the inputs computes a valid session identifier offline and uses it without ever presenting a credential, which is account takeover with no sign-in and no audit trail that looks unusual."
      : "An attacker who observes or enumerates the inputs computes the value that was issued to somebody else, and uses it for whatever it authorises: resetting that account's password, redeeming their invitation, or replaying their one-time code.",
    remediation:
      "Draw the value from a cryptographic source with at least 128 bits of entropy — crypto.randomBytes(32) rendered base64url, or crypto.randomUUID() where a UUID is wanted — and derive nothing about it from the account, the clock, or a counter. Store only a SHA-256 digest of it so a leak of the table does not yield working values.",
    verificationPlan:
      "Request several values in quick succession and confirm they show no shared structure, no monotonic component, and no relationship to the account or the time of issue. Then confirm a value minted for one account cannot be predicted from values minted for another.",
    taxonomy: session ? ["CWE-330", "CWE-384", "OWASP-A07"] : ["CWE-338", "CWE-330", "OWASP-A02"],
    location: locationOf(context, finding.node),
    ...withRoute(context, finding.node),
    evidence: [sourceEvidence(context, finding.node, `${subject} is produced from ${finding.source}.`)],
    reasoning: `The value is built from ${finding.source}. ${
      finding.purpose.use
        ? `It is classified as a session identifier because ${finding.purpose.use}, which is stronger evidence than the binding name.`
        : `Its purpose names (${finding.purposes.join(", ")}) mark it as security-bearing.`
    }`
  });
}

export const predictableSecurityValue: Rule = {
  id: "predictable-security-value",
  category: "insecure_randomness",
  describes: "tokens, codes, and session identifiers built from a predictable source",
  run(context: RuleContext) {
    for (const call of collect(context.file.source, ts.isCallExpression)) {
      if (calleeName(call) !== "Math.random") continue;
      const purposes = purposeNames(context.file, call);
      const purpose = classifySecurityPurpose(context.file, purposes);
      if (!purpose.unguessable) continue;
      reportPredictable(context, {
        node: call,
        purposes,
        purpose,
        source: "Math.random",
        detail:
          "Math.random is a fast non-cryptographic generator seeded per process. Its internal state is recoverable from a handful of observed outputs, so seeing a few values yields the ones issued before and after them."
      });
    }

    for (const site of digestSites(context)) {
      if (site.inputs.length === 0) continue;
      const purpose = classifySecurityPurpose(context.file, site.purposes);
      if (!purpose.unguessable) continue;
      // Hashing a random token for storage is the correct pattern and must stay
      // quiet; only a digest over inputs an attacker can reconstruct is a defect.
      if (!site.inputs.every((input) => isPredictableComposition(context.file, input))) continue;

      const inputs = site.inputs.map((input) => input.getText(context.file.source)).join(", ");
      reportPredictable(context, {
        node: site.call,
        purposes: site.purposes,
        purpose,
        source: `a ${site.algorithm.toUpperCase()} digest of ${inputs}`,
        detail:
          "A digest is deterministic, so the result is exactly as unguessable as what went into it. Every input here is something an attacker can observe, enumerate, or compute — an identifier, a counter, or the clock — so the value can be reconstructed offline."
      });
    }

    // A clock reading or a counter used directly as the value, with no digest at all.
    for (const declaration of collect(context.file.source, ts.isVariableDeclaration)) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const name = declaration.name.text;
      if (!HANDED_OUT_SECRET.test(name) || TIME_LIKE.test(name) || BENIGN_RANDOM_NAME.test(name)) continue;
      const initializer = declaration.initializer;
      if (!/Date\.now|performance\.now|process\.hrtime|new Date/.test(initializer.getText(context.file.source))) continue;
      if (!isPredictableComposition(context.file, initializer)) continue;

      reportPredictable(context, {
        node: declaration,
        purposes: [name],
        purpose: classifySecurityPurpose(context.file, [name]),
        source: "the current clock reading",
        detail:
          "The clock is public and monotonic: anyone who knows roughly when the value was issued can enumerate the small range it must fall in."
      });
    }
  }
};

/* -------------------------------------------------------- legacy digest algorithm */

export const legacyDigestAlgorithm: Rule = {
  id: "legacy-digest-algorithm",
  category: "weak_hash_algorithm",
  describes: "MD5, SHA-1, or RIPEMD used where collision resistance matters",
  run(context: RuleContext) {
    for (const site of digestSites(context)) {
      if (!LEGACY_DIGESTS.has(site.algorithm)) continue;
      // Reported by the rules that own the specific defect instead.
      if (anyMatches(site.inputs.map((input) => input.getText(context.file.source)).concat(site.purposes), PASSWORD_NAME)) continue;
      // Skipped on exactly the decision predictableSecurityValue fires on, so the
      // same digest is never reported once as a weak algorithm and again as a
      // predictable identifier.
      if (
        classifySecurityPurpose(context.file, site.purposes).unguessable &&
        site.inputs.every((input) => isPredictableComposition(context.file, input))
      ) {
        continue;
      }
      // A digest used as a cache key or an avatar hash is not a security decision.
      if (anyMatches(site.purposes, NON_SECURITY_DIGEST)) continue;
      // A helper named after its own algorithm is a wrapper. The decision that
      // depends on the digest lives at the call sites, so reporting the wrapper
      // gives the reader nothing to act on.
      if (site.purposes.some((purpose) => new RegExp(`^(hash)?${site.algorithm.replace("-", "")}(hash|sum|digest)?$`, "i").test(purpose))) {
        continue;
      }

      const name = site.algorithm.toUpperCase();
      context.report({
        ruleId: "legacy-digest-algorithm",
        category: "weak_hash_algorithm",
        title: `${name} is used to hash a value`,
        severity: "low",
        verification: "needs_review",
        summary: `${name} is used to produce a digest. Practical collisions exist for it, and preimage margins are thin, so it is unsuitable anywhere the digest stands in for the value it summarises — an integrity check, a signature input, a deduplication key that grants access.`,
        impact:
          "Where the digest is trusted to identify a value, an attacker who can supply the input can arrange for two different inputs to share a digest and substitute one for the other.",
        remediation:
          "Use SHA-256 for digests, HMAC-SHA-256 when the digest must prove origin, and a password hashing function for passwords. Where the digest is only a non-security cache key, say so at the call site so the next reader does not have to guess.",
        verificationPlan:
          "Establish what decision depends on this digest. If nothing security-relevant does, record it as accepted; otherwise confirm the replacement digest is used everywhere the old one was stored.",
        taxonomy: ["CWE-328", "CWE-327"],
        location: locationOf(context, site.call),
        ...withRoute(context, site.call),
        evidence: [sourceEvidence(context, site.call, `${name} digest.`)],
        reasoning: `create${site.keyed ? "Hmac" : "Hash"}("${site.algorithm}") is used, and the digest's purpose is not marked as a non-security cache key.`
      });
    }
  }
};

/* --------------------------------------------------------- JWT verification */

const JWT_MODULES = /^(jsonwebtoken|jose|jwt-simple|njwt|jwt-decode|@tsndr\/cloudflare-worker-jwt|fast-jwt)$/;

/** Local names bound to a JWT library in this file. */
function jwtBindings(file: ParsedFile): Set<string> {
  const names = new Set<string>();
  walk(file.source, (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier)) {
      if (!JWT_MODULES.test(node.moduleSpecifier.text)) return;
      const clause = node.importClause;
      if (!clause) return;
      if (clause.name) names.add(clause.name.text);
      if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) names.add(clause.namedBindings.name.text);
      if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) names.add(element.name.text);
      }
      return;
    }
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isCallExpression(node.initializer)) {
      if (calleeName(node.initializer) !== "require") return;
      const specifier = node.initializer.arguments[0];
      if (!specifier || !ts.isStringLiteralLike(specifier) || !JWT_MODULES.test(specifier.text)) return;
      if (ts.isIdentifier(node.name)) names.add(node.name.text);
      if (ts.isObjectBindingPattern(node.name)) {
        for (const element of node.name.elements) if (ts.isIdentifier(element.name)) names.add(element.name.text);
      }
    }
  });
  if (names.size === 0) {
    // A file that reaches a JWT through a project wrapper still names it `jwt`.
    walk(file.source, (node) => {
      if (!ts.isCallExpression(node)) return;
      if (!ts.isPropertyAccessExpression(node.expression)) return;
      const receiver = node.expression.expression.getText(file.source);
      if (/^(jwt|jsonwebtoken|jose)$/i.test(receiver)) names.add(receiver);
    });
  }
  return names;
}

function isJwtCall(file: ParsedFile, call: ts.CallExpression, bindings: Set<string>, tail: string): boolean {
  if (calleeTail(call) !== tail) return false;
  if (!ts.isPropertyAccessExpression(call.expression)) return bindings.has(calleeName(call));
  const receiver = call.expression.expression.getText(file.source);
  return bindings.has(receiver) || bindings.has(lastSegment(receiver));
}

/** The object literal of options a call was given, following a hoisted constant. */
function optionsObjectOf(file: ParsedFile, call: ts.CallExpression, from: number): ts.ObjectLiteralExpression | null {
  for (const argument of call.arguments.slice(from)) {
    const resolved = resolveValue(file, argument);
    if (ts.isObjectLiteralExpression(resolved)) return resolved;
  }
  return null;
}

function propertyOf(file: ParsedFile, options: ts.ObjectLiteralExpression, key: RegExp): ts.Expression | null {
  for (const property of options.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    if (key.test(property.name.getText(file.source).replace(/['"]/g, ""))) return property.initializer;
  }
  return null;
}

/** Does this branch stop the handler, so a failed verification cannot fall through? */
function branchStops(statement: ts.Node): boolean {
  let stops = false;
  walk(statement, (node) => {
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) stops = true;
  });
  return stops;
}

function jwtFinding(
  context: RuleContext,
  node: ts.Node,
  detail: { title: string; severity: "critical" | "high"; summary: string; remediation: string; reasoning: string }
): void {
  context.report({
    ruleId: "jwt-verification-bypass",
    category: "jwt_verification_bypass",
    title: detail.title,
    severity: detail.severity,
    verification: "strong_evidence",
    summary: detail.summary,
    impact:
      "An attacker mints a token carrying any claims they like — another tenant's identifier, an administrative role, an unexpired lifetime — and the application accepts it as proof of identity. Every check that reads those claims is then running on attacker-authored data, so this is a complete authentication bypass rather than a hardening gap.",
    remediation: detail.remediation,
    verificationPlan:
      "Take a token the application accepts, re-sign it with a key you generated, and send it. Then send the same token with its `alg` header set to `none` and its signature removed. Both must be rejected before any claim is read. Finally change `sub` in a valid token and confirm the response is not the other account's data.",
    taxonomy: ["CWE-347", "CWE-345", "OWASP-A07"],
    location: locationOf(context, node),
    ...withRoute(context, node),
    evidence: [sourceEvidence(context, node, "The token's signature is not what decides whether its claims are trusted.")],
    reasoning: detail.reasoning
  });
}

export const jwtVerificationBypass: Rule = {
  id: "jwt-verification-bypass",
  category: "jwt_verification_bypass",
  describes: "JSON Web Tokens trusted without a signature check that pins the algorithm and stops on failure",
  run(context: RuleContext) {
    const bindings = jwtBindings(context.file);
    if (bindings.size === 0) return;

    const verifyCalls = collect(context.file.source, ts.isCallExpression).filter(
      (call) => isJwtCall(context.file, call, bindings, "verify") || isJwtCall(context.file, call, bindings, "jwtVerify")
    );

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      if (!isJwtCall(context.file, call, bindings, "decode")) continue;
      const subject = call.arguments[0]?.getText(context.file.source) ?? "";
      // Decoding to read the `kid` before verifying with the matching key is a
      // legitimate pattern; it is only a bypass when nothing verifies the token.
      const verified = verifyCalls.some((verify) => verify.arguments[0]?.getText(context.file.source) === subject);
      if (verified) continue;
      // A decoded payload nobody reads is not a decision.
      const used = assignmentTargetName(context.file, call) !== null || isDecisionSite(call);
      if (!used) continue;

      jwtFinding(context, call, {
        title: "JSON Web Token claims are read without verifying the signature",
        severity: "critical",
        summary:
          "This call parses the token and returns its claims without checking the signature; nothing else in this file verifies the same token. The issuer, audience, expiry, subject and scope checks that follow therefore all run on values the caller wrote, and passing them proves only that the caller can format a JWT.",
        remediation:
          "Replace the decode with a verify against the issuer's key, with the algorithm list pinned to the one algorithm you expect, and with the issuer and audience checked by the library rather than by hand. Treat a verification failure as a 401 and read no claim before it succeeds.",
        reasoning: `A decode call on a JWT library binding whose result is used for a decision, with no verify call on \`${subject}\` in this file.`
      });
    }

    for (const call of verifyCalls) {
      const key = call.arguments[1];
      const token = call.arguments[0]?.getText(context.file.source) ?? "";

      // The key taken from the token means the token signs itself.
      if (key) {
        const keyText = key.getText(context.file.source);
        const derivedFromToken =
          /\bdecode\s*\(/.test(keyText) ||
          /^(header|payload|claims|decoded)\./.test(keyText) ||
          (token.length > 0 && new RegExp(`^${token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\.`).test(keyText));
        if (derivedFromToken) {
          jwtFinding(context, call, {
            title: "The key used to verify a JSON Web Token is taken from the token itself",
            severity: "critical",
            summary:
              "The verification key is read out of the token that is being verified. A signature checked against a key the signer chose proves nothing at all, so verification succeeds for any token the caller cares to construct.",
            remediation:
              "Load the verification key from configuration, or from the issuer's JWKS endpoint selected by `kid` against a pinned issuer. Never let any part of the token influence which key or which algorithm is used.",
            reasoning: "The second argument of verify is derived from the token being verified."
          });
          continue;
        }
      }

      const options = optionsObjectOf(context.file, call, 2);
      const algorithms = options ? propertyOf(context.file, options, /^algorithms?$/) : null;
      const algorithmText = algorithms ? algorithms.getText(context.file.source) : "";

      if (/none/i.test(algorithmText)) {
        jwtFinding(context, call, {
          title: "JSON Web Token verification accepts the `none` algorithm",
          severity: "critical",
          summary:
            "The accepted-algorithm list includes `none`, which means a token carrying no signature at all is treated as verified.",
          remediation:
            "Remove `none` from the list and pin the single algorithm the issuer actually uses. If tokens from two issuers must both be accepted, verify them in separate branches with their own key and their own pinned algorithm.",
          reasoning: "The verify options name the none algorithm."
        });
        continue;
      }

      if (!algorithms) {
        jwtFinding(context, call, {
          title: "JSON Web Token verification does not pin the accepted algorithms",
          severity: "high",
          summary:
            "Verification is called without an `algorithms` list, so the algorithm is taken from the token's own header. A caller can therefore choose it: against an asymmetric key, they submit an HMAC-signed token using the public key as the shared secret and the library validates it, because the public key is not secret.",
          remediation:
            "Pass `algorithms: [\"RS256\"]` — or whichever single algorithm the issuer signs with — on every verify call, and check `issuer` and `audience` in the same options object.",
          reasoning: "A JWT verify call with no algorithms option, so the token's own header selects the algorithm."
        });
        continue;
      }

      // A verification whose failure does not stop the handler is not a check.
      let container: ts.Node | undefined = call.parent;
      for (let depth = 0; container && depth < 8; depth += 1) {
        if (ts.isTryStatement(container) && container.catchClause) {
          if (!branchStops(container.catchClause.block)) {
            jwtFinding(context, call, {
              title: "A failed JSON Web Token verification does not stop the request",
              severity: "high",
              summary:
                "The verify call is wrapped in a try, and the catch block neither returns nor throws. A token with a bad signature therefore lands in the catch, the handler carries on, and whatever the code does next runs for a caller who never presented a valid token.",
              remediation:
                "Return a 401 from the catch block before any other work happens. If the route has an anonymous mode, make that an explicit branch with its own reduced permissions rather than a side effect of a swallowed exception.",
              reasoning: "A JWT verify call inside a try whose catch clause contains no return or throw."
            });
          }
          break;
        }
        container = container.parent;
      }
    }
  }
};

/* ------------------------------------------------------- session cookie flags */

type FlagState = "set" | "false" | "absent";

interface CookieSite {
  node: ts.Node;
  /** Every name the cookie might be known by, resolved and literal. */
  names: string[];
  httpOnly: FlagState;
  secure: FlagState;
  sameSite: string | null;
}

/**
 * Flatten a cookie options object, following spreads.
 *
 * `{ ...sessionCookieOptions(secure), expires }` is the ordinary way to share
 * cookie policy across handlers. A rule that reads only the literal's own
 * properties concludes every flag is missing and reports the correct code — the
 * one false positive that costs a cookie rule all of its credibility. When the
 * spread cannot be resolved, the attributes are unknown and the site is skipped.
 */
interface CookieAttributes {
  properties: Map<string, ts.Expression>;
  resolved: boolean;
}

function cookieAttributes(file: ParsedFile, options: ts.ObjectLiteralExpression, depth = 0): CookieAttributes {
  const properties = new Map<string, ts.Expression>();
  let resolved = true;
  for (const member of options.properties) {
    if (ts.isPropertyAssignment(member)) {
      properties.set(member.name.getText(file.source).replace(/['"]/g, "").toLowerCase(), member.initializer);
      continue;
    }
    if (ts.isShorthandPropertyAssignment(member)) {
      properties.set(member.name.text.toLowerCase(), member.name);
      continue;
    }
    if (ts.isSpreadAssignment(member)) {
      const source = depth < 3 ? resolveValue(file, member.expression) : member.expression;
      if (ts.isObjectLiteralExpression(source)) {
        const nested = cookieAttributes(file, source, depth + 1);
        for (const [key, value] of nested.properties) if (!properties.has(key)) properties.set(key, value);
        resolved = resolved && nested.resolved;
        continue;
      }
      resolved = false;
    }
  }
  return { properties, resolved };
}

function flagFrom(file: ParsedFile, attributes: CookieAttributes, key: string): FlagState {
  const value = attributes.properties.get(key);
  if (!value) return "absent";
  const resolved = unwrap(resolveValue(file, value));
  if (resolved.kind === ts.SyntaxKind.FalseKeyword) return "false";
  return "set";
}

function cookieSitesIn(context: RuleContext): CookieSite[] {
  const file = context.file;
  const sites: CookieSite[] = [];

  for (const call of collect(file.source, ts.isCallExpression)) {
    const tail = calleeTail(call);
    const dotted = calleeName(call);
    const isCookieCall = /cookie/i.test(dotted) && /^(cookie|setCookie|set|append)$/.test(tail);
    if (!isCookieCall) continue;

    let options: ts.ObjectLiteralExpression | null = null;
    let optionsIndex = -1;
    for (let index = 0; index < call.arguments.length; index += 1) {
      const resolved = resolveValue(file, call.arguments[index]!);
      if (ts.isObjectLiteralExpression(resolved)) {
        options = resolved;
        optionsIndex = index;
        break;
      }
    }
    if (!options) continue;

    const attributes = cookieAttributes(file, options);
    // An unresolved spread means the flags may all be set somewhere this pass
    // cannot see. Silence is the only honest answer.
    if (!attributes.resolved) continue;

    const names: string[] = [];
    if (optionsIndex === 0) {
      const declared = attributes.properties.get("name");
      if (declared) {
        const literal = literalTextOf(resolveValue(file, declared));
        if (literal) names.push(literal);
        names.push(declared.getText(file.source));
      }
    } else {
      const first = call.arguments[0];
      if (first) {
        const literal = literalTextOf(resolveValue(file, first));
        if (literal) names.push(literal);
        names.push(first.getText(file.source));
      }
    }

    const sameSiteNode = attributes.properties.get("samesite");
    sites.push({
      node: call,
      names,
      httpOnly: flagFrom(file, attributes, "httponly"),
      secure: flagFrom(file, attributes, "secure"),
      sameSite: sameSiteNode ? literalTextOf(resolveValue(file, sameSiteNode)) : null
    });
  }

  // `res.setHeader("Set-Cookie", ...)` and `{ "set-cookie": "sid=...; HttpOnly" }`.
  const headerValues: ts.Node[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!/^(setHeader|append)$/.test(calleeTail(call))) continue;
    const header = call.arguments[0] ? literalTextOf(call.arguments[0]!) : null;
    if (!header || !/^set-cookie$/i.test(header)) continue;
    if (call.arguments[1]) headerValues.push(call.arguments[1]!);
  }
  for (const property of collect(file.source, ts.isPropertyAssignment)) {
    const key = property.name.getText(file.source).replace(/['"]/g, "");
    if (!/^set-cookie$/i.test(key)) continue;
    headerValues.push(property.initializer);
  }

  for (const value of headerValues) {
    const text = value.getText(file.source);
    const name = /([A-Za-z0-9_.-]+)\s*=/.exec(text.replace(/^[`'"]/, ""));
    // A cookie being cleared carries no value to steal.
    if (/max-age\s*=\s*0|expires\s*=\s*thu,\s*01 jan 1970/i.test(text)) continue;
    const sameSite = /samesite\s*=\s*([a-z]+)/i.exec(text);
    sites.push({
      node: value,
      names: name ? [name[1]!] : [],
      httpOnly: /\bhttponly\b/i.test(text) ? "set" : "absent",
      secure: /\bsecure\b/i.test(text) ? "set" : "absent",
      sameSite: sameSite ? sameSite[1]! : null
    });
  }

  return sites;
}

/**
 * Does this file check the request's origin, or verify a CSRF token, so a cookie
 * deliberately issued for cross-site use is not left undefended?
 *
 * A `SameSite=None` session cookie is a considered decision in an application
 * embedded in third-party pages. Reporting it without looking for the check that
 * replaces SameSite would flag the correct implementation alongside the broken one.
 */
function hasCrossSiteCompensation(context: RuleContext): boolean {
  let compensated = false;
  walk(context.file.source, (node) => {
    if (compensated) return;
    if (ts.isCallExpression(node)) {
      const tail = calleeTail(node);
      if (tail === "has" || tail === "includes" || tail === "indexOf") {
        const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression.getText(context.file.source) : "";
        const argument = node.arguments[0]?.getText(context.file.source) ?? "";
        if (/origin|referer|allowed|host/i.test(receiver) && /origin|referer|host/i.test(argument)) compensated = true;
        return;
      }
      if (tail === "timingSafeEqual" || /^(verifyCsrf|checkCsrf|assertCsrf|validateCsrf)$/.test(tail)) {
        compensated = true;
        return;
      }
    }
    if (ts.isBinaryExpression(node) && EQUALITY_OPERATORS.has(node.operatorToken.kind)) {
      const text = node.getText(context.file.source);
      if (/\borigin\b/i.test(text) && isConstantString(node.left) !== isConstantString(node.right)) compensated = true;
      if (/csrf|xsrf/i.test(text)) compensated = true;
    }
  });
  return compensated;
}

export const sessionCookieConfiguration: Rule = {
  id: "session-cookie-configuration",
  category: "insecure_cookie_configuration",
  describes: "session and authentication cookies written without the flags that keep them private",
  run(context: RuleContext) {
    let compensation: boolean | null = null;

    for (const site of cookieSitesIn(context)) {
      if (site.names.length === 0) continue;
      if (!anyMatches(site.names, SESSION_COOKIE_NAME)) continue;
      // A cookie that is meant to be readable by script — a theme, a locale, or a
      // double-submit CSRF token — is doing its job and must not be reported.
      if (anyMatches(site.names, NON_SENSITIVE_COOKIE)) continue;

      const gaps: string[] = [];
      if (site.httpOnly !== "set") gaps.push("HttpOnly");
      if (site.secure !== "set") gaps.push("Secure");

      const crossSite = site.sameSite !== null && /^none$/i.test(site.sameSite);
      if (site.sameSite === null) gaps.push("SameSite");
      if (crossSite) {
        compensation ??= hasCrossSiteCompensation(context);
        if (!compensation) gaps.push("a check that replaces SameSite");
      }
      if (gaps.length === 0) continue;

      const name = site.names[0]!;
      const readable = site.httpOnly !== "set";
      const plaintext = site.secure !== "set";
      /**
       * A missing Secure flag on its own is not reported.
       *
       * This pass cannot settle it — and a claim the analysis cannot settle does not
       * belong in a findings list. A service behind an https edge is already safe, and
       * a local development server over plain http is correct as written; reporting
       * either teaches the reader that low-severity findings are noise, which is the
       * habit that makes them miss a real one. Where HttpOnly or SameSite is genuinely
       * absent the finding still fires, and its remediation already tells the reader to
       * set Secure as well.
       */
      if (gaps.length === 1 && gaps[0] === "Secure") continue;
      /**
       * `httpOnly: false` is a decision somebody made and wrote down; an absent
       * attribute is usually a codebase that has not had a security pass, on a
       * deployment whose TLS and default SameSite this file does not describe.
       * Both are worth fixing, but only the first states an unsafe intent, so only
       * the first carries the higher severity.
       */
      const explicitlyDisabled = site.httpOnly === "false" || site.secure === "false";
      const severity = readable && explicitlyDisabled ? "high" : "medium";

      const sentences: string[] = [];
      if (readable) {
        sentences.push(
          "Without HttpOnly the cookie is in `document.cookie`, so any script that runs on the page — including one injected through an XSS bug or pulled in by a third-party tag — reads the live session and can replay it from anywhere."
        );
      }
      if (plaintext) {
        sentences.push(
          "Without Secure the browser sends it over plain HTTP, so a single downgraded request on a shared network hands the session to whoever is watching."
        );
      }
      if (site.sameSite === null) {
        sentences.push(
          "With no SameSite attribute the browser's default is applied rather than a stated intent, and any change in that default silently changes the application's cross-site behaviour."
        );
      }
      if (crossSite && compensation === false) {
        sentences.push(
          "SameSite=None means the browser attaches it to requests started by any other site, and this file contains no origin check and no CSRF token verification to take SameSite's place, so a page the victim visits can drive authenticated state-changing requests."
        );
      }

      context.report({
        ruleId: "session-cookie-configuration",
        category: "insecure_cookie_configuration",
        title: `Session cookie \`${name}\` is set without ${gaps.join(" and ")}`,
        severity,
        verification: "strong_evidence",
        summary: `\`${name}\` carries the caller's authenticated session, and it is written without ${gaps.join(" and ")}. ${sentences.join(" ")}`,
        impact:
          "The session is the credential. Any of these gaps turns a bug elsewhere — a script injection, a downgraded request, a hostile page the user visits — into a full account takeover that leaves no failed sign-in behind.",
        remediation:
          "Set HttpOnly and Secure on every session cookie, and state SameSite explicitly: Lax for a first-party application, Strict where no cross-site navigation needs the session. Where the application genuinely runs inside third-party pages and needs SameSite=None, keep None but require an Origin on the allowlist and a double-submit CSRF token on every state-changing request.",
        verificationPlan:
          "Sign in against the running application and read the Set-Cookie header: confirm HttpOnly, Secure, and the intended SameSite are all present. Then read `document.cookie` in the console and confirm the session name is absent, and replay a state-changing request from an unrelated origin and confirm it is refused.",
        taxonomy: ["CWE-1004", "CWE-614", "CWE-1275", "OWASP-A05"],
        location: locationOf(context, site.node),
        ...withRoute(context, site.node),
        evidence: [sourceEvidence(context, site.node, `Cookie attributes as written: ${describeFlags(site)}.`)],
        reasoning: `A cookie named \`${name}\` matches a session or authentication cookie and is not a CSRF or preference cookie; its resolved attributes are ${describeFlags(site)}, so ${gaps.join(", ")} ${gaps.length === 1 ? "is" : "are"} missing.${explicitlyDisabled ? " At least one flag is written as an explicit false rather than merely absent." : ""}`
      });
    }
  }
};

function describeFlags(site: CookieSite): string {
  const parts = [
    `HttpOnly ${site.httpOnly === "set" ? "set" : site.httpOnly === "false" ? "explicitly false" : "absent"}`,
    `Secure ${site.secure === "set" ? "set" : site.secure === "false" ? "explicitly false" : "absent"}`,
    `SameSite ${site.sameSite ?? "absent"}`
  ];
  return parts.join(", ");
}

/* --------------------------------------------------------- credential literals */

function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function classifyCredential(value: string): { id: string; label: string; live: boolean } | null {
  for (const shape of CREDENTIAL_SHAPES) {
    if (shape.pattern.test(value)) return { id: shape.id, label: shape.label, live: shape.live === true };
  }
  return null;
}

/** Identifier names that mean the value beside them is meant to stay secret. */
const SECRET_BINDING_NAME =
  /(secret|password|passwd|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|client[_-]?secret|session[_-]?key|credential|auth[_-]?token|signing[_-]?key|encryption[_-]?key|dsn|connection[_-]?string)/i;

export const credentialLiteral: Rule = {
  id: "credential-literal",
  category: "hardcoded_secret",
  describes: "credentials committed to source, including defaults behind an environment read",
  run(context: RuleContext) {
    const reported = new Set<string>();

    const consider = (node: ts.Node, rawValue: string, boundTo: readonly string[], how: string): void => {
      const value = rawValue.trim();
      if (value.length < 8 || value.length > 4096) return;
      if (PLACEHOLDER_VALUE.test(value)) return;
      if (PUBLIC_VALUE_PREFIX.test(value)) return;

      const shape = classifyCredential(value);
      // Without a recognisable shape, a value that names itself is a fixture.
      if (!shape && SELF_DESCRIBING_VALUE.test(value)) return;
      const named = boundTo.some((name) => SECRET_BINDING_NAME.test(name));

      let label: string;
      let live: boolean;
      let reasoning: string;
      if (shape) {
        label = shape.label;
        live = shape.live;
        reasoning = `The literal matches the documented shape of a ${shape.label}${how ? ` and ${how}` : ""}.`;
      } else if (named && value.length >= 12 && shannonEntropy(value) >= 3.4 && !/\s/.test(value)) {
        label = `credential assigned to ${boundTo.find((name) => SECRET_BINDING_NAME.test(name))}`;
        // A long, high-entropy value under a secret-named binding is a working
        // credential, whichever vendor issued it; the impact does not depend on
        // whether the engine recognised the vendor's prefix.
        live = value.length >= 24 && shannonEntropy(value) >= 3.5;
        reasoning = `The literal ${how || "is bound to a secret-named binding"}, is ${value.length} characters with entropy ${shannonEntropy(value).toFixed(2)}, and contains no whitespace.`;
      } else {
        return;
      }

      const key = `${label}:${value.slice(0, 8)}:${lineOf(context.file, node)}`;
      if (reported.has(key)) return;
      reported.add(key);

      // The value is never reproduced: a scanner that prints the secret it found
      // has published it a second time.
      context.report({
        ruleId: "credential-literal",
        category: "hardcoded_secret",
        title: `Credential in source: ${label}`,
        severity: live ? "high" : "medium",
        verification: "strong_evidence",
        summary: `A ${label} is present as a literal in ${context.file.relativePath}${how ? `, where it ${how}` : ""}. Anyone who can read the repository, its history, a CI log, or a build artifact that contains this file holds the credential, and none of those audiences is the one it was issued to.`,
        impact:
          "The credential has to be treated as already compromised, because publication cannot be undone by deleting the line. What that costs depends on what it authorises: reading customer data, sending mail as the company, or spending money on the account it belongs to.",
        remediation:
          "Rotate the credential first — the old value is burned. Then read the new one from the process environment or a secret manager, fail closed at startup when it is absent rather than falling back to a literal, and purge the value from git history. Add a pre-commit secret scan so the next one is caught before it lands.",
        verificationPlan:
          "Confirm the rotated credential is loaded from configuration at runtime and that the application refuses to start without it. Then search the working tree and the full history for the shape and confirm no literal remains.",
        taxonomy: ["CWE-798", "CWE-259", "OWASP-A07"],
        location: locationOf(context, node),
        ...withRoute(context, node),
        evidence: [
          {
            kind: "source",
            description: `A ${label} appears as a literal. The value is deliberately not reproduced in this report.`,
            location: `${context.file.relativePath}:${lineOf(context.file, node)}`
          }
        ],
        reasoning
      });
    };

    for (const declaration of collect(context.file.source, ts.isVariableDeclaration)) {
      if (!declaration.initializer || !ts.isIdentifier(declaration.name)) continue;
      const name = declaration.name.text;
      const initializer = unwrap(declaration.initializer);

      if (ts.isStringLiteralLike(initializer)) {
        consider(declaration, initializer.text, [name], "");
        continue;
      }

      // `process.env.STRIPE_SECRET_KEY || "sk_live_..."`: the fallback is a working
      // credential the moment the variable is unset, which is precisely when nobody
      // is watching. The defaulting operator hides it from a rule that only reads
      // plain initializers.
      if (
        ts.isBinaryExpression(initializer) &&
        (initializer.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
          initializer.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
      ) {
        const fallback = unwrap(initializer.right);
        if (!ts.isStringLiteralLike(fallback)) continue;
        const source = initializer.left.getText(context.file.source);
        const environmentNames = /process\.env\.([A-Za-z0-9_]+)|process\.env\[["']([A-Za-z0-9_]+)["']\]/.exec(source);
        const bound = [name, environmentNames?.[1] ?? environmentNames?.[2] ?? source];
        consider(fallback, fallback.text, bound, `serves as the default when ${source} is unset`);
      }
    }

    for (const property of collect(context.file.source, ts.isPropertyAssignment)) {
      const initializer = unwrap(property.initializer);
      const name = property.name.getText(context.file.source).replace(/['"]/g, "");
      if (ts.isStringLiteralLike(initializer)) {
        consider(property, initializer.text, [name], "");
        continue;
      }
      if (
        ts.isBinaryExpression(initializer) &&
        (initializer.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
          initializer.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
      ) {
        const fallback = unwrap(initializer.right);
        if (!ts.isStringLiteralLike(fallback)) continue;
        const source = initializer.left.getText(context.file.source);
        consider(fallback, fallback.text, [name, source], `serves as the default when ${source} is unset`);
      }
    }

    // A key pasted into a template literal keeps its newlines, which is how PEM
    // material is almost always committed. The plain-literal pass never sees it.
    for (const template of collect(context.file.source, ts.isTemplateExpression)) {
      const text = template.getText(context.file.source);
      if (!/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(text)) continue;
      const bound = assignmentTargetName(context.file, template);
      consider(template, text.replace(/^`|`$/g, ""), bound ? [bound] : [], "is embedded in a template literal");
    }

    // A shape-matched literal anywhere else still matters: an inline client
    // constructor, a fetch header, a default parameter.
    for (const literal of collect(context.file.source, ts.isStringLiteralLike)) {
      if (!classifyCredential(literal.text)) continue;
      consider(literal, literal.text, [], "");
    }
  }
};
