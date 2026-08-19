import ts from "typescript";
import { calleeName, calleeTail, collect, expressionName, findAll, literalTextOf, walk } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, resolveExpression, taintOrigin, type TaintScope } from "../ast/taint.js";
import { lineOf, type ParsedFile } from "../ast/parse.js";
import { routeFromFilePath } from "../ast/routes.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/*
 * Authorization and the checks an endpoint forgets.
 *
 * Every rule here answers a question about what is *absent*, which is why they are
 * written against the structure of an endpoint rather than against a dangerous
 * call. A missing check has no sink to point at, so the evidence has to be the
 * contrast with the code around it: a sibling handler that does authenticate, a
 * role that was fetched and never compared, a field list that was never named.
 *
 * Every rule is also deliberately quiet when that contrast is absent. A module
 * where nothing is authenticated may be a public API; a lookup with no role
 * comparison may be a route where no role applies. Reporting those trains the
 * reader to ignore the tool.
 */

/* ------------------------------------------------------------------ vocabulary */

/**
 * Words that mean "this call establishes who the caller is".
 *
 * Matching is done on tokens, not substrings: `getSessionByToken` and
 * `current_session` both tokenize to something containing `session`, while
 * `db.query.users.findFirst` does not accidentally become an authentication check.
 */
const IDENTITY_TOKENS = new Set([
  "session", "auth", "authenticate", "authenticated", "authorization", "viewer", "identity", "principal",
  "actor", "jwt", "clerk", "whoami"
]);

/** Tokens that only count as identity when a resolving verb sits beside them. */
const IDENTITY_SUBJECT_TOKENS = new Set(["user", "account", "me", "subject", "caller", "customer"]);

const RESOLVING_VERBS = new Set([
  "get", "require", "resolve", "read", "current", "load", "fetch", "ensure", "assert", "must", "verify",
  "check", "with", "from", "use", "of"
]);

/**
 * Membership predicates. They prove the caller was identified, and nothing more:
 * "is a member of this workspace" is not "may change this workspace's plan".
 */
const MEMBERSHIP_TOKENS = new Set([
  "member", "membership", "tenant", "org", "organisation", "organization", "workspace", "team", "self",
  "collaborator", "participant"
]);

/** Words that name an authorization decision rather than an identity. */
const ROLE_TOKENS = new Set([
  "role", "roles", "permission", "permissions", "scope", "scopes", "isadmin", "isstaff", "issuperuser",
  "issuperadmin", "isowner", "admin", "superadmin", "acl", "rbac", "capability", "capabilities",
  "entitlement", "entitlements", "privilege", "privileges", "claims", "ability", "abilities", "grants"
]);

const AUTHZ_VERBS = new Set([
  "require", "assert", "ensure", "check", "must", "can", "may", "verify", "guard", "authorize", "authorise",
  "deny", "forbid", "is", "has", "allow"
]);

/** Calls that are an authorization decision whatever they are named around. */
const AUTHZ_CALLS = new Set([
  "authorize", "authorise", "can", "cannot", "isallowed", "ispermitted", "requirerole", "requirepermission",
  "requireadmin", "assertadmin", "hasrole", "haspermission", "checkaccess", "assertaccess", "ensureaccess",
  "forbidden"
]);

/**
 * Columns whose value *is* an authorization decision. Writing one of these is an
 * administrative operation no matter which path it sits on.
 *
 * Deliberately excludes money and inventory columns: a balance or a stock count
 * is a business-logic concern with its own rule, and claiming them here would
 * report every wallet debit as an authorization defect.
 */
const PRIVILEGED_COLUMNS = new Set([
  "role", "roles", "userrole", "memberrole", "membershiprole", "accountrole", "permission", "permissions",
  "scope", "scopes", "isadmin", "isstaff", "issuperuser", "issuperadmin", "isowner", "owner", "ownerid",
  "plan", "plantier", "plancode", "tier", "subscriptiontier", "seatlimit", "seats", "seatcount",
  "emailverified", "entitlement", "entitlements", "capabilities", "acl", "grants", "privileges", "accesslevel"
]);

/** The subset of privileged columns whose change hands over control outright. */
const CONTROL_COLUMNS = new Set([
  "role", "roles", "userrole", "memberrole", "membershiprole", "accountrole", "permission", "permissions",
  "scope", "scopes", "isadmin", "isstaff", "issuperuser", "issuperadmin", "isowner", "owner", "ownerid",
  "acl", "grants", "privileges", "accesslevel"
]);

/** Tables and collections that hold one row per subject. */
const IDENTITY_TABLE_TOKENS = new Set([
  "user", "users", "member", "members", "membership", "memberships", "account", "accounts", "profile",
  "profiles", "person", "people", "employee", "employees", "staff", "customer", "customers", "collaborator",
  "collaborators", "assignment", "assignments", "settings", "preferences", "preference", "subscription",
  "subscriptions", "device", "devices", "session", "sessions", "workspace", "workspaces", "team", "teams",
  "organisation", "organization"
]);

/** Columns that scope a row to one subject. */
const OWNER_COLUMN =
  /\b(user_?id|owner_?id|account_?id|tenant_?id|workspace_?id|team_?id|member_?id|organisation_?id|organization_?id|customer_?id|subject_?id|created_?by|invited_?by)\b/i;

/** Field names that must never reach a log line. */
const CREDENTIAL_FIELDS = new Set([
  "password", "passwd", "pwd", "passphrase", "secret", "clientsecret", "token", "accesstoken", "refreshtoken",
  "idtoken", "sessiontoken", "apikey", "apisecret", "privatekey", "authorization", "cookie", "setcookie",
  "cardnumber", "pan", "cvv", "cvc", "securitycode", "cardsecuritycode", "iban", "accountnumber",
  "routingnumber", "ssn", "socialsecuritynumber", "taxid", "otp", "mfacode", "totp", "resettoken",
  "verificationcode", "creditcard"
]);

/** Whole objects that carry a caller's submission or a subject's record. */
const WHOLE_INPUT_PROPERTIES = new Set(["body", "params", "query", "form", "formdata", "fields", "payload", "input"]);
const WHOLE_SUBJECT_PROPERTIES = new Set(["user", "session", "viewer", "account", "actor", "principal", "identity", "profile", "member"]);

/** Route paths whose name says the endpoint is privileged. */
const PRIVILEGED_PATH = /\/(admin|internal|manage|management|superuser|root|owner|staff|ops|system|console|backoffice|back-office)(\/|$|\?)/i;

/**
 * Diagnostic routes. The debug-endpoint rule owns these: it describes the same
 * missing control and prescribes the same fix, so reporting both would describe
 * one defect twice under two taxonomies. Matched on a segment suffix, because the
 * segment is usually `runtime-status` rather than `status`.
 */
const DIAGNOSTIC_PATH =
  /(^|\/|-|_)(debug|__debug|diagnostic|diagnostics|health|healthz|readyz|livez|metrics|status|state|dump|trace|pprof|env|version|info|stats|telemetry)(\/|$|\?)/i;

/**
 * Endpoints that are unauthenticated by definition, recognised on whole words so
 * `deregister` is not mistaken for `register` and a finding lost to a substring.
 */
const BY_DESIGN_TOKENS = new Set([
  "signin", "login", "signup", "signout", "logout", "register", "registration", "forgot", "recover",
  "callback", "oauth", "oidc", "saml", "sso", "webhook", "webhooks", "hook", "hooks", "redeem", "magic",
  "challenge", "healthz", "readyz", "livez", "ping", "robots", "sitemap", "manifest"
]);

function unauthenticatedByDesign(label: string): boolean {
  if (tokensOf(label).some((token) => BY_DESIGN_TOKENS.has(token))) return true;
  return /(signin|signup|signout|login|logout|passwordreset|forgotpassword|magiclink)/.test(normalizeKey(label));
}

/** Does this handler itself establish or tear down a session? Those cannot be authenticated. */
function establishesSession(context: RuleContext, body: ts.Node): boolean {
  const text = body.getText(context.file.source);
  if (/setCookie|clearCookie|set-cookie|cookies\(\)\s*\.\s*set|cookies\s*\.\s*set|\.setHeader\(\s*["']set-cookie/i.test(text)) {
    return true;
  }
  return /bcrypt\s*\.\s*compare|argon2\s*\.\s*verify|scrypt|verifyPassword|comparePassword|checkPassword|verifyCredentials|timingSafeEqual/i.test(
    text
  );
}

/** HTTP verbs that change state. */
const STATE_CHANGING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/* -------------------------------------------------------------------- tokenizing */

/** `requireWorkspaceRole` becomes ["require","workspace","role"]. */
function tokensOf(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((part) => part.length > 0)
    .map((part) => part.toLowerCase());
}

/** `is_admin` and `isAdmin` both become "isadmin", so one set matches both. */
function normalizeKey(name: string): string {
  return name.replace(/['"`]/g, "").replace(/[^A-Za-z0-9]+/g, "").toLowerCase();
}

function propertyKeyOf(property: ts.ObjectLiteralElementLike, file: ParsedFile): string | null {
  if (ts.isShorthandPropertyAssignment(property)) return property.name.text;
  if (!property.name) return null;
  if (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) return property.name.text;
  return property.name.getText(file.source);
}

/** Does any token of this dotted expression name an authorization concept? */
function isRoleExpression(text: string): boolean {
  const parts = text.split(/[.[\]]+/).filter(Boolean);
  const last = parts[parts.length - 1];
  if (last && ROLE_TOKENS.has(normalizeKey(last))) return true;
  return tokensOf(text).some((token) => ROLE_TOKENS.has(token));
}

/* --------------------------------------------------------------- identity checks */

/** A dotted path that reads the caller off a framework object. */
function isIdentityPath(text: string): boolean {
  return /(^|\.)(req|request|ctx|context|c|res|response|event|locals|globals|this)\.(user|session|viewer|auth|actor|identity|principal|currentUser)(\.|$)/.test(
    text
  );
}

/** Does this call name say it resolves the caller? */
function isIdentityCall(name: string): boolean {
  if (name.length === 0) return false;
  const tokens = tokensOf(name);
  if (tokens.some((token) => IDENTITY_TOKENS.has(token))) return true;
  const hasVerb = tokens.some((token) => RESOLVING_VERBS.has(token));
  if (hasVerb && tokens.some((token) => IDENTITY_SUBJECT_TOKENS.has(token))) return true;
  // `requireWorkspaceMember` proves the caller was identified even though it says
  // nothing about their role. Treating it as authentication is what lets the
  // authorization rule report it as *only* authentication.
  if (hasVerb && tokens.some((token) => MEMBERSHIP_TOKENS.has(token))) return true;
  return false;
}

/**
 * Does anything inside this node establish who the caller is?
 *
 * One hop into a module-local helper is followed, because `const session = await
 * currentSession()` and a hand-rolled dispatcher that delegates to a named
 * function are both extremely common, and stopping at the call site would report
 * correct code.
 */
function resolvesIdentity(
  context: RuleContext,
  node: ts.Node,
  visited = new Set<string>(),
  /** Middleware is passed by reference, so a bare name counts in gate position. */
  byReference = false
): boolean {
  let found = false;
  walk(node, (inner) => {
    if (found) return;
    if (ts.isPropertyAccessExpression(inner) && isIdentityPath(expressionName(inner))) {
      found = true;
      return;
    }
    // `router.get(path, requireUser, loadTeam, handler)` and
    // `{ preHandler: [fastify.authenticate] }` name their middleware and never call
    // it here. Without this the correct form of every framework's authentication
    // looks like no authentication at all.
    if (byReference && (ts.isIdentifier(inner) || ts.isPropertyAccessExpression(inner))) {
      const referenced = expressionName(inner);
      if (isIdentityCall(referenced) || namesAuthorization(referenced)) {
        found = true;
        return;
      }
      const local = moduleFunctionBody(context, referenced, visited);
      if (local && resolvesIdentity(context, local, visited)) {
        found = true;
        return;
      }
    }
    if (!ts.isCallExpression(inner)) return;
    const name = calleeName(inner);
    if (isIdentityCall(name)) {
      found = true;
      return;
    }
    // Hono and Fastify hand the caller through a typed store: `c.get("viewer")`.
    if (calleeTail(inner) === "get") {
      const key = inner.arguments[0] ? literalTextOf(inner.arguments[0]!) : null;
      if (key && (IDENTITY_TOKENS.has(normalizeKey(key)) || WHOLE_SUBJECT_PROPERTIES.has(normalizeKey(key)))) {
        found = true;
        return;
      }
    }
    if (findRoleCheck(context, inner, visited)) {
      found = true;
      return;
    }
    const local = moduleFunctionBody(context, name, visited);
    if (local && resolvesIdentity(context, local, visited)) found = true;
  });
  return found;
}

/**
 * A module-level function body, looked up by name, visited at most once.
 *
 * Following one hop is the difference between understanding `await
 * renderPreview(request, response)` and reporting the dispatcher that calls it.
 */
function moduleFunctionBody(context: RuleContext, name: string, visited: Set<string>): ts.Node | null {
  const simple = name.split(".").pop() ?? name;
  if (simple.length === 0 || visited.has(simple)) return null;
  for (const statement of context.file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === simple && statement.body) {
      visited.add(simple);
      return statement.body;
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== simple) continue;
      const initializer = declaration.initializer;
      if (initializer && (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer))) {
        visited.add(simple);
        return initializer.body;
      }
    }
  }
  return null;
}

/* ------------------------------------------------------- authorization detection */

/**
 * The node where this scope compares a role, a permission, or an ownership claim.
 *
 * A *mention* of a role is not a check: the handler that writes `SET role = $1` is
 * full of the word. Only a comparison, a membership test, a named authorization
 * call, or a query filtered on a role counts.
 */
function findRoleCheck(
  context: RuleContext,
  node: ts.Node,
  visited = new Set<string>(),
  byReference = false
): ts.Node | null {
  const file = context.file;
  let hit: ts.Node | null = null;

  walk(node, (inner) => {
    if (hit) return;

    // `ctx.session.role !== "owner"`, `membership.role === Role.Admin`
    if (ts.isBinaryExpression(inner)) {
      const kind = inner.operatorToken.kind;
      const isComparison =
        kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
        kind === ts.SyntaxKind.EqualsEqualsToken ||
        kind === ts.SyntaxKind.ExclamationEqualsToken;
      if (isComparison) {
        for (const side of [inner.left, inner.right]) {
          if (isSubjectRoleExpression(context, side, node)) {
            hit = inner;
            return;
          }
        }
      }
    }

    // `!viewer.isAdmin`, `!actor.permissions.length`
    if (ts.isPrefixUnaryExpression(inner) && inner.operator === ts.SyntaxKind.ExclamationToken) {
      if (isSubjectRoleExpression(context, inner.operand, node)) {
        hit = inner;
        return;
      }
    }

    if (ts.isSwitchStatement(inner) && isSubjectRoleExpression(context, inner.expression, node)) {
      hit = inner;
      return;
    }

    if (byReference && (ts.isIdentifier(inner) || ts.isPropertyAccessExpression(inner))) {
      if (namesAuthorization(expressionName(inner))) {
        hit = inner;
        return;
      }
    }

    if (ts.isCallExpression(inner)) {
      const name = calleeName(inner);
      const tail = calleeTail(inner);

      // `requireProjectRole("manager")`, `assertBillingRole(viewer, id)`, `assertOwner(...)`
      if (namesAuthorization(name)) {
        hit = inner;
        return;
      }
      // `ROLE_MANAGERS.has(assignment.role)`, `actor.roles.includes("marketing")`.
      //
      // The role has to belong to the *caller*, read off a record or a session.
      // `ASSIGNABLE_ROLES.has(role)` where `role` came out of the request body is
      // input validation of the value being written, and treating it as an
      // authorization check would silently excuse every unguarded role change.
      if (["has", "includes", "some", "every", "contains", "indexof"].includes(tail.toLowerCase())) {
        const receiver = ts.isPropertyAccessExpression(inner.expression) ? inner.expression.expression : null;
        const subjectSide =
          (receiver && isSubjectRoleExpression(context, receiver, node)) ||
          inner.arguments.some((argument) => isSubjectRoleExpression(context, argument, node));
        if (subjectSide) {
          hit = inner;
          return;
        }
      }
      const local = moduleFunctionBody(context, name, visited);
      if (local) {
        const nested = findRoleCheck(context, local, visited);
        if (nested) {
          hit = inner;
          return;
        }
      }
    }

    // `findFirst({ where: { workspaceId, userId: viewer.id, role: "OWNER" } })` is a
    // role check expressed as a filter: the row only exists if the caller holds it.
    if (ts.isPropertyAssignment(inner)) {
      const key = propertyKeyOf(inner, file);
      if (key && ROLE_TOKENS.has(normalizeKey(key)) && payloadContext(inner) === "filter") {
        hit = inner;
      }
    }
  });

  return hit;
}

/** Set-membership methods: whose role is being tested matters, so these are not names. */
const COLLECTION_TESTS = new Set(["has", "includes", "some", "every", "contains", "indexof", "hasownproperty"]);

/**
 * Does this name announce an authorization decision?
 *
 * A method call on a collection is excluded even when the collection is named for
 * roles. `ASSIGNABLE_ROLES.has(role)` validates the role being *written*; the
 * membership branch decides that by looking at whose role the argument is, and
 * letting the name decide here would excuse every unguarded role change.
 */
function namesAuthorization(name: string): boolean {
  if (name.length === 0) return false;
  const tail = name.split(".").pop() ?? name;
  if (name.includes(".") && COLLECTION_TESTS.has(normalizeKey(tail))) return false;
  if (AUTHZ_CALLS.has(normalizeKey(name)) || AUTHZ_CALLS.has(normalizeKey(tail))) return true;
  const tokens = tokensOf(name);
  const hasVerb = tokens.some((token) => AUTHZ_VERBS.has(token));
  const namesRole = tokens.some((token) => ROLE_TOKENS.has(token) || token === "owner" || token === "ownership");
  return hasVerb && namesRole;
}

/** Text that shows a query was narrowed to the authenticated caller. */
const CALLER_REFERENCE = /\b(session|viewer|actor|principal|identity|currentUser|caller)\b/i;

/** Object roots whose properties are the caller's submission, not the caller. */
const REQUEST_OBJECT_ROOT = /^(payload|body|form|formdata|input|args|arguments|params|query|data|patch|fields|values|dto|update|attrs|attributes)$/i;

/**
 * Is this expression the *caller's own* role, permission, or ownership claim?
 *
 * The distinction this makes is the whole reason the rule works. `session.role`
 * and `membership.role` describe who is asking; `input.role` and a bare `role`
 * destructured from the body describe what they asked for. Comparing the second
 * against a list of valid values is input validation, and mistaking it for an
 * authorization check is how a scanner concludes that an unguarded role change is
 * fine.
 */
function isSubjectRoleExpression(context: RuleContext, node: ts.Node, scopeNode: ts.Node): boolean {
  const file = context.file;
  let target = node;
  while (ts.isNonNullExpression(target) || ts.isParenthesizedExpression(target) || ts.isAwaitExpression(target)) {
    target = target.expression;
  }
  if (ts.isPropertyAccessChain(target) || ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) {
    const text = target.getText(file.source);
    if (!isRoleExpression(text)) return false;
    return !readsRequestObject(text);
  }
  if (ts.isIdentifier(target)) {
    if (!isRoleExpression(target.text)) return false;
    // A destructured role only counts when it came out of a subject rather than a
    // request object: `const { role } = ctx.session` yes, `= ctx.request.body` no.
    return boundFromSubject(context, target.text, scopeNode);
  }
  return false;
}

/** Does this dotted path read a property off the request's own payload? */
function readsRequestObject(text: string): boolean {
  const segments = text.split(/[.[\]?!]+/).filter(Boolean);
  const first = segments[0];
  if (first && REQUEST_OBJECT_ROOT.test(first)) return true;
  if (!first || !/^(req|request|ctx|context|c|event|this)$/i.test(first)) return false;
  return segments.slice(1, 4).some((segment) => REQUEST_OBJECT_ROOT.test(segment));
}

/** Was this binding destructured or assigned from a subject rather than a payload? */
function boundFromSubject(context: RuleContext, name: string, scopeNode: ts.Node): boolean {
  let subject = false;
  walk(scopeNode, (node) => {
    if (subject || !ts.isVariableDeclaration(node) || !node.initializer) return;
    const declares =
      (ts.isIdentifier(node.name) && node.name.text === name) ||
      (ts.isObjectBindingPattern(node.name) &&
        node.name.elements.some((element) => ts.isIdentifier(element.name) && element.name.text === name));
    if (!declares) return;
    const source = node.initializer.getText(context.file.source);
    if (readsRequestObject(source)) return;
    if (/\b(session|viewer|actor|principal|identity|membership|assignment|currentUser|me|caller|user|account|profile|member)\b/i.test(source)) {
      subject = true;
    }
  });
  return subject;
}

/** Property keys that introduce a query filter. */
const FILTER_KEYS = new Set(["where", "filter", "criteria", "match", "$match", "query", "conditions", "having", "find"]);

/** Property keys that introduce a projection: these name the row's columns, not a write. */
const PROJECTION_KEYS = new Set(["select", "returning", "columns", "projection", "fields", "include", "omit", "orderby", "distinct"]);

/**
 * What role a property plays in a database call: the payload being written, the
 * filter selecting rows, or the projection naming columns to read back.
 *
 * The nearest enclosing clause wins. `update({ data: {...}, select: { role: true } })`
 * writes `data` and only *reads* `role`, and a rule that cannot tell those apart
 * reports every settings endpoint that returns the caller's role.
 */
function payloadContext(node: ts.Node): "write" | "filter" | "projection" | null {
  let current: ts.Node | undefined = node.parent;
  let depth = 0;
  while (current && depth < 8) {
    if (ts.isPropertyAssignment(current) && (ts.isIdentifier(current.name) || ts.isStringLiteralLike(current.name))) {
      const key = normalizeKey(current.name.text);
      if (WRITE_PAYLOAD_KEYS.has(key)) return "write";
      if (FILTER_KEYS.has(key)) return "filter";
      if (PROJECTION_KEYS.has(key)) return "projection";
    }
    if (ts.isCallExpression(current)) {
      const tail = normalizeKey(calleeTail(current));
      if (PROJECTION_KEYS.has(tail)) return "projection";
      if (WRITE_METHODS.has(tail)) return "write";
    }
    current = current.parent;
    depth += 1;
  }
  return null;
}

/* ---------------------------------------------------------- data operation model */

/** Write methods whose name alone identifies a database operation. */
const UNAMBIGUOUS_WRITES = new Set([
  "updateone", "updatemany", "insertone", "insertmany", "deleteone", "deletemany", "findoneandupdate",
  "findoneanddelete", "findbyidandupdate", "findbyidanddelete", "createmany", "replaceone", "upsert",
  "bulkwrite"
]);

/** Write methods that need a database-shaped receiver to be believable. */
const AMBIGUOUS_WRITES = new Set(["update", "create", "insert", "delete", "destroy", "remove", "save", "set", "values", "add", "put"]);

const WRITE_METHODS = new Set([...UNAMBIGUOUS_WRITES, ...AMBIGUOUS_WRITES]);

/** Property names that hold the payload a write applies. */
const WRITE_PAYLOAD_KEYS = new Set([
  "data", "set", "$set", "values", "create", "update", "doc", "document", "attributes", "payload", "changes",
  "record"
]);

/** Methods that take a key and a value on every web primitive that has them. */
const KEYED_SETTERS = new Set(["set", "add", "put"]);

/** Receivers that are browser, protocol, or collection primitives, never tables. */
const WEB_STORE_RECEIVER =
  /(^|\.)(cookies?|cookieStore|headers?|searchParams|urlSearchParams|formData|localStorage|sessionStorage|response|reply|res|req|request|params|query|map|weakMap|weakSet|set|cache|env|process|window|document|logger|log|metrics|span|emitter|bus)$/i;

const DATABASE_RECEIVER =
  /\b(db|database|prisma|knex|pool|client|conn|connection|sequelize|mongoose|mongo|collection|repo|repository|store|model|models|table|tx|trx|sql|pg|mysql|sqlite|drizzle|orm|dao|entity|manager)\b/i;

/**
 * SQL that changes rows. The shape is required, not just the verb: a log message
 * reading "could not update user" is not a database write.
 */
const MUTATING_SQL = /\binsert\s+into\s+[`"\w.]+|\bupdate\s+[`"\w.]+\s+set\b|\bdelete\s+from\s+[`"\w.]+|\bmerge\s+into\s+[`"\w.]+/is;

interface WriteOperation {
  call: ts.CallExpression;
  /** `create` when the row is new, `update` when an existing row is modified. */
  kind: "create" | "update" | "delete";
  /** The text a rule can inspect for column names. */
  subject: string;
}

function classifyWrite(context: RuleContext, call: ts.CallExpression): WriteOperation | null {
  const file = context.file;
  const tail = calleeTail(call);
  const normalized = normalizeKey(tail);
  const receiver = ts.isPropertyAccessExpression(call.expression)
    ? call.expression.expression.getText(file.source)
    : "";

  if (UNAMBIGUOUS_WRITES.has(normalized)) {
    return { call, kind: kindOf(normalized), subject: `${receiver}.${tail}` };
  }

  if (AMBIGUOUS_WRITES.has(normalized)) {
    if (!DATABASE_RECEIVER.test(receiver)) return null;
    if (WEB_STORE_RECEIVER.test(receiver)) return null;
    // A query builder's `.set()` takes exactly one payload object. A cookie jar,
    // a header bag, and a Map all take a key and a value, and calling any of those
    // a database write is how a rule about database writes ends up reporting
    // `cookies().set(name, "", options)`.
    if (KEYED_SETTERS.has(normalized) && (call.arguments.length !== 1 || !isObjectish(call.arguments[0]!))) {
      return null;
    }
    return { call, kind: kindOf(normalized, receiver), subject: `${receiver}.${tail}` };
  }

  // Raw SQL: the statement itself says what it does.
  const sql = call.arguments.map((argument) => literalTextOf(argument) ?? argument.getText(file.source)).join(" ");
  if (MUTATING_SQL.test(sql)) {
    const kind: WriteOperation["kind"] = /\bdelete\s+from\b/i.test(sql)
      ? "delete"
      : /\bupdate\s+\w/i.test(sql)
        ? "update"
        : "create";
    return { call, kind, subject: sql };
  }
  return null;
}

function kindOf(method: string, receiver = ""): WriteOperation["kind"] {
  if (/delete|destroy|remove/.test(method)) return "delete";
  if (/insert|create/.test(method)) return "create";
  if (method === "values" || method === "add") return /insert|create/i.test(receiver) ? "create" : "update";
  if (method === "set") return /insert/i.test(receiver) ? "create" : "update";
  return "update";
}

function isObjectish(node: ts.Node): boolean {
  return ts.isObjectLiteralExpression(node) || ts.isIdentifier(node) || ts.isPropertyAccessExpression(node);
}

function writesIn(context: RuleContext, node: ts.Node): WriteOperation[] {
  const out: WriteOperation[] = [];
  for (const call of collect(node, ts.isCallExpression)) {
    const write = classifyWrite(context, call);
    if (write) out.push(write);
  }
  return out;
}

/** Does this node read or write a record that belongs to one subject? */
function touchesPerSubjectRecord(context: RuleContext, node: ts.Node): boolean {
  const text = node.getText(context.file.source);
  if (OWNER_COLUMN.test(text)) return true;
  for (const call of collect(node, ts.isCallExpression)) {
    const callee = calleeName(call);
    const argumentText = call.arguments
      .filter((argument) => !ts.isArrowFunction(argument) && !ts.isFunctionExpression(argument))
      .map((argument) => literalTextOf(argument) ?? argument.getText(context.file.source))
      .join(" ");
    const tokens = [...tokensOf(callee), ...tokensOf(argumentText)];
    if (tokens.some((token) => IDENTITY_TABLE_TOKENS.has(token))) return true;
  }
  return false;
}

/** Does the node perform any data access at all? Used to keep empty handlers quiet. */
function performsDataAccess(context: RuleContext, node: ts.Node, visited = new Set<string>()): boolean {
  let found = false;
  walk(node, (inner) => {
    if (found || !ts.isCallExpression(inner)) return;
    const name = calleeName(inner);
    if (DATABASE_RECEIVER.test(name) || /\bfetch\b|axios|request\(|readFile|writeFile|createReadStream|exec|spawn/i.test(name)) {
      found = true;
      return;
    }
    if (classifyWrite(context, inner)) {
      found = true;
      return;
    }
    const local = moduleFunctionBody(context, name, visited);
    if (local && performsDataAccess(context, local, visited)) found = true;
  });
  return found;
}

/** Calls that hand a value back to the caller. */
const RESPONSE_SENDERS = new Set(["json", "send", "end", "write", "html", "render", "text", "reply", "sendfile", "sendstatus"]);

/**
 * Does this handler actually serve state, rather than a constant?
 *
 * A route whose name says it is privileged is only worth reporting when it does
 * something. Requiring a database or filesystem call is too strict: an in-memory
 * store is still a store, and returning the user table from a module-level binding
 * is exactly the administrative listing this rule exists to find. Requiring only
 * that *some* module binding is returned is too loose: an endpoint that answers
 * with a hardcoded list of template names is configuration, not data, and
 * reporting it is the noise that trains a reader to ignore the tool.
 *
 * The line between them is whether the binding's value is written in this file. A
 * literal array of strings is a constant; an import, or anything built by a call,
 * is state this module did not author and cannot vouch for.
 */
function servesStatefulData(context: RuleContext, node: ts.Node): boolean {
  if (performsDataAccess(context, node)) return true;

  let found = false;
  const visited = new Set<string>();
  walk(node, (inner) => {
    if (found || !ts.isCallExpression(inner)) return;
    if (RESPONSE_SENDERS.has(normalizeKey(calleeTail(inner)))) {
      for (const argument of inner.arguments) {
        for (const identifier of collect(argument, ts.isIdentifier)) {
          if (isExternalModuleBinding(context, identifier.text)) {
            found = true;
            return;
          }
        }
      }
    }
    // A dispatcher branch usually delegates; the response is sent one hop away.
    const local = moduleFunctionBody(context, calleeName(inner), visited);
    if (local && servesStatefulData(context, local)) found = true;
  });
  return found;
}

/** A module-level binding whose value is not a constant written in this file. */
function isExternalModuleBinding(context: RuleContext, name: string): boolean {
  for (const statement of context.file.source.statements) {
    if (ts.isImportDeclaration(statement) && importsName(statement, name)) return true;
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      const names = ts.isIdentifier(declaration.name)
        ? [declaration.name.text]
        : bindingNames(declaration.name);
      if (!names.includes(name)) continue;
      return !isStaticLiteral(declaration.initializer);
    }
  }
  return false;
}

function importsName(statement: ts.ImportDeclaration, name: string): boolean {
  const clause = statement.importClause;
  if (!clause) return false;
  if (clause.name?.text === name) return true;
  const bindings = clause.namedBindings;
  if (!bindings) return false;
  if (ts.isNamespaceImport(bindings)) return bindings.name.text === name;
  return bindings.elements.some((element) => element.name.text === name);
}

function bindingNames(pattern: ts.BindingName): string[] {
  if (ts.isIdentifier(pattern)) return [pattern.text];
  const out: string[] = [];
  for (const element of pattern.elements) {
    if (ts.isOmittedExpression(element)) continue;
    out.push(...bindingNames(element.name));
  }
  return out;
}

/** Is this initializer composed of literals and nothing else? */
function isStaticLiteral(node: ts.Expression | undefined): boolean {
  if (!node) return false;
  if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return true;
  if (
    node.kind === ts.SyntaxKind.TrueKeyword ||
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword
  ) {
    return true;
  }
  if (ts.isPrefixUnaryExpression(node)) return isStaticLiteral(node.operand);
  if (ts.isAsExpression(node) || ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node)) {
    return isStaticLiteral(node.expression);
  }
  if (ts.isArrayLiteralExpression(node)) return node.elements.every((element) => isStaticLiteral(element));
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.every((property) => ts.isPropertyAssignment(property) && isStaticLiteral(property.initializer));
  }
  return false;
}

/* ------------------------------------------------------------- route attribution */

/**
 * The address a reader would use to reach this code.
 *
 * GraphQL resolvers and tRPC procedures are not bound to an HTTP path in the file
 * that declares them, so they are named the way their clients name them: the
 * transport endpoint for GraphQL, the dotted procedure path for tRPC. Without
 * that, a finding in either has no address at all.
 */
function attributeRoute(context: RuleContext, node: ts.Node): string | undefined {
  const procedure = trpcProcedurePath(context, node);
  if (procedure) return procedure;
  if (graphqlOperation(context, node)) return "POST /graphql";

  const line = lineOf(context.file, node);
  let best: { method: string; path: string; line: number } | undefined;
  for (const hint of context.routes) {
    if (hint.line <= line && (!best || hint.line > best.line)) best = hint;
  }
  if (!best) return undefined;
  return best.method === "ANY" ? best.path : `${best.method} ${best.path}`;
}

/** `Mutation: { updateMemberRole: ... }` gives the operation this node implements. */
function graphqlOperation(context: RuleContext, node: ts.Node): string | null {
  let current: ts.Node | undefined = node;
  let operation: string | null = null;
  while (current) {
    if (ts.isPropertyAssignment(current) && (ts.isIdentifier(current.name) || ts.isStringLiteralLike(current.name))) {
      const key = current.name.text;
      if (["Query", "Mutation", "Subscription"].includes(key)) return operation;
      operation = key;
    }
    current = current.parent;
  }
  void context;
  return null;
}

/** `members.setRole` for a procedure declared inside `membersRouter = router({...})`. */
function trpcProcedurePath(context: RuleContext, node: ts.Node): string | null {
  let current: ts.Node | undefined = node;
  let procedure: string | null = null;
  let namespace: string | null = null;

  while (current) {
    if (
      ts.isPropertyAssignment(current) &&
      (ts.isIdentifier(current.name) || ts.isStringLiteralLike(current.name)) &&
      procedureBase(current.initializer, context.file) !== null
    ) {
      procedure = current.name.text;
    }
    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name) && procedure) {
      namespace = current.name.text.replace(/[Rr]outer$/, "");
      break;
    }
    current = current.parent;
  }

  if (!procedure) return null;
  if (!namespace || namespace.length === 0) return procedure;
  return `${namespace.charAt(0).toLowerCase()}${namespace.slice(1)}.${procedure}`;
}

/** The `publicProcedure` / `protectedProcedure` a chain is built on. */
function procedureBase(expression: ts.Expression, file: ParsedFile): string | null {
  let current: ts.Node = expression;
  for (let depth = 0; depth < 12; depth += 1) {
    if (ts.isIdentifier(current)) {
      return /procedure$/i.test(current.text) ? current.text : null;
    }
    if (ts.isCallExpression(current) || ts.isPropertyAccessExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isNonNullExpression(current) || ts.isParenthesizedExpression(current) || ts.isAsExpression(current)) {
      current = current.expression;
      continue;
    }
    void file;
    return null;
  }
  return null;
}

/* ---------------------------------------------------------------- endpoint model */

type EndpointKind = "file-route" | "server-action" | "registration" | "trpc" | "graphql" | "dispatch";

interface Endpoint {
  kind: EndpointKind;
  /** How a reader refers to this endpoint. */
  label: string;
  route?: string;
  /** Where a finding about this endpoint belongs. */
  anchor: ts.Node;
  /** The handler body, for taint and for identity checks. */
  body: ts.Node;
  /** Everything that gates the handler: middleware, route options, procedure base. */
  gate: ts.Node[];
  authenticated: boolean;
  stateChanging: boolean;
}

function collectEndpoints(context: RuleContext): Endpoint[] {
  return [
    ...fileRouteEndpoints(context),
    ...serverActionEndpoints(context),
    ...registrationEndpoints(context),
    ...trpcEndpoints(context),
    ...graphqlEndpoints(context)
  ];
}

/**
 * Endpoints recovered from route discovery rather than from a registration call.
 *
 * A hand-rolled dispatcher — one `http.createServer` handler with a chain of
 * `if (route === "GET /api/admin/users")` branches — has no registration to model,
 * but route discovery recognises the comparison and hands back the branch that
 * implements it. That branch is a real endpoint boundary, so a trigger keyed to the
 * route's *name* can be judged on it exactly as on a registered route, and a
 * dispatcher stops being a blind spot for the one trigger that needs nothing but
 * the path and the branch body.
 *
 * Only privileged-looking paths are recovered, and only where a registration did
 * not already cover them. Enumerating every branch of a dispatcher as an endpoint
 * is the part this engine cannot do reliably — a branch may delegate to a helper
 * shared with three other routes — so the rules that depend on comparing siblings
 * deliberately do not consume these.
 */
function dispatchEndpoints(context: RuleContext, covered: readonly Endpoint[]): Endpoint[] {
  const out: Endpoint[] = [];
  for (const hint of context.routes) {
    const node = hint.node;
    if (!node || hint.method === "ANY") continue;
    if (!PRIVILEGED_PATH.test(hint.path)) continue;
    const route = `${hint.method} ${hint.path}`;
    if (covered.some((endpoint) => endpoint.route === route || spans(endpoint.body, node))) continue;
    if (out.some((endpoint) => endpoint.route === route)) continue;

    out.push({
      kind: "dispatch",
      label: route,
      route,
      anchor: node,
      body: node,
      gate: [],
      authenticated: resolvesIdentity(context, node),
      stateChanging: STATE_CHANGING.has(hint.method)
    });
  }
  return out;
}

function spans(container: ts.Node, node: ts.Node): boolean {
  return node.getStart() >= container.getStart() && node.getEnd() <= container.getEnd();
}

/**
 * GraphQL resolvers. Each field under `Query`, `Mutation`, or `Subscription` is an
 * endpoint a client addresses by name over the single GraphQL transport, so a
 * missing check in one of them is the same defect as on an HTTP route.
 */
function graphqlEndpoints(context: RuleContext): Endpoint[] {
  const out: Endpoint[] = [];
  for (const group of collect(context.file.source, ts.isPropertyAssignment)) {
    const groupName = propertyKeyOf(group, context.file);
    if (!groupName || !["Query", "Mutation", "Subscription"].includes(groupName)) continue;
    if (!ts.isObjectLiteralExpression(group.initializer)) continue;

    for (const field of group.initializer.properties) {
      if (!ts.isPropertyAssignment(field) && !ts.isMethodDeclaration(field)) continue;
      const name = propertyKeyOf(field, context.file);
      if (!name) continue;
      const fn = ts.isMethodDeclaration(field)
        ? field
        : ts.isArrowFunction(field.initializer) || ts.isFunctionExpression(field.initializer)
          ? field.initializer
          : null;
      if (!fn?.body) continue;

      out.push({
        kind: "graphql",
        label: `the ${name} ${groupName === "Mutation" ? "mutation" : groupName === "Subscription" ? "subscription" : "query"}`,
        route: "POST /graphql",
        anchor: field,
        body: fn.body,
        gate: [],
        authenticated: resolvesIdentity(context, fn.body),
        stateChanging: groupName === "Mutation"
      });
    }
  }
  return out;
}

/** `"use server"` / `"use client"` at the top of a module. */
function moduleDirective(file: ParsedFile, directive: string): boolean {
  for (const statement of file.source.statements.slice(0, 3)) {
    if (!ts.isExpressionStatement(statement)) continue;
    const text = literalTextOf(statement.expression);
    if (text === directive) return true;
  }
  return false;
}

function isExported(node: ts.Node): boolean {
  const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  if (modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) return true;
  // `export const POST = async () => {}` puts the modifier on the statement.
  const statement = node.parent?.parent;
  if (statement && ts.isVariableStatement(statement)) {
    const outer = ts.getModifiers(statement);
    return outer?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false;
  }
  return false;
}

interface ExportedFunction {
  name: string;
  declaration: ts.Node;
  fn: ts.FunctionLikeDeclaration;
}

function exportedFunctions(file: ParsedFile): ExportedFunction[] {
  const out: ExportedFunction[] = [];
  for (const statement of file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name && statement.body && isExported(statement)) {
      out.push({ name: statement.name.text, declaration: statement, fn: statement });
      continue;
    }
    if (!ts.isVariableStatement(statement)) continue;
    const exported = ts.getModifiers(statement)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const initializer = declaration.initializer;
      if (!ts.isArrowFunction(initializer) && !ts.isFunctionExpression(initializer)) continue;
      out.push({ name: declaration.name.text, declaration, fn: initializer });
    }
  }
  return out;
}

/** Next.js route handlers: one exported function per HTTP method. */
function fileRouteEndpoints(context: RuleContext): Endpoint[] {
  const path = routeFromFilePath(context.file.relativePath);
  if (!path) return [];
  const out: Endpoint[] = [];
  for (const exported of exportedFunctions(context.file)) {
    const method = exported.name.toUpperCase();
    if (!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].includes(method)) continue;
    const body = exported.fn.body;
    if (!body) continue;
    out.push({
      kind: "file-route",
      label: `${method} ${path}`,
      route: `${method} ${path}`,
      anchor: exported.declaration,
      body,
      gate: [],
      authenticated: resolvesIdentity(context, body),
      stateChanging: STATE_CHANGING.has(method)
    });
  }
  return out;
}

/**
 * Next.js server actions. Each exported function in a `"use server"` module is a
 * POST endpoint the framework will invoke for anyone who can address it, which is
 * why a missing session check there is the same defect as on a route handler.
 */
function serverActionEndpoints(context: RuleContext): Endpoint[] {
  if (!moduleDirective(context.file, "use server")) return [];
  const out: Endpoint[] = [];
  for (const exported of exportedFunctions(context.file)) {
    const body = exported.fn.body;
    if (!body) continue;
    out.push({
      kind: "server-action",
      label: `server action ${exported.name}()`,
      anchor: exported.declaration,
      body,
      gate: [],
      authenticated: resolvesIdentity(context, body),
      stateChanging: true
    });
  }
  return out;
}

/** Is this identifier a framework instance declared in this file? */
function frameworkInstances(file: ParsedFile): Set<string> {
  const names = new Set(["app", "router", "server", "api", "fastify", "route", "r"]);
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
    const text = declaration.initializer.getText(file.source);
    if (/new\s+Hono|express\s*\(|express\.Router\s*\(|Router\s*\(|new\s+Koa|Fastify\s*\(|fastify\s*\(|new\s+OpenAPIHono/.test(text)) {
      names.add(declaration.name.text);
    }
  }
  return names;
}

const HTTP_REGISTRATION_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all"]);

/** Express, Koa, Fastify and Hono style registrations, with their middleware. */
function registrationEndpoints(context: RuleContext): Endpoint[] {
  const file = context.file;
  const instances = frameworkInstances(file);
  const out: Endpoint[] = [];

  // Middleware mounted on the instance itself applies to every route it carries.
  const moduleLevelAuth = new Set<string>();
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeTail(call) !== "use" || !ts.isPropertyAccessExpression(call.expression)) continue;
    const receiver = call.expression.expression.getText(file.source);
    if (!instances.has(receiver)) continue;
    if (call.arguments.some((argument) => resolvesIdentity(context, argument, new Set(), true))) moduleLevelAuth.add(receiver);
  }

  for (const call of collect(file.source, ts.isCallExpression)) {
    const tail = calleeTail(call).toLowerCase();
    if (!HTTP_REGISTRATION_METHODS.has(tail)) continue;
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const receiver = call.expression.expression.getText(file.source);
    if (!instances.has(receiver)) continue;

    const first = call.arguments[0];
    const path = first ? literalTextOf(first) : null;
    if (!path || !path.startsWith("/")) continue;

    const handler = call.arguments.find(
      (argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)
    ) as ts.ArrowFunction | ts.FunctionExpression | undefined;
    const gate = call.arguments.filter((argument) => argument !== handler && argument !== first);
    const body = handler?.body ?? call;
    const method = tail === "all" ? "ANY" : tail.toUpperCase();

    out.push({
      kind: "registration",
      label: `${method} ${path}`,
      route: `${method} ${path}`,
      anchor: call,
      body,
      gate,
      authenticated:
        moduleLevelAuth.has(receiver) ||
        gate.some((argument) => resolvesIdentity(context, argument, new Set(), true)) ||
        (handler ? resolvesIdentity(context, body) : true),
      stateChanging: STATE_CHANGING.has(method)
    });
  }
  return out;
}

/** tRPC procedures, whose gate is the procedure they are built on. */
function trpcEndpoints(context: RuleContext): Endpoint[] {
  const file = context.file;
  const out: Endpoint[] = [];

  for (const property of collect(file.source, ts.isPropertyAssignment)) {
    const base = procedureBase(property.initializer, file);
    if (base === null) continue;
    if (!ts.isIdentifier(property.name) && !ts.isStringLiteralLike(property.name)) continue;

    const handler = collect(property.initializer, ts.isCallExpression)
      .filter((call) => ["mutation", "query", "subscription"].includes(calleeTail(call)))
      .flatMap((call) => call.arguments.filter((argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)))
      .at(0) as ts.ArrowFunction | ts.FunctionExpression | undefined;
    if (!handler?.body) continue;

    const isMutation = collect(property.initializer, ts.isCallExpression).some((call) => calleeTail(call) === "mutation");
    const baseTokens = tokensOf(base);
    // `publicProcedure` says out loud that no session is required. Anything else —
    // protected, authed, admin — carries a middleware that resolves one.
    const gated = !baseTokens.includes("public") && !baseTokens.includes("open") && !baseTokens.includes("anonymous");

    out.push({
      kind: "trpc",
      label: trpcProcedurePath(context, property) ?? property.name.text,
      ...(trpcProcedurePath(context, property) ? { route: trpcProcedurePath(context, property)! } : {}),
      anchor: property,
      body: handler.body,
      gate: [property.initializer],
      authenticated: gated || resolvesIdentity(context, handler.body),
      stateChanging: isMutation
    });
  }
  return out;
}

/* -------------------------------------------------------------- caller-input model */

/**
 * Whether an expression is the caller's own submission, extended past what the
 * shared taint model covers.
 *
 * A Next.js server action receives its input as a `FormData` parameter, which the
 * shared model does not recognise as a request object. Without this the entire
 * server-action surface is invisible to a data-flow rule, so the extension is
 * local here and belongs upstream in `taint.ts`.
 */
function formDataParameters(fn: ts.Node): Set<string> {
  const names = new Set<string>();
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? ts.factory.createNodeArray([]);
  for (const parameter of parameters) {
    if (!ts.isIdentifier(parameter.name)) continue;
    const typeText = parameter.type ? parameter.type.getText() : "";
    if (/FormData|URLSearchParams/.test(typeText) || /^(formData|form|fields)$/.test(parameter.name.text)) {
      names.add(parameter.name.text);
    }
  }
  return names;
}

/** Calls that hand back a whole caller-supplied object. */
const WHOLE_BODY_READERS = new Set(["fromEntries", "json", "parseBody", "formData", "body", "readBody", "urlencoded"]);

function callerObjectOrigin(
  context: RuleContext,
  fn: ts.Node,
  node: ts.Node,
  scope: TaintScope,
  depth = 0
): string | null {
  if (depth > 4) return null;

  const shared = taintOrigin(node, scope);
  if (shared) return shared;

  const forms = formDataParameters(fn);
  if (ts.isIdentifier(node)) {
    if (forms.has(node.text)) return `the submitted form fields (${node.text})`;
    const initializer = scope.initializers.get(node.text);
    if (initializer) return callerObjectOrigin(context, fn, initializer, scope, depth + 1);
    return null;
  }
  if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node) || ts.isParenthesizedExpression(node) || ts.isNonNullExpression(node)) {
    return callerObjectOrigin(context, fn, node.expression, scope, depth + 1);
  }
  if (ts.isAwaitExpression(node)) return callerObjectOrigin(context, fn, node.expression, scope, depth + 1);
  if (ts.isCallExpression(node)) {
    const tail = calleeTail(node);
    if (WHOLE_BODY_READERS.has(tail)) {
      for (const argument of node.arguments) {
        const origin = callerObjectOrigin(context, fn, argument, scope, depth + 1);
        if (origin) return origin;
      }
      if (ts.isPropertyAccessExpression(node.expression)) {
        const origin = callerObjectOrigin(context, fn, node.expression.expression, scope, depth + 1);
        if (origin) return origin;
      }
    }
  }
  if (ts.isPropertyAccessExpression(node)) {
    const root = node.expression;
    if (ts.isIdentifier(root) && forms.has(root.text)) return `the submitted form fields (${root.text})`;
  }
  return null;
}

/* --------------------------------------------------------------- rule: no identity */

export const missingHandlerAuthentication: Rule = {
  id: "missing-handler-authentication",
  category: "missing_authentication",
  describes: "an endpoint that touches a per-subject record with no identity check, beside siblings that have one",
  run(context: RuleContext) {
    const endpoints = collectEndpoints(context);
    if (endpoints.length < 2) return;

    // The contrast is the evidence. A module where nothing is authenticated may be
    // a public API, and reporting every endpoint in it is noise, not a finding.
    const authenticated = endpoints.filter((endpoint) => endpoint.authenticated);
    if (authenticated.length === 0) return;

    for (const endpoint of endpoints) {
      if (endpoint.authenticated) continue;
      if (unauthenticatedByDesign(endpoint.label)) continue;
      // A sign-in, sign-out, or credential-exchange handler cannot require a
      // session: establishing one is what it is for.
      if (establishesSession(context, endpoint.body)) continue;

      const writes = writesIn(context, endpoint.body);
      const reads = performsDataAccess(context, endpoint.body);
      if (writes.length === 0 && !reads) continue;
      if (!touchesPerSubjectRecord(context, endpoint.body)) continue;

      const mutates = writes.length > 0;
      const siblings = authenticated.map((sibling) => sibling.label).join(", ");
      const route = endpoint.route ?? attributeRoute(context, endpoint.anchor);

      context.report({
        ruleId: "missing-handler-authentication",
        category: "missing_authentication",
        title: `${endpoint.label} ${mutates ? "writes" : "reads"} a per-user record without establishing who the caller is`,
        severity: mutates ? "critical" : "high",
        verification: "strong_evidence",
        summary: `${endpoint.label} ${mutates ? "writes to" : "reads"} a record scoped to a single subject, but nothing in it resolves a session, a token, or a user. ${
          authenticated.length === 1 ? `${siblings} in the same module does` : `${siblings} in the same module do`
        }, so the surrounding code establishes that this surface is meant to be authenticated and the check was omitted here rather than deliberately left off.${
          endpoint.kind === "server-action"
            ? " A server action is an HTTP POST endpoint: the framework will invoke it for any caller who can address it, and the form that normally calls it is not a constraint."
            : ""
        }`,
        impact: mutates
          ? "An unauthenticated caller writes rows belonging to accounts they have no relationship with. Where the row carries a role, a membership, or a notification setting, that is a direct route to taking over or silencing another account."
          : "An unauthenticated caller reads records belonging to other accounts by supplying their identifiers.",
        remediation: `Resolve the caller before any data access in ${endpoint.label} and return 401 when there is no session, using the same helper the authenticated ${
          authenticated.length === 1 ? "sibling uses" : "siblings use"
        }. Then derive the subject from that session rather than from the request, so the identifier in the payload cannot select a different account. Better still, put the check in shared middleware or a wrapper so a newly added handler inherits it instead of having to remember it.`,
        verificationPlan: `Call ${endpoint.label} with no cookies and no authorization header, using an identifier that belongs to another test account. The response must be 401 and the record must be unchanged; compare against the same call to ${authenticated[0]!.label}, which should already answer 401.`,
        taxonomy: ["CWE-306", "CWE-862", "OWASP-A01"],
        location: locationOf(context, endpoint.anchor),
        ...(route ? { route } : {}),
        evidence: [
          sourceEvidence(
            context,
            endpoint.anchor,
            `No session, token, or user lookup appears anywhere in ${endpoint.label}, which nonetheless ${mutates ? "writes" : "reads"} a subject-scoped record.`
          ),
          sourceEvidence(
            context,
            authenticated[0]!.anchor,
            `${authenticated[0]!.label} in the same module resolves the caller first, which is the check the reported endpoint is missing.`
          )
        ],
        reasoning: `${endpoint.label} contains no identity-resolving expression and no role check, performs ${mutates ? `a ${writes[0]!.kind} operation` : "a data read"} on a table or column scoped to a subject, and shares a module with ${authenticated.length} endpoint(s) that do resolve the caller.`
      });
    }
  }
};

/* ------------------------------------------------------------- rule: mass assignment */

export const massAssignment: Rule = {
  id: "mass-assignment-spread",
  category: "mass_assignment",
  describes: "caller-supplied fields spread wholesale into a database write",
  run(context: RuleContext) {
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);

      for (const call of collect(fn, ts.isCallExpression)) {
        const write = classifyWrite(context, call);
        if (!write || write.kind === "delete") continue;

        for (const payload of payloadsOf(context, call, scope)) {
          const line = lineOf(context.file, payload);
          if (reported.has(line)) continue;

          const spread = taintedSpread(context, fn, payload, scope);
          if (!spread) continue;

          const columns = privilegedColumnsNear(context, call);
          const table = tableOf(context, call);
          const identityRow = tokensOf(table).some((token) => IDENTITY_TABLE_TOKENS.has(token));
          reported.add(line);

          context.report({
            ruleId: "mass-assignment-spread",
            category: "mass_assignment",
            title: `Caller-supplied fields are spread into a database ${write.kind} without naming the columns they may set`,
            severity: identityRow || columns.length > 0 ? "high" : "medium",
            verification: "strong_evidence",
            summary: `The payload for this ${write.kind} is built by spreading ${spread.origin} into an object, so the set of columns written is whatever the caller chose to send rather than a list this code decided on.${
              columns.length > 0
                ? ` The same statement or module names ${columns.map((column) => `\`${column}\``).join(", ")} on this row, so ${columns.length === 1 ? "that column is" : "those columns are"} reachable by adding ${columns.length === 1 ? "it" : "them"} to the request.`
                : ""
            }${
              spread.deletions.length > 0
                ? ` The code removes ${spread.deletions.map((key) => `\`${key}\``).join(", ")} before the write, which is a denylist: it constrains the keys someone thought of, not the ones they did not.`
                : ""
            }`,
            impact:
              "A caller adds a field the form never renders and the value is written to their row. Where the row carries a role, a plan, a seat allowance, or a verification flag, that is privilege escalation or paid entitlement performed through the ordinary settings endpoint.",
            remediation:
              "Name the fields this operation accepts and copy only those into the payload, or parse the request through a schema that rejects unknown keys and assign from the parsed result. Do not delete keys from a spread object: the safe form is a list of what is allowed, because it fails closed when a column is added to the table.",
            verificationPlan: `Send the request this endpoint expects with one extra field${columns.length > 0 ? ` — ${columns[0]} is the one to try` : ""} — and read the row back. The extra field must be absent from the stored row and the request should be rejected rather than silently accepted.`,
            taxonomy: ["CWE-915", "CWE-639", "OWASP-A01", "OWASP-A04"],
            location: locationOf(context, payload),
            ...(attributeRoute(context, payload) ? { route: attributeRoute(context, payload)! } : {}),
            evidence: [
              sourceEvidence(context, payload, `The write payload spreads ${spread.origin} rather than assigning named columns.`),
              sourceEvidence(context, call, `The payload is applied by ${write.subject}${table ? ` on ${table}` : ""}.`)
            ],
            reasoning: `A spread of ${spread.origin} appears in the ${write.kind} payload of ${write.subject}; no allowlist of field names constrains it${spread.deletions.length > 0 ? `, only a denylist removing ${spread.deletions.join(", ")}` : ""}.`
          });
        }
      }
    }
  }
};

/** The object literals a write call will apply, including one level of `data:`/`set:`. */
function payloadsOf(context: RuleContext, call: ts.CallExpression, scope: TaintScope): ts.ObjectLiteralExpression[] {
  const out: ts.ObjectLiteralExpression[] = [];
  const push = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node) && !out.includes(node)) out.push(node);
  };

  for (const argument of call.arguments) {
    const resolved = resolveExpression(argument, scope);
    push(resolved);
    if (!ts.isObjectLiteralExpression(resolved)) continue;
    for (const property of resolved.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const key = propertyKeyOf(property, context.file);
      if (!key || !WRITE_PAYLOAD_KEYS.has(normalizeKey(key))) continue;
      const inner = resolveExpression(property.initializer, scope);
      push(inner);
      // Drizzle's upsert nests the update payload one level deeper again.
      if (ts.isObjectLiteralExpression(inner)) {
        for (const nested of inner.properties) {
          if (!ts.isPropertyAssignment(nested)) continue;
          const nestedKey = propertyKeyOf(nested, context.file);
          if (nestedKey && WRITE_PAYLOAD_KEYS.has(normalizeKey(nestedKey))) push(resolveExpression(nested.initializer, scope));
        }
      }
    }
  }
  return out;
}

interface TaintedSpread {
  origin: string;
  node: ts.Node;
  /** Keys the code deletes before the write: a denylist, not a fix. */
  deletions: string[];
}

/** A spread of caller input in this payload, if the safe forms do not explain it. */
function taintedSpread(
  context: RuleContext,
  fn: ts.Node,
  payload: ts.ObjectLiteralExpression,
  scope: TaintScope
): TaintedSpread | null {
  for (const property of payload.properties) {
    if (!ts.isSpreadAssignment(property)) continue;
    const expression = property.expression;

    // `...(x !== undefined ? { x } : {})` and `...{ a, b }` name their fields.
    if (ts.isParenthesizedExpression(expression) || ts.isConditionalExpression(expression)) continue;
    if (ts.isObjectLiteralExpression(expression)) continue;

    const resolved = resolveExpression(expression, scope);
    if (ts.isObjectLiteralExpression(resolved) && !hasSpread(resolved)) continue;
    if (isAllowlisted(context, resolved)) continue;

    const origin = callerObjectOrigin(context, fn, expression, scope);
    if (!origin) continue;

    return { origin, node: expression, deletions: deletedKeys(context, fn, expression) };
  }
  return null;
}

function hasSpread(node: ts.ObjectLiteralExpression): boolean {
  return node.properties.some((property) => ts.isSpreadAssignment(property));
}

/**
 * Shapes that constrain which keys survive: a pick, a filtered entry list, or a
 * schema parse in a module that declares the schema strict. Each is the correct
 * form of this code and must not be reported.
 */
function isAllowlisted(context: RuleContext, node: ts.Node): boolean {
  if (!ts.isCallExpression(node)) return false;
  const tail = calleeTail(node).toLowerCase();
  if (["pick", "pickby", "omitby", "filter", "sanitize", "sanitise", "whitelist", "allowlist"].includes(tail)) return true;
  if (tail === "fromentries") {
    const first = node.arguments[0];
    if (first && ts.isCallExpression(first) && ["filter", "map"].includes(calleeTail(first))) return true;
  }
  if (["parse", "safeparse", "validate", "cast", "decode", "assert"].includes(tail)) {
    return /\.strict\s*\(|additionalProperties\s*:\s*false|stripUnknown|unknown\s*:\s*['"]strip/.test(context.file.text);
  }
  // A helper in this module that returns an object literal of named properties is
  // a configuration builder, not a pass-through of the caller's fields — even when
  // the caller's value is one of its arguments.
  const body = moduleFunctionBody(context, calleeName(node), new Set());
  if (body) {
    const literals = collect(body, ts.isObjectLiteralExpression);
    if (literals.length > 0 && literals.every((literal) => !hasSpread(literal))) return true;
  }
  return false;
}

/** `delete patch.role` before the write: worth quoting, never a defence. */
function deletedKeys(context: RuleContext, fn: ts.Node, spreadExpression: ts.Node): string[] {
  const target = ts.isIdentifier(spreadExpression) ? spreadExpression.text : null;
  const keys: string[] = [];
  walk(fn, (node) => {
    if (!ts.isDeleteExpression(node)) return;
    const operand = node.expression;
    if (!ts.isPropertyAccessExpression(operand) && !ts.isElementAccessExpression(operand)) return;
    const base = operand.expression.getText(context.file.source);
    if (target !== null && base !== target) return;
    const key = ts.isPropertyAccessExpression(operand)
      ? operand.name.text
      : (literalTextOf(operand.argumentExpression) ?? operand.argumentExpression.getText(context.file.source));
    keys.push(key);
  });
  return keys;
}

/**
 * Privileged-looking columns visible on the row this write touches.
 *
 * The best evidence is in the statement itself: a `select`, `returning`, or
 * `columns` clause lists the row's own columns. Failing that the module is
 * searched, because a GraphQL input type or a neighbouring query names the same
 * columns and a reader needs to know which ones are reachable.
 */
function privilegedColumnsNear(context: RuleContext, call: ts.CallExpression): string[] {
  const found = new Set<string>();
  const consider = (name: string): void => {
    if (PRIVILEGED_COLUMNS.has(normalizeKey(name))) found.add(name);
  };

  // The projection is usually further along the same chain — `.update(patch)
  // .returning([...])` — so the search covers the whole statement, not one call.
  const scope = enclosingStatement(call) ?? call;

  const projections = collect(scope, ts.isPropertyAssignment).filter((property) => {
    const key = propertyKeyOf(property, context.file);
    return key !== null && ["select", "returning", "columns", "projection", "fields"].includes(normalizeKey(key));
  });
  for (const projection of projections) {
    for (const inner of collect(projection.initializer, ts.isPropertyAssignment)) {
      const key = propertyKeyOf(inner, context.file);
      if (key) consider(key);
    }
    for (const literal of collect(projection.initializer, ts.isStringLiteralLike)) consider(literal.text);
  }
  // `.returning(["id", "role", "seat_type"])` is a call, not a property.
  for (const inner of collect(scope, ts.isCallExpression)) {
    if (!["returning", "select", "pluck"].includes(calleeTail(inner))) continue;
    for (const literal of collect(inner, ts.isStringLiteralLike)) consider(literal.text);
    for (const property of collect(inner, ts.isPropertyAssignment)) {
      const key = propertyKeyOf(property, context.file);
      if (key) consider(key);
    }
  }

  if (found.size > 0) return [...found];

  // Failing that, any projection clause in the module names the same row's columns:
  // a neighbouring query, or a schema's own field list.
  for (const property of collect(context.file.source, ts.isPropertyAssignment)) {
    const key = propertyKeyOf(property, context.file);
    if (key && PROJECTION_KEYS.has(normalizeKey(key))) {
      for (const inner of collect(property.initializer, ts.isPropertyAssignment)) {
        const innerKey = propertyKeyOf(inner, context.file);
        if (innerKey) consider(innerKey);
      }
      for (const literal of collect(property.initializer, ts.isStringLiteralLike)) consider(literal.text);
    }
  }
  for (const inner of collect(context.file.source, ts.isCallExpression)) {
    if (!PROJECTION_KEYS.has(normalizeKey(calleeTail(inner)))) continue;
    for (const literal of collect(inner, ts.isStringLiteralLike)) consider(literal.text);
    for (const property of collect(inner, ts.isPropertyAssignment)) {
      const key = propertyKeyOf(property, context.file);
      if (key) consider(key);
    }
  }
  return [...found];
}

/** The whole statement a call belongs to, so a fluent chain is one unit. */
function enclosingStatement(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isStatement(current)) return current;
    current = current.parent;
  }
  return undefined;
}

/** The table or collection a write targets, from its receiver and its arguments. */
function tableOf(context: RuleContext, call: ts.CallExpression): string {
  const parts: string[] = [];
  if (ts.isPropertyAccessExpression(call.expression)) parts.push(call.expression.expression.getText(context.file.source));
  for (const argument of call.arguments) {
    if (ts.isIdentifier(argument) || ts.isStringLiteralLike(argument)) {
      parts.push(literalTextOf(argument) ?? argument.getText(context.file.source));
    }
  }
  return parts.join(" ").slice(0, 200);
}

/* ------------------------------------------------- rule: function-level authorization */

export const privilegedOperationWithoutRoleCheck: Rule = {
  id: "privileged-operation-without-role-check",
  category: "broken_function_level_authorization",
  describes: "an administrative operation, or a resolved role never compared, in a handler with no authorization check",
  run(context: RuleContext) {
    const registered = collectEndpoints(context);
    for (const endpoint of [...registered, ...dispatchEndpoints(context, registered)]) {
      if (unauthenticatedByDesign(endpoint.label)) continue;
      if (endpoint.route && DIAGNOSTIC_PATH.test(endpoint.route)) continue;

      const check =
        findRoleCheck(context, endpoint.body) ??
        endpoint.gate.map((scope) => findRoleCheck(context, scope, new Set(), true)).find(Boolean) ??
        null;
      if (check) continue;

      const write = privilegedWriteIn(context, endpoint.body);
      const unusedRole = resolvedButUncomparedRole(context, endpoint);
      const privilegedByPath = Boolean(endpoint.route && PRIVILEGED_PATH.test(endpoint.route));

      // An endpoint with no identity at all is the missing-authentication defect,
      // not this one. Reporting both describes one omission twice with one fix.
      if (!endpoint.authenticated && !privilegedByPath) continue;
      if (!write && !unusedRole && !privilegedByPath) continue;
      if (privilegedByPath && !write && !unusedRole && !servesStatefulData(context, endpoint.body)) continue;

      const control = write ? write.columns.some((column) => CONTROL_COLUMNS.has(normalizeKey(column))) : false;
      const anchor = write?.node ?? unusedRole?.node ?? endpoint.anchor;
      const route = endpoint.route ?? attributeRoute(context, anchor);

      const what = write
        ? `writes ${write.columns.map((column) => `\`${column}\``).join(", ")} on an existing row`
        : unusedRole
          ? "resolves the caller's own role and never compares it"
          : "sits on a path reserved for operators";

      context.report({
        ruleId: "privileged-operation-without-role-check",
        category: "broken_function_level_authorization",
        title: `${endpoint.label} ${what} with no authorization check`,
        severity: control || !endpoint.authenticated ? "critical" : "high",
        verification: unusedRole && !write ? "strong_evidence" : "needs_review",
        summary: summaryFor(endpoint, write, unusedRole, privilegedByPath),
        impact: control
          ? "Any caller who reaches this endpoint can change who holds which role. In practice that means a viewer promotes itself to owner and then has every permission the application defines, including the ability to remove the real owner."
          : "Any caller who reaches this endpoint performs an operation the application reserves for a subset of its members — changing a plan, a seat allowance, or another account's state — and is billed to, or borne by, the organisation rather than them.",
        remediation: `Compare the caller's role against the privilege this operation needs before performing it, and answer 403 when it does not match.${
          unusedRole ? " The role is already loaded here, so the fix is the comparison rather than another query." : ""
        } Put the comparison in the same place for every administrative operation — a middleware, a procedure builder, or a helper such as the one a sibling in this module already uses — so a newly added operation inherits the check instead of needing to remember it.`,
        verificationPlan: write || unusedRole
          ? `Sign in as an account with the lowest role this endpoint's tenant offers and call ${endpoint.label} against a row it should not be able to change. The response must be 403 and the row must be unchanged. Repeat as a privileged account to confirm the operation still works.`
          : `Sign in as an ordinary, non-administrative account and call ${endpoint.label}. The response must be 403 or 404 and must contain none of the data the route serves. Repeat with an administrative account to confirm the route still works, and compare the two responses: if they are the same, the route has no authorization at all.`,
        taxonomy: ["CWE-285", "CWE-862", "CWE-269", "OWASP-A01"],
        location: locationOf(context, anchor),
        ...(route ? { route } : {}),
        evidence: evidenceFor(context, endpoint, write, unusedRole),
        reasoning: `No comparison, membership test, or authorization call involving a role, permission, or ownership claim appears in ${endpoint.label} or in its middleware, options, or procedure chain, while the handler ${
          write ? `updates ${write.columns.join(", ")}` : unusedRole ? "loads the caller's role for the target tenant" : "serves a privileged path"
        }.`
      });
    }
  }
};

interface PrivilegedWrite {
  node: ts.Node;
  columns: string[];
  subject: string;
}

/** An update that changes a column whose value is itself an authorization decision. */
function privilegedWriteIn(context: RuleContext, node: ts.Node): PrivilegedWrite | null {
  for (const call of collect(node, ts.isCallExpression)) {
    const write = classifyWrite(context, call);
    // Creating a row with a role is how invitations and sign-ups work. Changing an
    // existing row's role is the escalation, so only updates qualify.
    if (!write || write.kind !== "update") continue;

    const columns = new Set<string>();
    for (const property of collect(call, ts.isPropertyAssignment)) {
      const key = propertyKeyOf(property, context.file);
      if (!key) continue;
      if (!PRIVILEGED_COLUMNS.has(normalizeKey(key))) continue;
      if (payloadContext(property) !== "write") continue;
      columns.add(key);
    }
    for (const property of collect(call, ts.isShorthandPropertyAssignment)) {
      const key = property.name.text;
      if (!PRIVILEGED_COLUMNS.has(normalizeKey(key))) continue;
      if (payloadContext(property) !== "write") continue;
      columns.add(key);
    }
    // Raw SQL: `UPDATE workspace_members SET role = $1, updated_at = now()`.
    const setClause = /\bset\b([\s\S]*?)(?:\bwhere\b|\breturning\b|$)/i.exec(write.subject);
    if (setClause?.[1]) {
      for (const assignment of setClause[1].split(",")) {
        const name = assignment.split("=")[0]?.trim() ?? "";
        if (name.length > 0 && PRIVILEGED_COLUMNS.has(normalizeKey(name.split(".").pop() ?? name))) columns.add(name);
      }
    }

    if (columns.size > 0) return { node: call, columns: [...columns], subject: write.subject };
  }
  return null;
}

interface UncomparedRole {
  node: ts.Node;
  binding: string;
}

/**
 * The clearest possible evidence: the handler asks the database for the caller's
 * own role, and then never compares it.
 *
 * The lookup has to be scoped to the caller — otherwise reading a role column back
 * out of a row the handler just wrote would look like an authorization decision.
 */
function resolvedButUncomparedRole(context: RuleContext, endpoint: Endpoint): UncomparedRole | null {
  if (!endpoint.authenticated || !endpoint.stateChanging) return null;
  if (writesIn(context, endpoint.body).length === 0) return null;

  const file = context.file;
  for (const call of collect(endpoint.body, ts.isCallExpression)) {
    const tail = calleeTail(call).toLowerCase();
    if (!["findfirst", "findone", "findunique", "findmany", "query", "get", "select"].includes(tail)) continue;

    // The lookup has to be about the caller. Reading a role column back out of a
    // row the handler just wrote is not an authorization decision.
    const filterText = collect(call, ts.isPropertyAssignment)
      .filter((property) => {
        const key = propertyKeyOf(property, file);
        return key !== null && FILTER_KEYS.has(normalizeKey(key));
      })
      .map((property) => property.initializer.getText(file.source))
      .join(" ");
    if (!CALLER_REFERENCE.test(filterText) && !isIdentityPath(filterText)) continue;

    const roleProperty = collect(call, ts.isPropertyAssignment).find((property) => {
      const key = propertyKeyOf(property, file);
      if (!key || !ROLE_TOKENS.has(normalizeKey(key))) return false;
      return payloadContext(property) === "projection";
    });
    if (!roleProperty) continue;

    return { node: roleProperty, binding: roleProperty.getText(file.source).slice(0, 60) };
  }
  return null;
}

function summaryFor(
  endpoint: Endpoint,
  write: PrivilegedWrite | null,
  unusedRole: UncomparedRole | null,
  privilegedByPath: boolean
): string {
  const gate = endpoint.authenticated
    ? "The caller is identified — a session, a token, or a membership is resolved — but being identified is treated as being entitled."
    : "Nothing in the handler or its middleware identifies the caller at all.";

  if (write) {
    return `${endpoint.label} updates ${write.columns.map((column) => `\`${column}\``).join(", ")} on a row that already exists. That value is itself an authorization decision: whoever can set it decides what the affected account may do. ${gate} No comparison of the caller's own role, permission, or ownership appears anywhere in the handler, its middleware, or its procedure chain.${
      unusedRole ? " The handler even loads the caller's role for this tenant and then does not look at it." : ""
    }`;
  }
  if (unusedRole) {
    return `${endpoint.label} queries the caller's own membership for the tenant it is about to modify and asks for the role column specifically, then performs the write without ever comparing that role to anything. Selecting a value and discarding it is what a forgotten check looks like: the query exists because someone intended to authorize the request. ${gate}`;
  }
  void privilegedByPath;
  const shape =
    endpoint.kind === "dispatch"
      ? "The endpoint is a branch of a hand-rolled dispatcher, so there is no middleware layer that could be holding the check on its behalf: whatever guards it has to be in the branch, and there is none."
      : "";
  return `${endpoint.label} sits on a path whose name reserves it for operators, and it answers with state rather than a constant, but no comparison of the caller's role, permission, or ownership appears in the handler or its middleware. ${gate}${shape ? ` ${shape}` : ""}`;
}

function evidenceFor(
  context: RuleContext,
  endpoint: Endpoint,
  write: PrivilegedWrite | null,
  unusedRole: UncomparedRole | null
) {
  const evidence = [];
  if (write) {
    evidence.push(
      sourceEvidence(context, write.node, `The update writes ${write.columns.join(", ")}, which is an authorization decision rather than ordinary content.`)
    );
  }
  if (unusedRole) {
    evidence.push(
      sourceEvidence(context, unusedRole.node, "The caller's own role is selected here and never compared with anything afterwards.")
    );
  }
  evidence.push(
    sourceEvidence(
      context,
      endpoint.anchor,
      `Neither ${endpoint.label} nor its middleware, route options, or procedure chain contains a role comparison, a permission membership test, or an authorization helper call.`
    )
  );
  return evidence;
}

/* --------------------------------------------------------------------- rule: CSRF */

export const missingCsrfProtection: Rule = {
  id: "missing-csrf-protection",
  category: "missing_csrf_protection",
  describes: "a hand-rolled cookie-authenticated state change with no origin check and no token",
  run(context: RuleContext) {
    // A framework's own server actions are not exposed this way, so a module of
    // them is never this finding.
    if (moduleDirective(context.file, "use server")) return;

    const crossSite = crossSiteCookie(context);
    if (!crossSite) return;

    for (const endpoint of collectEndpoints(context)) {
      if (endpoint.kind === "trpc" || endpoint.kind === "server-action" || endpoint.kind === "graphql") continue;
      if (!endpoint.stateChanging) continue;
      if (unauthenticatedByDesign(endpoint.label)) continue;
      if (!authenticatedByCookie(context, endpoint)) continue;
      // A sign-out endpoint's only state change is destroying the caller's own
      // session. Forcing that cross-site is a nuisance, not this defect, and the
      // remediation below would not be the right advice for it.
      if (tearsDownSession(context, endpoint)) continue;
      if (writesIn(context, endpoint.body).length === 0 && !dispatchesWrite(context, endpoint)) continue;
      if (checksOrigin(context, endpoint) || comparesSynchroniserToken(context, endpoint)) continue;

      const formEncoded = readsFormEncodedBody(context, endpoint);
      const route = endpoint.route ?? attributeRoute(context, endpoint.anchor);
      // The defect lives where the cookie is trusted, not at the function's
      // signature: that is the line a reader has to change.
      const anchor = cookieTrustPoint(context, endpoint) ?? endpoint.anchor;

      context.report({
        ruleId: "missing-csrf-protection",
        category: "missing_csrf_protection",
        title: `${endpoint.label} changes state on the strength of a cookie with no origin check and no synchroniser token`,
        severity: formEncoded ? "high" : "medium",
        verification: "needs_review",
        summary: `${endpoint.label} authenticates by reading a session cookie and then mutates state. This module also issues that cookie with ${crossSite.description}, which is what removes the browser's own cross-site protection: the cookie is attached to requests a third-party page makes. Nothing in the handler compares the Origin or Referer header against an expected value, and nothing compares a token in the request against one bound to the session.${
          formEncoded
            ? " The body is read as form data, so a plain HTML form on an unrelated page can submit it without a preflight the browser would block."
            : ""
        } A framework's own server actions do not have this exposure — Next.js accepts an action only as a POST carrying its own action id and rejects the request when the Origin header does not match the Host, before any handler code runs — so this finding is about the hand-rolled endpoint beside them, not about the actions.`,
        impact:
          "A page the victim visits while signed in can drive this endpoint in their browser with their session attached. Every operation the endpoint dispatches — renaming a tenant, removing a member, rotating a credential — becomes something an unrelated site can trigger on the victim's behalf.",
        remediation:
          "Reject the request unless the Origin header (falling back to Referer) is one of the application's own origins, and additionally require a synchroniser token: set a random value in a cookie, require the same value in a header or field, and compare the two with a constant-time comparison. If the cookie does not actually need to travel cross-site, set SameSite=Lax instead and the browser will refuse the cross-site submission on its own.",
        verificationPlan: `From an origin the application does not own, submit a form that posts to ${endpoint.label} with credentials included and a valid session cookie present. The response must be 403 and no state must change. Then repeat from the application's own origin and confirm the operation still succeeds.`,
        taxonomy: ["CWE-352", "OWASP-A01"],
        location: locationOf(context, anchor),
        ...(route ? { route } : {}),
        evidence: [
          sourceEvidence(context, crossSite.node, `The session cookie is issued with ${crossSite.description}, so the browser attaches it to cross-site requests.`),
          sourceEvidence(context, anchor, `${endpoint.label} resolves the session from that cookie and dispatches a state change with no origin check and no token comparison.`)
        ],
        reasoning: `${endpoint.label} is a ${endpoint.label.split(" ")[0]} handler that reads a cookie to authenticate and performs a write; the module sets the session cookie with ${crossSite.description}; no Origin, Referer, or Sec-Fetch-Site read and no double-submit or synchroniser token comparison appears in the handler.`
      });
    }
  }
};

interface CrossSiteCookie {
  node: ts.Node;
  description: string;
}

/**
 * Evidence that the session cookie is not protected by SameSite.
 *
 * Without this, a cookie-authenticated POST is not actually forgeable from another
 * site: every current browser defaults cookies to SameSite=Lax and refuses to
 * attach them to a cross-site form submission. Requiring the evidence is what
 * keeps this rule off the many correct endpoints that have no token because they
 * do not need one.
 */
function crossSiteCookie(context: RuleContext): CrossSiteCookie | null {
  for (const property of collect(context.file.source, ts.isPropertyAssignment)) {
    const key = propertyKeyOf(property, context.file);
    if (!key || normalizeKey(key) !== "samesite") continue;
    // `sameSite: "none" as const` is the same declaration with a type assertion on
    // it, so the value is read past the assertion rather than off the raw text.
    let value: ts.Node = property.initializer;
    while (ts.isAsExpression(value) || ts.isParenthesizedExpression(value) || ts.isNonNullExpression(value)) {
      value = value.expression;
    }
    const text = literalTextOf(value) ?? value.getText(context.file.source);
    if (/^["']?none["']?$/i.test(text.trim()) || value.kind === ts.SyntaxKind.FalseKeyword) {
      return { node: property, description: '`sameSite: "none"`' };
    }
  }
  for (const literal of collect(context.file.source, ts.isStringLiteralLike)) {
    if (/set-cookie|samesite/i.test(literal.text) && /samesite\s*=\s*none/i.test(literal.text)) {
      return { node: literal, description: "`SameSite=None` in its Set-Cookie header" };
    }
  }
  for (const template of collect(context.file.source, ts.isTemplateExpression)) {
    const text = template.getText(context.file.source);
    if (/samesite\s*=\s*none/i.test(text)) {
      return { node: template, description: "`SameSite=None` in its Set-Cookie header" };
    }
  }
  return null;
}

/** Does this handler exist to end the caller's session? */
function tearsDownSession(context: RuleContext, endpoint: Endpoint): boolean {
  const text = endpoint.body.getText(context.file.source);
  return /clearCookie|cookies\s*\(\s*\)\s*\.\s*delete|\.cookies\s*\.\s*delete|destroySession|revokeSession|signOut|logOut/i.test(text);
}

/** The call that turns a cookie into a trusted identity. */
function cookieTrustPoint(context: RuleContext, endpoint: Endpoint): ts.Node | null {
  for (const call of collect(endpoint.body, ts.isCallExpression)) {
    if (!isIdentityCall(calleeName(call))) continue;
    if (!/cookie/i.test(call.getText(context.file.source))) continue;
    return call;
  }
  return null;
}

function authenticatedByCookie(context: RuleContext, endpoint: Endpoint): boolean {
  const text = endpoint.body.getText(context.file.source);
  if (!/cookie/i.test(text)) return false;
  return resolvesIdentity(context, endpoint.body);
}

/** The handler delegates the write to a table of procedures declared in this module. */
function dispatchesWrite(context: RuleContext, endpoint: Endpoint): boolean {
  let found = false;
  const visited = new Set<string>();
  walk(endpoint.body, (node) => {
    if (found || !ts.isCallExpression(node)) return;
    const name = calleeName(node);
    const local = moduleFunctionBody(context, name, visited);
    if (local && writesIn(context, local).length > 0) {
      found = true;
      return;
    }
    // `const handler = PROCEDURES[procedure]; await handler(session, form)`
    if (ts.isIdentifier(node.expression)) {
      for (const declaration of collect(context.file.source, ts.isVariableDeclaration)) {
        if (!ts.isIdentifier(declaration.name) || declaration.name.text !== node.expression.getText(context.file.source)) continue;
        if (!declaration.initializer) continue;
        for (const inner of collect(declaration.initializer, ts.isIdentifier)) {
          const body = moduleFunctionBody(context, inner.text, new Set());
          if (body && writesIn(context, body).length > 0) found = true;
        }
      }
      // Or the table itself is a module constant of named handlers.
      for (const object of collect(context.file.source, ts.isObjectLiteralExpression)) {
        for (const property of object.properties) {
          if (!ts.isPropertyAssignment(property) || !ts.isIdentifier(property.initializer)) continue;
          const body = moduleFunctionBody(context, property.initializer.text, new Set());
          if (body && writesIn(context, body).length > 0) found = true;
        }
      }
    }
  });
  return found;
}

function checksOrigin(context: RuleContext, endpoint: Endpoint): boolean {
  const text = endpoint.body.getText(context.file.source);
  return /\borigin\b|\breferer\b|\breferrer\b|sec-fetch-site/i.test(text);
}

function comparesSynchroniserToken(context: RuleContext, endpoint: Endpoint): boolean {
  const text = endpoint.body.getText(context.file.source);
  if (/csrf|xsrf|synchroni[sz]er|double.?submit|anti.?forgery/i.test(text)) return true;
  // A token compared between a header and a cookie is a double submit under any name.
  const headerReads = findAll(endpoint.body, (node) => ts.isCallExpression(node) && /headers\.get|get\(["'][^"']*token/i.test(node.getText(context.file.source)));
  return headerReads.length > 0 && /timingSafeEqual|===/.test(text) && /cookie/i.test(text) && /token/i.test(text);
}

function readsFormEncodedBody(context: RuleContext, endpoint: Endpoint): boolean {
  const text = endpoint.body.getText(context.file.source);
  return /formData\s*\(|urlencoded|x-www-form-urlencoded|new URLSearchParams/i.test(text);
}

/* ----------------------------------------------------------- rule: logs and secrets */

const LOGGER_RECEIVER = /(^|\.)(console|logger|log|pino|winston|bunyan|fastify|request|req|ctx|this|app)(\.|$)/i;
const LOGGER_METHODS = new Set(["log", "info", "warn", "error", "debug", "trace", "fatal", "verbose", "silly"]);

export const sensitiveDataInLogs: Rule = {
  id: "sensitive-data-in-logs",
  category: "sensitive_data_in_logs",
  describes: "a request body, a whole subject record, or a named credential written to a log",
  run(context: RuleContext) {
    // The module scope walks function bodies as well, so the same logger call is
    // visited more than once. One finding per line, whatever scope saw it first.
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);

      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        if (!LOGGER_METHODS.has(tail)) continue;
        if (reported.has(lineOf(context.file, call))) continue;
        const callee = calleeName(call);
        if (!LOGGER_RECEIVER.test(callee.slice(0, callee.lastIndexOf(".") + 1)) && !/log/i.test(callee)) continue;

        const exposure = loggedExposure(context, fn, call, scope);
        if (!exposure) continue;
        reported.add(lineOf(context.file, call));

        const credentials = credentialFieldsInModule(context);
        const named = exposure.kind === "credential";

        context.report({
          ruleId: "sensitive-data-in-logs",
          category: "sensitive_data_in_logs",
          title: named
            ? `A credential field is written to the log by ${callee}()`
            : `${exposure.what} is written to the log by ${callee}()`,
          severity: named || credentials.length > 0 ? "high" : "medium",
          verification: "strong_evidence",
          summary: `${callee}() is called with ${exposure.description}. A log line is not a scratch buffer: it is written to disk, shipped to whatever aggregator the deployment uses, and retained under that system's policy rather than this application's.${
            credentials.length > 0 && !named
              ? ` This module's own request schema declares ${credentials.map((field) => `\`${field}\``).join(", ")}, so those values are inside the object being logged.`
              : ""
          }`,
          impact:
            "Everyone with log access — operators, the log vendor, anyone who later obtains a backup — holds the values that were logged. For a credential or a payment instrument that is a disclosure in its own right, and it usually reaches further than the database it was trying to stay out of.",
          remediation:
            "Log the identifiers you need to correlate the request and nothing else: a request or correlation id, the subject's id, and named non-sensitive fields. Never pass a whole request body or a whole subject record to a logger; if a value must be recognisable in a log, store a truncation or a digest of it rather than the value.",
          verificationPlan:
            "Exercise this endpoint with a recognisable marker in the sensitive field, then grep the application log and the aggregator for that marker. Neither should contain it.",
          taxonomy: ["CWE-532", "CWE-359", "OWASP-A09"],
          location: locationOf(context, exposure.node),
          ...(attributeRoute(context, call) ? { route: attributeRoute(context, call)! } : {}),
          evidence: [sourceEvidence(context, exposure.node, `${exposure.description} is passed to the logger.`)],
          reasoning: `A call to ${callee}() receives ${exposure.description}; the value is neither truncated, hashed, nor reduced to named non-sensitive fields.`
        });
      }
    }
  }
};

interface LoggedExposure {
  node: ts.Node;
  kind: "whole-input" | "whole-subject" | "credential";
  what: string;
  description: string;
}

function loggedExposure(
  context: RuleContext,
  fn: ts.Node,
  call: ts.CallExpression,
  scope: TaintScope
): LoggedExposure | null {
  const file = context.file;
  const candidates: ts.Node[] = [];
  for (const argument of call.arguments) {
    candidates.push(argument);
    if (ts.isObjectLiteralExpression(argument)) {
      for (const property of argument.properties) {
        if (ts.isPropertyAssignment(property)) candidates.push(property);
        if (ts.isShorthandPropertyAssignment(property)) candidates.push(property);
        if (ts.isSpreadAssignment(property)) candidates.push(property);
      }
    }
  }

  for (const candidate of candidates) {
    const value = ts.isPropertyAssignment(candidate)
      ? candidate.initializer
      : ts.isSpreadAssignment(candidate)
        ? candidate.expression
        : candidate;
    const key = ts.isPropertyAssignment(candidate) || ts.isShorthandPropertyAssignment(candidate)
      ? propertyKeyOf(candidate, file)
      : null;

    // A named credential, unless the value has been reduced to something harmless.
    const nameToTest = key ?? (ts.isIdentifier(value) ? value.text : lastSegment(value, file));
    if (nameToTest && CREDENTIAL_FIELDS.has(normalizeKey(nameToTest)) && !isReduced(value, file)) {
      return {
        node: candidate,
        kind: "credential",
        what: `\`${nameToTest}\``,
        description: `the value of \`${nameToTest}\`, a field whose name says it is a credential`
      };
    }

    if (isReduced(value, file)) continue;

    // The caller's whole submission.
    const wholeInput = wholeObjectName(value, file, WHOLE_INPUT_PROPERTIES);
    if (wholeInput && callerObjectOrigin(context, fn, value, scope)) {
      return {
        node: candidate,
        kind: "whole-input",
        what: `The whole request ${wholeInput}`,
        description: `the entire request ${wholeInput} object, whose fields are whatever the caller submitted`
      };
    }

    // A whole subject record rather than the identifier from it.
    const wholeSubject = wholeObjectName(value, file, WHOLE_SUBJECT_PROPERTIES);
    if (wholeSubject) {
      return {
        node: candidate,
        kind: "whole-subject",
        what: `The whole ${wholeSubject} record`,
        description: `the entire \`${wholeSubject}\` object rather than the identifier from it`
      };
    }
  }
  return null;
}

/** The last dotted segment of an expression, for naming what was logged. */
function lastSegment(node: ts.Node, file: ParsedFile): string | null {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isIdentifier(node)) return node.text;
  void file;
  return null;
}

/**
 * Is the logged expression a whole object of the named kind, rather than a field
 * read out of one? `request.body` is; `request.body.country` is not.
 */
function wholeObjectName(node: ts.Node, file: ParsedFile, names: Set<string>): string | null {
  let target = node;
  if (ts.isCallExpression(target) && ["stringify", "inspect", "format"].includes(calleeTail(target))) {
    target = target.arguments[0] ?? target;
  }
  if (ts.isSpreadElement(target)) target = target.expression;
  if (ts.isIdentifier(target)) return names.has(normalizeKey(target.text)) ? target.text : null;
  if (ts.isPropertyAccessExpression(target)) {
    return names.has(normalizeKey(target.name.text)) ? expressionName(target) : null;
  }
  void file;
  return null;
}

/** Has the value already been truncated, hashed, or masked? */
function isReduced(node: ts.Node, file: ParsedFile): boolean {
  const text = node.getText(file.source);
  if (/\.slice\s*\(|\.substring\s*\(|\.at\s*\(|last4|Last4|mask|redact|hash|digest|fingerprint|\.length\b|Object\.keys|Object\.getOwnPropertyNames/.test(text)) {
    return true;
  }
  // `count`, `size`, and boolean presence checks reveal nothing.
  return /^Boolean\(|^!!/.test(text);
}

/** Credential-shaped field names declared anywhere in this module. */
function credentialFieldsInModule(context: RuleContext): string[] {
  const found = new Set<string>();
  for (const property of collect(context.file.source, ts.isPropertyAssignment)) {
    const key = propertyKeyOf(property, context.file);
    if (key && CREDENTIAL_FIELDS.has(normalizeKey(key))) found.add(key);
  }
  for (const literal of collect(context.file.source, ts.isStringLiteralLike)) {
    if (CREDENTIAL_FIELDS.has(normalizeKey(literal.text))) found.add(literal.text);
  }
  return [...found].slice(0, 4);
}

/* ---------------------------------------------------- rule: secret in client bundle */

/** Prefixes that a bundler treats as "safe to inline into the browser". */
const PUBLIC_ENV_PREFIX = /^(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_|VUE_APP_|STORYBOOK_)/;

/** Names that say the value is a server credential. */
const SECRET_ENV_NAME = /(SECRET|PRIVATE|PASSWORD|PASSWD|CREDENTIAL|SERVICE_KEY|SERVICE_ROLE|API_KEY|APIKEY|ACCESS_KEY|SIGNING|WEBHOOK_SECRET|SALT|SESSION_KEY|ENCRYPTION|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|CLIENT_SECRET|_PAT$|_DSN$)/;

/** Names that are credentials only in appearance: these are meant to be public. */
const PUBLISHABLE_ENV_NAME = /(PUBLISHABLE|ANON_KEY|SITE_KEY|PUBLIC_KEY|CLIENT_ID|MEASUREMENT_ID|VAPID_PUBLIC|_URL$|_ENDPOINT$|_HOST$|_DOMAIN$|_REGION$|_BUCKET$|_ID$)/;

export const clientBundleSecret: Rule = {
  id: "secret-exposed-to-client-bundle",
  category: "secret_exposed_to_client_bundle",
  describes: "a server credential read from an environment variable that reaches the browser bundle",
  run(context: RuleContext) {
    const isClientModule = moduleDirective(context.file, "use client");

    for (const access of collect(context.file.source, ts.isPropertyAccessExpression)) {
      const name = access.name.text;
      const base = expressionName(access.expression);
      if (!/^(process\.env|import\.meta\.env)$/.test(base)) continue;

      const publicPrefix = PUBLIC_ENV_PREFIX.exec(name)?.[0] ?? null;
      const bare = publicPrefix ? name.slice(publicPrefix.length) : name;
      const looksSecret = SECRET_ENV_NAME.test(bare) && !PUBLISHABLE_ENV_NAME.test(bare);
      if (!looksSecret) continue;
      // A server-only variable read in a server module is the correct pattern.
      if (!publicPrefix && !isClientModule) continue;

      const bundled = publicPrefix !== null;
      const severity = bundled && isClientModule ? "critical" : "high";

      context.report({
        ruleId: "secret-exposed-to-client-bundle",
        category: "secret_exposed_to_client_bundle",
        title: bundled
          ? `Server credential \`${name}\` is exposed to the browser by its \`${publicPrefix}\` prefix`
          : `Server credential \`${name}\` is read inside a client module`,
        severity,
        verification: bundled ? "strong_evidence" : "needs_review",
        summary: bundled
          ? `\`${name}\` carries the \`${publicPrefix}\` prefix, which instructs the bundler to replace this read with the literal value at build time and ship it in the JavaScript served to every visitor. The rest of the name — \`${bare}\` — says the value is a server credential rather than a public identifier${isClientModule ? ", and it is read inside a module marked \"use client\", so it is definitely in a browser chunk" : ""}. Anyone who opens the page's sources has it.`
          : `\`${name}\` has no public prefix but is read inside a module marked "use client". Depending on how the bundler is configured — a webpack \`DefinePlugin\` over the whole environment, or a plugin that inlines \`process.env\` wholesale — that read is either replaced with the literal value and shipped to the browser or is simply undefined at runtime. Both outcomes are defects, and which one applies has to be settled against the build.`,
        impact:
          "The credential is public. Whatever it authorises — writing to a data warehouse, sending mail, calling a payment or storage API — can be done directly by anyone who reads the page, without going through this application or its rate limits, and the usage is billed to the account that owns the key.",
        remediation: `Move the call that needs this credential to the server: a route handler, a server action, or a server component that the client calls instead. Where the browser genuinely has to talk to the third party, have the server mint a short-lived, narrowly scoped token for that one operation and pass the token down. Then remove the \`${publicPrefix ?? ""}\`-prefixed variable from every environment, and rotate the credential, because publication is not reversible.`,
        verificationPlan: `Build the application and search the generated client chunks for the credential's value; it must not appear. Then confirm the previous value has been rotated at the provider, since anything already served is out of your control.`,
        taxonomy: ["CWE-200", "CWE-522", "OWASP-A02", "OWASP-A05"],
        location: locationOf(context, access),
        evidence: [
          sourceEvidence(
            context,
            access,
            bundled
              ? `\`${name}\` is a build-time inlined variable whose name identifies it as a credential.`
              : `\`${name}\` is read in a module marked "use client".`
          )
        ],
        reasoning: bundled
          ? `The variable name begins with \`${publicPrefix}\`, which the bundler inlines into client output, and the remainder matches a credential naming pattern without matching any of the conventionally public ones${isClientModule ? "; the module is also marked \"use client\"" : ""}.`
          : `The module carries a "use client" directive and reads \`process.env.${name}\`, whose name matches a credential naming pattern.`
      });
    }
  }
};
