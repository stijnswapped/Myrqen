import ts from "typescript";
import { calleeName, calleeTail, collect, expressionName, findAll, literalTextOf, walk } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, resolveExpression, taintOrigin, type TaintScope } from "../ast/taint.js";
import { entryPointsOf, functionOf } from "../ast/entrypoints.js";
import { lineOf, type ParsedFile } from "../ast/parse.js";
import { routeFromFilePath } from "../ast/routes.js";
import { formatRoute, locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";
import { storeMembers } from "./records-origin.js";
import { registrationGate } from "../engine/handlers.js";

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
 * Guards whose decision is read from metadata a *separate* decorator supplies.
 *
 * `@UseGuards(RolesGuard)` on its own permits everything: at request time the
 * guard asks the reflector which roles the handler requires, finds that nobody
 * declared any, and lets the call through. Counting the guard registration as the
 * authorization check is therefore the exact mistake the framework invites, and
 * it would excuse every method that forgot the `@Roles(...)` beside it.
 */
const METADATA_DRIVEN_GUARD_TOKENS = new Set([
  "role", "roles", "permission", "permissions", "scope", "scopes", "rbac", "acl", "ability", "abilities",
  "policy", "policies", "casl", "entitlement", "entitlements", "claims", "grants"
]);

/** Privileges named concretely enough that a guard called after one decides alone. */
const CONCRETE_PRIVILEGE_TOKENS = new Set([
  "admin", "admins", "administrator", "superadmin", "superuser", "owner", "owners", "staff", "root",
  "operator", "maintainer", "moderator"
]);

/** Decorators that register a guard: what the guard requires is declared elsewhere. */
const GUARD_REGISTRATION_DECORATORS = new Set([
  "useguards", "guards", "usefilters", "usepipes", "useinterceptors", "authorized", "secured"
]);

/**
 * Decorators that declare an address, a status, or a view rather than a privilege.
 *
 * Their arguments are paths and template names, and a path segment is very often
 * a privileged-sounding word: `@Get("roles")` lists the roles a tenant offers and
 * authorizes nothing. Reading the privilege vocabulary out of a route decorator
 * would silently mark those handlers as guarded.
 */
const ADDRESS_DECORATORS = new Set([
  "controller", "jsoncontroller", "get", "post", "put", "patch", "delete", "options", "head", "all", "sse",
  "route", "httpcode", "header", "redirect", "render", "apitags", "apioperation", "apiresponse"
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

/**
 * Columns whose value records a sign-off: that one happened, who gave it, and when.
 *
 * An approval is not ordinary content. It is the moment an application decides a
 * request may proceed, and these columns are the record of that decision, which
 * makes writing one an authorization decision in exactly the sense
 * `PRIVILEGED_COLUMNS` means. They are kept as a separate list because the check
 * that excuses them is a wider one: a role write is only ever excused by a role
 * comparison, while an approval is also legitimately something a subject performs
 * on their own row — consenting to a grant, accepting a transfer addressed to them
 * — so the trigger built on this list has silencers the role trigger must not have.
 */
const APPROVAL_COLUMNS = new Set([
  "approved", "isapproved", "approvedby", "approvedbyid", "approveduserid", "approvedat", "approvedon",
  "approvaldate", "approvalstatus", "approvalstate", "approver", "approverid", "signedoff", "signedoffby",
  "signedoffbyid", "signedoffat", "signoff", "signoffby", "signoffbyid", "signoffat", "signoffstatus",
  "authorizedby", "authorisedby", "authorizedbyid", "authorisedbyid", "authorizedat", "authorisedat",
  "countersignedby", "countersignedbyid", "countersignedat", "ratifiedby", "ratifiedat"
]);

/**
 * Columns that carry a workflow's decision as a word rather than as a timestamp.
 *
 * A sign-off is very often written as nothing but `status: "approved"`, with no
 * column whose *name* mentions approval anywhere in the statement. Reading the
 * literal is the only way to see it, and the literal has to be read: `status` on
 * its own is the most generic column name in any schema and claiming every write
 * of one would report every state machine in the application.
 */
const WORKFLOW_STATUS_COLUMNS = new Set([
  "status", "state", "approvalstatus", "approvalstate", "workflowstatus", "workflowstate", "stage",
  "decision", "outcome", "reviewstatus", "reviewstate"
]);

/** The values a workflow column is driven to once the decision has been granted. */
const APPROVED_STATE = /^(approved?|authori[sz]ed|signed[_ -]?off|signoff|countersigned|ratified|granted)$/i;

/**
 * Columns that name the person a row is *about*, as opposed to the tenant it
 * belongs to.
 *
 * Deliberately excludes tenant, workspace, organisation and team: comparing the
 * caller's tenant against the row's tenant is a membership test, and the whole
 * reason a sign-off rule is worth having is that membership is routinely mistaken
 * for entitlement. Including those columns here would silence exactly the finding
 * this list exists to support.
 */
const RECORD_SUBJECT_COLUMN =
  /\b(user_?id|owner|owner_?id|account_?id|member_?id|submitter_?id|submitted_?by(_?id)?|requester_?id|requested_?by(_?id)?|raised_?by(_?id)?|opened_?by(_?id)?|created_?by(_?id)?|creator_?id|author_?id|assignee_?id|assigned_?to(_?id)?|target_?user_?id|recipient_?id|employee_?id|customer_?id|subject_?id|approver_?id)\b/i;

/** Verbs that make a call a refusal rather than a record of one. */
const REFUSING_VERBS = new Set([
  ...AUTHZ_VERBS, "refuse", "reject", "prevent", "prohibit", "disallow", "block", "enforce"
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

/**
 * Words for the thing a machine-to-machine receiver checks instead of a session.
 *
 * A webhook has no caller to identify: the issuer signs the payload with a shared
 * secret and the receiver recomputes the signature. That check is the receiver's
 * whole authentication, so a model that only looks for sessions and tokens reads
 * a correctly verified receiver and a completely open one as identical.
 */
const SIGNATURE_TOKENS = new Set(["signature", "signatures", "signed", "sign", "hmac", "mac", "checksum", "digest"]);

/** Verbs that turn a signature into a decision rather than a value. */
const VERIFYING_VERBS = new Set([
  "verify", "verified", "valid", "validate", "validated", "check", "checked", "is", "assert", "ensure",
  "require", "compare", "matches", "match", "equals", "expect"
]);

/** Calls that are a signature comparison whatever the surrounding names are. */
const SIGNATURE_CALLS = new Set([
  "timingsafeequal", "createhmac", "constructevent", "verifyheader", "verifyandparse", "verifywebhook",
  "verifysignature", "verifyevent", "verifypayload", "verifyrequestsignature"
]);

/** Labels for endpoints an outside system calls rather than a person. */
const WEBHOOK_TOKENS = new Set(["webhook", "webhooks", "hook", "hooks"]);

/** HTTP verbs that change state. */
const STATE_CHANGING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Does anything in this node prove the request was signed by the issuer?
 *
 * One hop into a module-local helper is followed for the same reason
 * `resolvesIdentity` follows one: the verification is almost always factored out
 * — `if (!(await signatureIsValid(secret, raw, header))) return 401` — and a check
 * that stopped at the call site would read every correct receiver as unverified.
 */
/**
 * A signature check the caller can opt out of is not a signature check.
 *
 *     const signature = req.header('x-carrier-signature');
 *     const secret = SIGNING_SECRETS[carrierCode];
 *     if (signature && secret) {
 *       …recompute the HMAC, 401 on mismatch…
 *     }
 *     // and then the handler carries on regardless
 *
 * Omit the header and the whole block is skipped; name a carrier with no configured
 * secret and it is skipped too. The verification is real, correct, and constant-time —
 * and it runs only when the sender chooses to be checked, which makes the endpoint
 * unauthenticated to anyone who declines.
 *
 * Recognised as: the verification sits inside an `if` whose condition is a **truthiness
 * test** — no comparison, no negation of a verification result — over identifiers, at
 * least one of them the presented signature, and that `if` has no `else`. The correct
 * shapes do not match it: `if (!signature) return 401;` rejects before verifying and is a
 * negation, and `if (!valid(signature, body)) return 401;` is not a presence test.
 *
 * Nothing is reported from here. The judgement narrowed is "this handler authenticates by
 * signature", so a receiver that only checks conditionally falls back to being an
 * unauthenticated handler, which is what it is.
 */
function verificationIsOptional(scope: ts.Node, call: ts.Node): boolean {
  for (let node: ts.Node | undefined = call; node && node !== scope; node = node.parent) {
    const parent: ts.Node | undefined = node.parent;
    if (!parent || !ts.isIfStatement(parent) || parent.thenStatement !== node) continue;
    if (parent.elseStatement) continue;

    // A truthiness test: identifiers and `&&`, nothing that compares or negates.
    let onlyPresence = true;
    let mentionsSignature = false;
    walk(parent.expression, (inner) => {
      if (ts.isBinaryExpression(inner) && inner.operatorToken.kind !== ts.SyntaxKind.AmpersandAmpersandToken) {
        onlyPresence = false;
      }
      if (ts.isPrefixUnaryExpression(inner) && inner.operator === ts.SyntaxKind.ExclamationToken) onlyPresence = false;
      if (ts.isCallExpression(inner)) onlyPresence = false;
      if (ts.isIdentifier(inner) && tokensOf(inner.text).some((token) => SIGNATURE_TOKENS.has(token))) {
        mentionsSignature = true;
      }
    });
    if (onlyPresence && mentionsSignature) return true;
  }
  return false;
}

function verifiesSignature(context: RuleContext, node: ts.Node, visited = new Set<string>()): boolean {
  let found = false;
  walk(node, (inner) => {
    if (found || !ts.isCallExpression(inner)) return;
    // A check the sender can skip by omitting the header does not authenticate anything.
    if (verificationIsOptional(node, inner)) return;
    const name = calleeName(inner);
    const normalized = normalizeKey(calleeTail(inner));
    if (SIGNATURE_CALLS.has(normalized) || SIGNATURE_CALLS.has(normalizeKey(name))) {
      found = true;
      return;
    }
    const tokens = tokensOf(name);
    // `signatureIsValid(...)`, `verifyHmac(...)`, `checkSignature(...)`: a
    // signature word and a verb that decides something about it.
    if (tokens.some((token) => SIGNATURE_TOKENS.has(token)) && tokens.some((token) => VERIFYING_VERBS.has(token))) {
      found = true;
      return;
    }
    // WebCrypto spells it `crypto.subtle.verify(...)`, with the algorithm named in
    // the first argument rather than in the callee.
    if (normalized === "verify") {
      const argumentText = inner.arguments.map((argument) => literalTextOf(argument) ?? "").join(" ");
      if (/hmac|sha\d|ed25519|rsa|ecdsa/i.test(argumentText) || /crypto|subtle|webhook|svix|stripe/i.test(name)) {
        found = true;
        return;
      }
    }
    const local = moduleFunctionBody(context, name, visited);
    if (local && verifiesSignature(context, local, visited)) found = true;
  });
  return found;
}

/**
 * Is this endpoint addressed by another system rather than by a person?
 *
 * The handler's own name is the weakest of the three places that say so, and it was
 * the only one being read: `carrierStatusCallback` tokenizes to carrier/status/callback
 * and matched nothing, so a receiver mounted at `POST /api/webhooks/carrier-status`,
 * in a file called `src/webhooks/carrier-status.ts`, did not read as a webhook at all.
 * The route and the module path are stated by the application rather than chosen as a
 * variable name, which makes them the better evidence of the two.
 */
function isWebhookEndpoint(context: RuleContext, endpoint: Endpoint): boolean {
  if (tokensOf(endpoint.label).some((token) => WEBHOOK_TOKENS.has(token))) return true;
  const route = endpoint.route ?? attributeRoute(context, endpoint.anchor);
  if (route && tokensOf(route).some((token) => WEBHOOK_TOKENS.has(token))) return true;
  return tokensOf(context.file.relativePath).some((token) => WEBHOOK_TOKENS.has(token));
}

/**
 * A webhook receiver that writes, in a module whose other receivers verify theirs.
 *
 * A webhook is unauthenticated by design in the only sense the by-design list
 * means: no session reaches it, so demanding one would be wrong. It is emphatically
 * not open by design — the issuer signs the payload precisely so the receiver can
 * refuse everyone else — and a receiver that skips the check accepts an event body
 * from whoever discovers the URL. The contrast is the same one this rule relies on
 * everywhere else: a sibling receiver in the same module performs the check, with
 * the helper and the secret already in scope, so the omission here is an omission.
 */
function unverifiedWebhook(
  context: RuleContext,
  endpoint: Endpoint,
  siblings: readonly Endpoint[]
): { contrast: Endpoint[] } | null {
  if (!isWebhookEndpoint(context, endpoint)) return null;
  if (verifiesSignature(context, endpoint.body)) return null;
  if (writesIn(context, endpoint.body).length === 0) return null;
  // A verifying sibling makes the omission demonstrable rather than merely likely, so
  // it decides how confidently the finding is stated — it no longer decides whether
  // there is one. Requiring it meant a file holding a single unverified receiver, which
  // is how webhook modules are usually laid out, produced nothing.
  return {
    contrast: siblings.filter(
      (sibling) =>
        sibling !== endpoint && isWebhookEndpoint(context, sibling) && verifiesSignature(context, sibling.body)
    ),
  };
}

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

      // `RANK[requester.role] <= RANK[target.role]`, `actor.tier < required.tier`.
      //
      // Ranked roles are compared with `<`, not with `===`: the question is not
      // which role the caller holds but whether it outranks the row being changed.
      // Both sides have to speak about a role for this to count. `viewer.roles.length
      // > 0` is also a relational comparison against a role expression, and it
      // decides nothing about whether the caller may perform *this* operation, so
      // accepting it would excuse a role change guarded by no more than "the caller
      // has some role".
      const isRanking =
        kind === ts.SyntaxKind.LessThanToken ||
        kind === ts.SyntaxKind.LessThanEqualsToken ||
        kind === ts.SyntaxKind.GreaterThanToken ||
        kind === ts.SyntaxKind.GreaterThanEqualsToken;
      if (isRanking) {
        const subjectSide = [inner.left, inner.right].some((side) => isSubjectRoleExpression(context, side, node));
        const bothSpeakOfRoles = [inner.left, inner.right].every((side) =>
          isRoleExpression(side.getText(file.source))
        );
        if (subjectSide && bothSpeakOfRoles) {
          hit = inner;
          return;
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

/* ------------------------------------------------------- authorization by decorator */

function decoratorsOf(node: ts.Node): readonly ts.Decorator[] {
  return (ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined) ?? [];
}

/** `@Roles(...)` and `@common.Roles(...)` are the same decorator under a namespace import. */
function decoratorName(decorator: ts.Decorator): string {
  const expression = ts.isCallExpression(decorator.expression) ? decorator.expression.expression : decorator.expression;
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return "";
}

function decoratorArguments(decorator: ts.Decorator): readonly ts.Expression[] {
  return ts.isCallExpression(decorator.expression) ? decorator.expression.arguments : [];
}

/**
 * A decorator that states which role or permission this handler requires.
 *
 * For a decorator-routed framework the authorization decision is not written in
 * the handler at all: `@Roles("admin")`, `@Permissions("billing:write")` and
 * `@SetMetadata("roles", [...])` are the check, and the guard that reads them is
 * generic. A rule that only looks inside the body therefore sees every correctly
 * guarded controller method as unguarded.
 *
 * The distinction that has to hold is between declaring a requirement and
 * registering the machinery that would enforce one. `@UseGuards(RolesGuard)` is
 * inert on its own — the guard finds no required roles and admits everyone — so
 * it is not a check, while `@UseGuards(AdminGuard)` names the privilege it
 * enforces and needs no metadata beside it. Treating the two alike in either
 * direction is a defect: one way excuses every method that forgot its `@Roles`,
 * the other reports every method that is genuinely guarded by a specific guard.
 */
function declaredRoleRequirement(decorator: ts.Decorator): ts.Node | null {
  const name = decoratorName(decorator);
  if (name.length === 0) return null;
  const key = normalizeKey(name);
  if (ADDRESS_DECORATORS.has(key)) return null;

  const registration = GUARD_REGISTRATION_DECORATORS.has(key);
  const tokens = tokensOf(name);

  if (!registration && tokens.some((token) => ROLE_TOKENS.has(token) || CONCRETE_PRIVILEGE_TOKENS.has(token))) {
    return decorator;
  }

  for (const argument of decoratorArguments(decorator)) {
    if (registration) {
      const argumentTokens = tokensOf(expressionName(argument));
      // A guard named for the mechanism is inert until something declares what it
      // should require, so it decides nothing on its own. A guard named for the
      // privilege it enforces, or for the ownership claim it tests, needs nothing
      // beside it and is the check.
      if (argumentTokens.some((token) => METADATA_DRIVEN_GUARD_TOKENS.has(token))) continue;
      if (argumentTokens.some((token) => CONCRETE_PRIVILEGE_TOKENS.has(token))) return decorator;
      if (namesAuthorization(expressionName(argument))) return decorator;
      continue;
    }
    // `@SetMetadata("roles", ["admin"])` and `@Auth("owner")` put the privilege in
    // the argument rather than in the decorator's own name.
    for (const literal of collect(argument, ts.isStringLiteralLike)) {
      const literalKey = normalizeKey(literal.text);
      if (ROLE_TOKENS.has(literalKey) || CONCRETE_PRIVILEGE_TOKENS.has(literalKey)) return decorator;
    }
  }
  return null;
}

/** Does this decorator establish who the caller is, without saying what they may do? */
function decoratorResolvesIdentity(decorator: ts.Decorator): boolean {
  const name = decoratorName(decorator);
  if (isIdentityCall(name)) return true;
  for (const argument of decoratorArguments(decorator)) {
    const referenced = expressionName(argument);
    if (isIdentityCall(referenced) || namesAuthorization(referenced)) return true;
  }
  return false;
}

/** The authorization decision guarding an endpoint, whether written as code or as a decorator. */
function gateRoleCheck(context: RuleContext, gate: ts.Node): ts.Node | null {
  if (ts.isDecorator(gate)) return declaredRoleRequirement(gate);
  return findRoleCheck(context, gate, new Set(), true);
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

/**
 * Write methods that need a database-shaped receiver to be believable.
 *
 * `merge` and `assign` are here because of what a repository's `merge` is *for*:
 * TypeORM's `Repository.merge(entity, payload)` applies a payload to an entity that
 * is about to be saved, and the save two lines later carries no payload of its own.
 * A rule reading only the persisting call sees `save(updated)` — one identifier, no
 * caller data anywhere near it — and mass assignment becomes unreportable in the
 * framework's own idiom. Both still require a store-shaped receiver, which is what
 * keeps `lodash.merge` and a config merge out.
 */
const AMBIGUOUS_WRITES = new Set([
  "update", "create", "insert", "delete", "destroy", "remove", "save", "set", "values", "add", "put",
  "merge", "assign"
]);

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
    /*
     * A repository is usually named after what it holds, not after what it is.
     *
     * `DATABASE_RECEIVER` is a list of words that mean "data store" — `db`, `repo`,
     * `prisma`. The idiomatic TypeORM and NestJS spelling is neither: the injected
     * member is called `this.subscriptions`, `this.invoices`, `this.users`, and the
     * only thing that says "store" is its declared type. So `this.subscriptions
     * .save({ ...patch })` was not a database write as far as this rule was
     * concerned, and mass assignment was unreportable across an entire framework
     * convention.
     *
     * `storeMembers` already answers this for the ownership rules, by reading
     * declared types and injection decorators. Reusing it here rather than adding
     * entity names to a word list, because the list would need every noun.
     */
    const member = ts.isPropertyAccessExpression(call.expression)
      ? call.expression.expression
      : undefined;
    const memberName =
      member && ts.isPropertyAccessExpression(member)
        ? member.name.text
        : member && ts.isIdentifier(member)
          ? member.text
          : null;
    const declaredStore = memberName !== null && storeMembers(file).has(memberName);
    if (!declaredStore && !DATABASE_RECEIVER.test(receiver)) return null;
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
  return formatRoute(best.method, best.path);
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

type EndpointKind = "file-route" | "server-action" | "registration" | "decorator" | "trpc" | "graphql" | "dispatch";

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
  const declared = [
    ...fileRouteEndpoints(context),
    ...serverActionEndpoints(context),
    ...registrationEndpoints(context),
    ...decoratorEndpoints(context),
    ...trpcEndpoints(context),
    ...graphqlEndpoints(context)
  ];
  return [...declared, ...entryPointEndpoints(context, declared)];
}

/**
 * Endpoints the entry-point adapters recognised and no registration model can.
 *
 * A server function is the shape this exists for. `createServerFn().handler(fn)`
 * and the SolidStart and Astro equivalents are compiled into an HTTP endpoint that
 * anybody who can address it may invoke, but nothing at the declaration site says
 * so: there is no path literal, no verb, no registration call, and no `"use
 * server"` directive for the model above to key off. The whole purpose of the
 * shape is that a network call reads as a local one, and that is exactly why the
 * authorization a reviewer would demand of a route is so easy to leave out of one
 * — the handler looks like a function the application calls itself. Until the
 * adapters were read back here, every rule in this file was silent on the entire
 * surface, which is the wrong kind of quiet: the omission is invisible rather than
 * absent.
 *
 * Only `action` and `rpc` kinds are taken. A queue consumer and a command-line
 * invocation have no caller to identify, so demanding a session in one would be
 * noise, and an `ipc` channel's trust boundary differs per host — those are judged
 * where the boundary is known rather than through this generic model.
 */
function entryPointEndpoints(context: RuleContext, declared: readonly Endpoint[]): Endpoint[] {
  const out: Endpoint[] = [];
  for (const entry of entryPointsOf(context.file)) {
    /*
     * `http` joins them, now that an adapter recognises the generic shape.
     *
     * It was excluded because the registration models in this file already covered HTTP
     * for every framework that had an adapter, and a second endpoint for the same handler
     * is one finding reported twice. The dedupe below — same body, or a body spanning
     * one already declared — is what actually prevents that, and it does the job for
     * `http` exactly as it does for `action`.
     *
     * What excluding it cost was every framework the registration models do *not* cover:
     * a Medusa `export const GET`, an Azure `app.http(name, { route, handler })`, an
     * Encore `api({ path }, fn)`. Those got seeds from the adapter, so a taint-shaped
     * defect in them was found, and no endpoint, so every rule that asks "which endpoint
     * is this and does it authenticate" stayed silent. Run 7 missed four missing-
     * authentication cases with the handler, the route and the caller's data all
     * recognised.
     */
    if (entry.kind !== "action" && entry.kind !== "rpc" && entry.kind !== "http") continue;
    const fn = entry.node;
    if (!fn) continue;
    const body = (fn as ts.FunctionLikeDeclaration).body;
    if (!body) continue;
    // A `"use server"` module is reported both by an adapter and by the directive
    // model above, and one handler counted twice is one finding reported twice.
    if (declared.some((endpoint) => endpoint.body === body || spans(endpoint.body, body))) continue;
    if (out.some((endpoint) => endpoint.body === body)) continue;

    // A form action is addressed by the URL of the page that posts to it; a server
    // function is addressed by the name the client imports. Presenting the second
    // as a path would send a reader looking for a route that exists nowhere in the
    // application, so only the first gets a route.
    const addressed = entry.path.startsWith("/");

    /*
     * The gate the declaration put beside the handler.
     *
     * `[]` was a claim that nothing gates this endpoint, and for a registration written
     * as `{ preHandler: [authenticate, requireRole("manager")], handler }` that claim is
     * false: the whole point of the option is that the handler body stays clean. Reading
     * only the body reported a route gated twice as gated not at all.
     */
    const gate = entry.gate ?? [];

    out.push({
      kind: "server-action",
      label: addressed ? `${entry.method} ${entry.path}` : `server function ${entry.path}()`,
      ...(addressed ? { route: `${entry.method} ${entry.path}` } : {}),
      anchor: fn,
      body,
      gate,
      authenticated:
        gate.some((scope) => resolvesIdentity(context, scope, new Set(), true)) || resolvesIdentity(context, body),
      stateChanging: STATE_CHANGING.has(entry.method)
    });
  }
  return out;
}

/**
 * Endpoints published by decorator rather than by a registration call.
 *
 * NestJS and the frameworks that copied its shape join a class decorator to a
 * method decorator and let the framework do the wiring at runtime, so there is no
 * `app.patch("/x", handler)` anywhere in the file for the registration model to
 * recognise. Every rule in this file is therefore silent on a controller — not
 * because the handlers are safe, but because as far as the endpoint model is
 * concerned they do not exist.
 *
 * The address is taken from the entry-point adapters, which already resolve the
 * class prefix and the method suffix. What the rules need on top of it is the
 * gate, and for these frameworks the gate is also written as decorators: the
 * guards on the class and the required roles on the method.
 */
function decoratorEndpoints(context: RuleContext): Endpoint[] {
  const out: Endpoint[] = [];
  const seen = new Set<string>();

  for (const entry of entryPointsOf(context.file)) {
    if (entry.kind !== "http") continue;
    const member = entry.node;
    if (!member || !ts.isMethodDeclaration(member) || !member.body) continue;

    const owner = member.parent;
    // A class-level guard applies to every method the class carries, exactly as
    // instance-level middleware applies to every route registered on it.
    const gate: ts.Node[] = [
      ...decoratorsOf(member),
      ...(owner && ts.isClassLike(owner) ? decoratorsOf(owner) : [])
    ];

    const label = formatRoute(entry.method, entry.path);
    // Stacked verb decorators give one body two addresses; the endpoint model
    // only needs one of them, and reporting both would repeat every finding.
    if (seen.has(label)) continue;
    seen.add(label);

    out.push({
      kind: "decorator",
      label,
      route: label,
      anchor: member,
      body: member.body,
      gate,
      authenticated:
        gate.some((node) => ts.isDecorator(node) && decoratorResolvesIdentity(node)) ||
        resolvesIdentity(context, member.body),
      stateChanging: STATE_CHANGING.has(entry.method)
    });
  }
  return out;
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
    // An extension worker is judged on its own terms first: the boundary there is
    // the channel rather than a sibling that authenticates, and the sibling model
    // below would read every worker as a module where nothing is authenticated and
    // therefore say nothing at all.
    reportUnauthenticatedExternalListeners(context);

    const endpoints = collectEndpoints(context);

    // Identifying the caller and verifying the issuer's signature are the same
    // claim made by two kinds of endpoint. A receiver that checks its HMAC knows
    // who sent the request just as surely as a handler that resolves a session,
    // and counting only the second reads a correctly verified webhook as open.
    const proves = (endpoint: Endpoint): boolean =>
      endpoint.authenticated || verifiesSignature(context, endpoint.body);

    /*
     * The contrast is the evidence — with one exception that had swallowed a whole class.
     *
     * A module where nothing is authenticated may be a public API, and reporting every
     * endpoint in it is noise. Likewise a module holding a single endpoint says nothing
     * about what its siblings do, because it has none. Both gates are right for a
     * session-authenticated route: without a sibling that resolves one, the engine
     * cannot tell a deliberately public API from an oversight.
     *
     * Neither is right for a **webhook**. A receiver that writes the request body into
     * storage without recomputing the issuer's signature is exposed whatever else is in
     * the file, because the URL is the only thing standing between an outside caller and
     * that write, and a URL is not a secret. Between them the two gates meant the
     * commonest layout there is — one receiver, alone in its own module — produced
     * nothing at all. Third time this project has found the same shape: a precision rule
     * stated as "no contrast, no finding" turning into silence on exactly the code most
     * likely to be wrong.
     *
     * Alone, it is reported as `needs_review`, because verification could legitimately
     * sit in framework middleware this file cannot see. That is a question a reader
     * settles in one request, and it became sayable once the corpus scorer stopped
     * counting an unsettled candidate as a false claim.
     */
    const gaps = new Map<Endpoint, { contrast: Endpoint[] }>();
    for (const endpoint of endpoints) {
      const gap = unverifiedWebhook(context, endpoint, endpoints);
      if (gap) {
        gaps.set(endpoint, gap);
        continue;
      }
      /*
       * The other kind of endpoint whose exposure does not depend on a sibling.
       *
       * The contrast gate asks "does anything here authenticate", because a module where
       * nothing does may be a deliberately public API. An **administratively scoped
       * path** answers that question without a sibling: `/admin/…`, `/internal/…`,
       * `/manage/…` is the application's own statement that this surface is not for the
       * public, and a handler on one that resolves no caller at all is exposed whatever
       * its neighbours do. A module holding one such route — which is how file-routed
       * frameworks lay them out, one file per endpoint — produced nothing.
       *
       * Reported as a question, because the gate is very often route-level middleware
       * config in another module that this file cannot see. That is the same reason the
       * privileged-operation rule no longer asserts on path alone; the difference is that
       * saying "nothing here identifies the caller, and the path says operators only" is
       * true and checkable either way, where naming it a *role* defect was not.
       */
      if (proves(endpoint)) continue;
      const route = endpoint.route ?? attributeRoute(context, endpoint.anchor);
      if (!route || !PRIVILEGED_PATH.test(route)) continue;
      if (unauthenticatedByDesign(endpoint.label)) continue;
      if (writesIn(context, endpoint.body).length === 0 && !performsDataAccess(context, endpoint.body)) continue;
      gaps.set(endpoint, { contrast: [] });
    }

    const authenticated = endpoints.filter(proves);
    if (gaps.size === 0 && (endpoints.length < 2 || authenticated.length === 0)) return;

    for (const endpoint of endpoints) {
      if (proves(endpoint)) continue;
      const gap = gaps.get(endpoint) ?? null;
      const webhook = gap && isWebhookEndpoint(context, endpoint) ? gap : null;
      const operatorPath = gap && !webhook ? gap : null;
      // With no authenticated sibling anywhere in the module, or no sibling at all, the
      // only thing worth saying is about an unverified webhook; the rest is the
      // public-API case, where silence is the correct answer.
      if (!gap && (endpoints.length < 2 || authenticated.length === 0)) continue;
      if (unauthenticatedByDesign(endpoint.label) && !gap) continue;
      // A sign-in, sign-out, or credential-exchange handler cannot require a
      // session: establishing one is what it is for. A webhook receiver is never that,
      // whatever its vocabulary suggests — handling a shared signing secret reads like
      // a credential exchange and is the opposite of one, and taking the exemption at
      // face value here suppressed the finding after every other gate had passed it.
      if (!gap && establishesSession(context, endpoint.body)) continue;

      const writes = writesIn(context, endpoint.body);
      const reads = performsDataAccess(context, endpoint.body);
      if (writes.length === 0 && !reads) continue;
      // Whether the record belongs to one identifiable subject decides whether a
      // session-less handler is exposed — a shared catalogue read by anybody is not a
      // finding. It decides nothing about a webhook: what an unverified receiver exposes
      // is the write itself, performable by anyone who learns the URL, and shipment
      // status rows keyed by a carrier reference are no less writable for not belonging
      // to a person.
      if (!webhook && !operatorPath && !touchesPerSubjectRecord(context, endpoint.body)) continue;

      const mutates = writes.length > 0;
      // The endpoints the finding is contrasted against. For a webhook that is the
      // receivers which verify their signature, not every sibling that happens to
      // resolve a session: naming a session-authenticated route as the example a
      // webhook should follow would send the reader after the wrong fix.
      const contrast = gap ? gap.contrast : authenticated;
      const siblings = contrast.map((sibling) => sibling.label).join(", ");
      /*
       * Every sentence below used to assume this list had something in it, because until
       * a receiver could be reported without a verified sibling it always did. `alone`
       * is what a webhook module containing exactly one receiver looks like, and reading
       * `contrast[0]!.label` on it threw — which the rule's own try/catch turned into a
       * `parseFailures` entry rather than a crash, so the case simply read as silent.
       */
      const alone = contrast.length === 0;
      const example = contrast[0] ?? null;
      const route = endpoint.route ?? attributeRoute(context, endpoint.anchor);

      context.report({
        ruleId: "missing-handler-authentication",
        category: "missing_authentication",
        title: webhook
          ? `${endpoint.label} accepts an unsigned event body and ${mutates ? "writes it to storage" : "reads storage with it"}`
          : `${endpoint.label} ${mutates ? "writes" : "reads"} a per-user record without establishing who the caller is`,
        severity: mutates ? "critical" : "high",
        // A receiver with no verifying sibling to compare against cannot rule out
        // framework middleware, so the absence is a question there rather than an
        // established gap.
        verification: alone ? "needs_review" : "strong_evidence",
        summary: webhook
          ? `${endpoint.label} parses the request body and ${mutates ? "writes it into" : "reads"} storage without checking that the request came from the issuer. A webhook has no session to resolve — the issuer signs the payload with a shared secret and the receiver recomputes the signature — and this handler never does. ${
              alone
                ? "No other receiver in this module verifies one either, so it is possible the check lives in middleware this file cannot see; confirm that before dismissing it, because nothing in the handler performs it"
                : contrast.length === 1
                  ? `${siblings} in the same module verifies its signature before touching the database, so the helper, the secret binding, and the pattern are all present in this file and were simply not applied here`
                  : `${siblings} in the same module verify their signatures before touching the database, so the helper, the secret binding, and the pattern are all present in this file and were simply not applied here`
            }. The URL is the only thing standing between an outside caller and this write, and a URL is not a secret: it appears in provider dashboards, in proxy logs, and in anything that ever saw the request.`
          : `${endpoint.label} ${mutates ? "writes to" : "reads"} a record scoped to a single subject, but nothing in it resolves a session, a token, or a user. ${
              alone
                ? `Its own path places it under \`${(route ?? "").replace(/^[A-Z]+ /, "").split("/").filter(Boolean)[0] ?? "an operator prefix"}\`, which is this application's statement that the surface is not public — so confirm whether route-level middleware outside this file supplies the check, because nothing inside it does`
                : contrast.length === 1
                  ? `${siblings} in the same module does, so the surrounding code establishes that this surface is meant to be authenticated and the check was omitted here rather than deliberately left off`
                  : `${siblings} in the same module do, so the surrounding code establishes that this surface is meant to be authenticated and the check was omitted here rather than deliberately left off`
            }.${
              endpoint.kind === "server-action"
                ? " A server action is an HTTP POST endpoint: the framework will invoke it for any caller who can address it, and the form that normally calls it is not a constraint."
                : ""
            }`,
        impact: webhook
          ? "Anyone who learns the URL submits their own events. Every field the handler reads off the payload — the account it names, the amount it carries, the state it sets — is chosen by the caller, so the write is performed on an account of their choosing with a value of their choosing and recorded as if the issuer had sent it."
          : mutates
            ? "An unauthenticated caller writes rows belonging to accounts they have no relationship with. Where the row carries a role, a membership, or a notification setting, that is a direct route to taking over or silencing another account."
            : "An unauthenticated caller reads records belonging to other accounts by supplying their identifiers.",
        remediation: webhook
          ? `Verify the signature before parsing the payload in ${endpoint.label}${
              alone ? "" : `, using the same helper and the same secret binding the verified ${contrast.length === 1 ? "sibling uses" : "siblings use"}`
            }, and return 401 when it does not match. Read the raw body once and compare against it, because re-serialising the parsed object changes the bytes the signature covers, and compare in constant time. Where the provider supports it, reject events whose timestamp is outside a short window so a captured request cannot be replayed.`
          : `Resolve the caller before any data access in ${endpoint.label} and return 401 when there is no session${
              alone ? "" : `, using the same helper the authenticated ${contrast.length === 1 ? "sibling uses" : "siblings use"}`
            }. Then derive the subject from that session rather than from the request, so the identifier in the payload cannot select a different account. Better still, put the check in shared middleware or a wrapper so a newly added handler inherits it instead of having to remember it.`,
        verificationPlan: webhook
          ? `Post a hand-written event body to ${endpoint.label} with no signature header at all, naming an account you control, and read the affected row back. The response must be 401 and the row must be unchanged${
              example ? `; compare against the same call to ${example.label}, which should already answer 401` : ""
            }. Then repeat with a correctly signed body to confirm genuine events are still accepted.`
          : `Call ${endpoint.label} with no cookies and no authorization header, using an identifier that belongs to another test account. The response must be 401 and the record must be unchanged${
              example ? `; compare against the same call to ${example.label}, which should already answer 401` : ""
            }.`,
        taxonomy: ["CWE-306", "CWE-862", "OWASP-A01"],
        location: locationOf(context, endpoint.anchor),
        ...(route ? { route } : {}),
        evidence: [
          sourceEvidence(
            context,
            endpoint.anchor,
            webhook
              ? `No signature verification, session, or token check appears anywhere in ${endpoint.label}, which nonetheless ${mutates ? "writes" : "reads"} a subject-scoped record from the request body.`
              : `No session, token, or user lookup appears anywhere in ${endpoint.label}, which nonetheless ${mutates ? "writes" : "reads"} a subject-scoped record.`
          ),
          ...(example
            ? [
                sourceEvidence(
                  context,
                  example.anchor,
                  webhook
                    ? `${example.label} in the same module verifies the issuer's signature before touching the database, which is the check the reported endpoint is missing.`
                    : `${example.label} in the same module resolves the caller first, which is the check the reported endpoint is missing.`
                )
              ]
            : [])
        ],
        reasoning: webhook
          ? `${endpoint.label} contains no signature verification, no identity-resolving expression, and no role check, and performs ${mutates ? `a ${writes[0]!.kind} operation` : "a data read"} on storage using values taken from the request body. ${
              alone
                ? "No sibling receiver verifies a signature either, so this is reported as a candidate rather than an established gap: verification could sit in middleware outside this file."
                : `It shares a module with ${contrast.length} receiver(s) that do verify their signature.`
            }`
          : `${endpoint.label} contains no identity-resolving expression and no role check, and performs ${mutates ? `a ${writes[0]!.kind} operation` : "a data read"} on storage. ${
              alone
                ? "No sibling in the module authenticates either, so this is reported as a candidate rather than an established gap: the route sits under an operator-scoped path, and route-level middleware outside this file could be supplying the check."
                : `It shares a module with ${contrast.length} endpoint(s) that do resolve the caller, and touches a table or column scoped to a subject.`
            }`
      });
    }
  }
};

/* ------------------------------------------ browser-extension message channels */

/**
 * Extension listeners a web page can address directly.
 *
 * `runtime.onMessage` is reachable from the extension's own content scripts and
 * from other extensions the browser has installed. `runtime.onMessageExternal` and
 * `runtime.onConnectExternal` are reachable from *pages* — from every origin the
 * manifest's `externally_connectable` permits, and that list is routinely a match
 * pattern wide enough to mean every site the user visits. Those are two different
 * boundaries with two different attackers, and they are almost always written side
 * by side in one worker with nearly the same body, which is exactly why the
 * external one is the easy one to leave open: it looks like the internal one, so
 * the check that only the external one needs is the check nobody notices is
 * missing.
 */
const EXTERNAL_MESSAGE_CHANNEL = /(?:^|\.)(?:onMessageExternal|onConnectExternal)$/;

/** The internal channel, named in evidence as the boundary this one is not. */
const INTERNAL_MESSAGE_CHANNEL = /(?:^|\.)onMessage$/;

/**
 * Capabilities the worker holds and the page on the other end does not.
 *
 * A page can already call the open web for itself, so a bare `fetch` proves
 * nothing. What it cannot do is read the extension's own storage — where a linked
 * account's token lives — script another tab, read cookies for a host it has no
 * business on, or talk to a native binary. Those are the capabilities that turn
 * answering an unauthenticated message into lending them out.
 */
const EXTENSION_PRIVILEGE =
  /(?:^|\.)(?:storage\.(?:local|sync|session|managed)|cookies\.(?:get|getAll|set|remove)|tabs\.(?:create|update|remove|executeScript|captureVisibleTab|query|sendMessage)|scripting\.(?:executeScript|insertCSS|registerContentScripts|unregisterContentScripts)|identity\.(?:getAuthToken|launchWebAuthFlow)|debugger\.(?:attach|sendCommand)|downloads\.download|history\.(?:search|deleteUrl)|bookmarks|management|browsingData|webRequest|declarativeNetRequest|proxy|sendNativeMessage|connectNative)(?:\.|$)/;

/** Requests that carry a credential the worker holds and the sender does not. */
const CREDENTIAL_BEARING_REQUEST = /(?:^|\.)(?:fetch|axios|request|get|post|put|patch|del|delete)$/i;
const CREDENTIAL_IN_REQUEST = /authorization|bearer|api[_-]?key|x-api-key|access[_-]?token|\btoken\b/i;

interface ExternalListener {
  /** The `addListener(...)` call: the line a reader will go to. */
  registration: ts.CallExpression;
  /** The channel as it is written in the file, such as `chrome.runtime.onMessageExternal`. */
  channel: string;
  handler: ts.Node;
  /** Which parameter carries the browser-filled sender, when the channel has one. */
  senderIndex: number | null;
}

/**
 * Every externally reachable listener in this file, with its handler resolved.
 *
 * The adapters have already answered the question this rule must not answer for
 * itself — whether `chrome`, `browser`, or a local alias really is the extension
 * API rather than the Playwright handle that half the world calls `browser` — so a
 * file with no extension entry point is left alone outright.
 */
function externalMessageListeners(context: RuleContext): ExternalListener[] {
  const file = context.file;
  if (!entryPointsOf(file).some((entry) => entry.framework === "extension")) return [];

  const out: ExternalListener[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    if (call.expression.name.text !== "addListener") continue;
    const channel = expressionName(call.expression.expression);
    if (!EXTERNAL_MESSAGE_CHANNEL.test(channel)) continue;
    const handler = listenerFunction(context, call.arguments[0]);
    if (!handler) continue;
    // A message listener is handed `(message, sender, sendResponse)`. A connect
    // listener is handed one `Port`, which carries the sender at `port.sender`, so
    // no parameter position holds it and only the property reference counts.
    const senderIndex = /onMessageExternal$/.test(channel) ? 1 : null;
    out.push({ registration: call, channel, handler, senderIndex });
  }
  return out;
}

/** The function a listener argument denotes, inline or declared in this module. */
function listenerFunction(context: RuleContext, argument: ts.Node | undefined): ts.Node | null {
  const inline = functionOf(argument);
  if (inline) return inline;
  if (!argument || !ts.isIdentifier(argument)) return null;
  for (const statement of context.file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === argument.text && statement.body) {
      return statement;
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== argument.text) continue;
      const resolved = functionOf(declaration.initializer);
      if (resolved) return resolved;
    }
  }
  return null;
}

/**
 * Does this listener look at who sent the message?
 *
 * `sender` is the one thing on this channel the sending page cannot choose: the
 * browser fills `sender.origin`, `sender.url`, `sender.id` and `sender.tab` in
 * from the context it dispatched from, not from anything the message claimed.
 * Comparing one of them against an allow list is therefore the whole of
 * authentication here, and a handler that never mentions the binding cannot have
 * done it — the absence is proof rather than an inference, which is exactly why a
 * bare reference is enough to stay silent. A handler that hands `sender` to a
 * helper is taken at its word; deciding otherwise from here would mean guessing
 * about a function this pass may not even be able to see, and guessing is how a
 * rule starts reporting correct code.
 */
function examinesSender(handler: ts.Node, senderIndex: number | null): boolean {
  const fn = handler as ts.FunctionLikeDeclaration;
  const body = fn.body;
  if (!body) return true;

  const bindings = new Set<string>();
  const parameter = senderIndex === null ? undefined : fn.parameters?.[senderIndex];
  if (parameter) for (const name of bindingNames(parameter.name)) bindings.add(name);

  let seen = false;
  walk(body, (inner) => {
    if (seen) return;
    // `port.sender.origin`, and the `sender` a handler pulls off a Port by name.
    if (ts.isPropertyAccessExpression(inner) && inner.name.text === "sender") {
      seen = true;
      return;
    }
    if (ts.isIdentifier(inner) && bindings.has(inner.text)) seen = true;
  });
  return seen;
}

/**
 * Does the page on the other end steer this listener, or hear its answer?
 *
 * Either is enough to make the missing sender check matter: a listener that reads
 * the message decides what to do from something the page chose, and one that
 * answers hands the result of a privileged capability back across the boundary. A
 * listener that does neither — a fire-and-forget ping, a cache clear — acts on
 * nobody's behalf, and reporting it is the noise that teaches a reader to skip
 * this rule.
 */
function servesTheSender(handler: ts.Node): boolean {
  const fn = handler as ts.FunctionLikeDeclaration;
  const body = fn.body;
  if (!body) return false;

  const parameters = fn.parameters ?? [];
  const message = new Set<string>();
  const respond = new Set<string>();
  if (parameters[0]) for (const name of bindingNames(parameters[0].name)) message.add(name);
  if (parameters[2]) for (const name of bindingNames(parameters[2].name)) respond.add(name);

  let found = false;
  walk(body, (inner) => {
    if (found) return;
    if (ts.isIdentifier(inner) && message.has(inner.text)) {
      found = true;
      return;
    }
    if (!ts.isCallExpression(inner)) return;
    if (respond.has(calleeName(inner))) {
      found = true;
      return;
    }
    // A long-lived connection answers through the port rather than a callback.
    if (calleeTail(inner) === "postMessage") found = true;
  });
  return found;
}

/**
 * The capability this listener reaches, if it reaches one.
 *
 * The privilege is never in the listener body. A worker of this shape is written
 * as a dispatcher — one listener, a table of commands, a helper that performs the
 * call — so the listener holds nothing but `dispatch(message)` and the answer it
 * sends back, and a check that stopped at the listener would read every one of
 * them as harmless. The walk therefore follows module-local functions by name, as
 * every other structural check in this file does, and additionally descends into
 * module-level tables of functions, because a table indexed by the message's own
 * `type` is how the command a page selects is actually reached. It stops at the
 * file: a helper in another module is past what this pass can see, and asserting
 * something about it would be inventing a flow rather than finding one.
 */
function extensionPrivilegeIn(context: RuleContext, node: ts.Node): ts.Node | null {
  // The extension API is looked for first and the credential-bearing request
  // second, because a report that names `chrome.storage.local` tells a reader what
  // is being lent out and one that names `fetch` does not. Both are the same
  // finding; only the sentence differs.
  return reachableCapability(context, node, "api", new Set()) ?? reachableCapability(context, node, "credential", new Set());
}

function reachableCapability(
  context: RuleContext,
  node: ts.Node,
  want: "api" | "credential",
  visited: Set<string>
): ts.Node | null {
  const file = context.file;
  let hit: ts.Node | null = null;

  walk(node, (inner) => {
    if (hit) return;

    if (want === "api" && ts.isPropertyAccessExpression(inner) && EXTENSION_PRIVILEGE.test(expressionName(inner))) {
      hit = inner;
      return;
    }

    if (ts.isCallExpression(inner)) {
      const name = calleeName(inner);
      // A request the worker signs with a credential it holds. The credential has
      // to be visible in the call, because an unauthenticated `fetch` to a public
      // URL is something the page could have done for itself.
      if (
        want === "credential" &&
        CREDENTIAL_BEARING_REQUEST.test(name) &&
        CREDENTIAL_IN_REQUEST.test(inner.getText(file.source))
      ) {
        hit = inner;
        return;
      }
      const local = moduleFunctionBody(context, name, visited);
      if (local) {
        const nested = reachableCapability(context, local, want, visited);
        if (nested) {
          hit = nested;
          return;
        }
      }
    }

    // `commands[message.type](message)`: the hop is through a module-level object
    // rather than through a function name, and it is the only hop that reaches the
    // command a page actually selected.
    if (ts.isIdentifier(inner)) {
      const table = moduleObjectLiteral(context, inner.text, visited);
      if (table) {
        const nested = reachableCapability(context, table, want, visited);
        if (nested) hit = nested;
      }
    }
  });

  return hit;
}

/** How the reached capability is named in evidence: the dotted path, else the call. */
function describeCapability(context: RuleContext, node: ts.Node): string {
  const named = ts.isPropertyAccessExpression(node) || ts.isCallExpression(node) ? expressionName(node) : "";
  if (named.length > 0) return `\`${named}\``;
  return `\`${node.getText(context.file.source).slice(0, 60)}\``;
}

/** A module-level binding whose value is an object literal, visited at most once. */
function moduleObjectLiteral(context: RuleContext, name: string, visited: Set<string>): ts.ObjectLiteralExpression | null {
  if (name.length === 0 || visited.has(name)) return null;
  for (const statement of context.file.source.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
      const initializer = declaration.initializer;
      if (initializer && ts.isObjectLiteralExpression(initializer)) {
        visited.add(name);
        return initializer;
      }
    }
  }
  return null;
}

/**
 * An externally reachable extension listener that lends the worker's capabilities
 * to whoever asked.
 *
 * This is the same defect the rest of this rule describes — privileged work with
 * nothing establishing who the caller is — but the contrast that finds it
 * everywhere else is the wrong one here. There is no sibling handler resolving a
 * session, because an extension worker has no sessions: the boundary is the
 * channel, and the channel is named in the source. `onMessage` is the extension
 * talking to itself and needs no check; `onMessageExternal` is the open web
 * talking to the extension and has exactly one — the browser-filled `sender` —
 * which this handler never reads.
 */
function reportUnauthenticatedExternalListeners(context: RuleContext): void {
  const listeners = externalMessageListeners(context);
  if (listeners.length === 0) return;

  const internal = collect(context.file.source, ts.isCallExpression)
    .filter((call) => ts.isPropertyAccessExpression(call.expression) && call.expression.name.text === "addListener")
    .map((call) => expressionName((call.expression as ts.PropertyAccessExpression).expression))
    .find((channel) => INTERNAL_MESSAGE_CHANNEL.test(channel));

  for (const listener of listeners) {
    if (examinesSender(listener.handler, listener.senderIndex)) continue;
    if (!servesTheSender(listener.handler)) continue;
    const privilege = extensionPrivilegeIn(context, listener.handler);
    if (!privilege) continue;

    const capability = describeCapability(context, privilege);
    const contrast = internal
      ? ` The worker also registers ${internal}, and that listener genuinely needs no sender check: it is reachable only from the extension's own content scripts and from extensions the user chose to install. The two are one boundary apart and read as though they were the same one.`
      : "";

    context.report({
      ruleId: "missing-handler-authentication",
      category: "missing_authentication",
      title: `${listener.channel} performs privileged work on a message from any web page without checking the sender`,
      severity: "critical",
      verification: "strong_evidence",
      summary: `${listener.channel} is the boundary between this extension and the open web: every page the manifest's \`externally_connectable\` permits can post to it, and that list is routinely \`*://*/*\`. The listener acts on the message and reaches ${capability}, a capability the extension holds and the page does not, yet the word \`sender\` appears nowhere in it. \`sender\` is the only thing on this channel a page cannot choose — the browser fills it in from the context the message was dispatched from — so nothing here establishes who is asking.${contrast}`,
      impact: "Any page the user visits, and any page that can get itself loaded in their browser, drives the extension as though it were the user. It reads whatever the worker's storage, cookies, host permissions or native connections can reach and receives the answer in its own script, so a linked account's token, a tenant's data, or a privileged action becomes available to a site that has no relationship with either.",
      remediation: `Check \`sender\` as the first thing ${listener.channel} does: compare \`sender.origin\` against an explicit allow list of your own origins, return without answering when it does not match, and keep the list in code rather than relying on the manifest. \`externally_connectable\` is a routing rule and not a trust decision — it decides which pages may deliver a message, not which pages may be believed — so narrowing it is worth doing and is not a substitute. Where the extension does not need to be reachable from the web at all, remove the listener and the manifest entry together.`,
      verificationPlan: `Open the console on an unrelated origin — any page at all — and call \`chrome.runtime.sendMessage("<extension id>", { ... })\` with a command this worker answers. The call must be refused with no useful payload; today it returns the result of ${capability}. Then repeat from your own origin to confirm the legitimate caller still works.`,
      taxonomy: ["CWE-306", "CWE-862", "CWE-346", "OWASP-A01"],
      location: locationOf(context, listener.registration),
      evidence: [
        sourceEvidence(
          context,
          listener.registration,
          `No reference to \`sender\` appears anywhere in this listener, and on an external channel the browser-filled \`sender\` is the only evidence of who sent the message.`
        ),
        sourceEvidence(
          context,
          privilege,
          `The listener reaches ${capability} from here, which belongs to the extension rather than to the page that sent the message.`
        )
      ],
      reasoning: `${listener.channel} is reachable from any web origin the manifest permits. Its handler reads the message or answers it, reaches ${capability} through this module's own functions, and contains no reference to the \`sender\` argument the browser fills in, which is the only authentication the channel offers.`
    });
  }
}

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

      for (const copy of wholeObjectCopies(context, fn, scope)) {
        const line = lineOf(context.file, copy.call);
        if (reported.has(line)) continue;
        reported.add(line);

        const columns = privilegedColumnsNear(context, copy.persist);
        const table = tableOf(context, copy.persist);
        const identityRow = tokensOf(table).some((token) => IDENTITY_TABLE_TOKENS.has(token));

        context.report({
          ruleId: "mass-assignment-spread",
          category: "mass_assignment",
          title: "Caller-supplied fields are copied wholesale onto a stored record without naming the columns they may set",
          severity: identityRow || columns.length > 0 ? "high" : "medium",
          verification: "strong_evidence",
          summary: `${copy.how} copies every key of ${copy.origin} onto \`${copy.record}\`, and \`${copy.record}\` is then handed to storage by ${copy.persistSubject}. The set of columns the write touches is whatever the caller chose to send rather than a list this code decided on, which is the same defect as spreading the body into the payload and is invisible for the same reason: no field name appears anywhere between the request and the row.${
            columns.length > 0
              ? ` The same module names ${columns.map((column) => `\`${column}\``).join(", ")} on this row, so ${columns.length === 1 ? "that column is" : "those columns are"} reachable by adding ${columns.length === 1 ? "it" : "them"} to the request.`
              : ""
          }`,
          impact:
            "A caller adds a field the form never renders and the value is written to their row. Where the row carries a role, a plan, a seat allowance, or a verification flag, that is privilege escalation or paid entitlement performed through the ordinary settings endpoint.",
          remediation:
            "Copy only the fields this operation accepts: iterate a list of permitted names, or parse the request through a schema that rejects unknown keys and assign from the parsed result. An allowlist is the safe form because it fails closed when a column is added to the entity later; deleting keys from the caller's object constrains only the ones somebody thought of.",
          verificationPlan: `Send the request this endpoint expects with one extra field${columns.length > 0 ? ` — ${columns[0]} is the one to try` : ""} — and read the record back. The extra field must be absent from the stored row and the request should be rejected rather than silently accepted.`,
          taxonomy: ["CWE-915", "CWE-639", "OWASP-A01", "OWASP-A04"],
          location: locationOf(context, copy.call),
          ...(attributeRoute(context, copy.call) ? { route: attributeRoute(context, copy.call)! } : {}),
          evidence: [
            sourceEvidence(context, copy.call, `${copy.how} copies ${copy.origin} onto \`${copy.record}\` field for field, with no list of permitted names between them.`),
            sourceEvidence(context, copy.persist, `\`${copy.record}\` is persisted by ${copy.persistSubject}${table ? ` on ${table}` : ""}, so every key the caller sent reaches the row.`)
          ],
          reasoning: `${copy.how} receives ${copy.origin} as its source and \`${copy.record}\` as its target; \`${copy.record}\` reaches ${copy.persistSubject} in the same function, and no allowlist of field names constrains which keys are copied.`
        });
      }
    }
  }
};

/** Methods that hand a record to storage. */
const PERSIST_METHODS = new Set([
  "save", "update", "updateone", "insert", "insertone", "upsert", "persist", "flush", "create",
  "findoneandupdate", "replaceone", "bulkwrite"
]);

interface WholeObjectCopy {
  call: ts.CallExpression;
  /** How a reader would name the copying call, e.g. `Object.assign()`. */
  how: string;
  /** The local binding the caller's fields land on. */
  record: string;
  origin: string;
  persist: ts.CallExpression;
  persistSubject: string;
}

/**
 * Caller-supplied fields copied field-for-field onto a record that is then stored.
 *
 * `Object.assign(account, body)` is `{ ...body }` written with a different
 * keyboard, and it is the shape an ORM entity invites: the handler already holds
 * a loaded row, so the natural way to apply a patch is to copy onto it rather
 * than to build a payload object. A rule that only inspects the payload literal
 * of a database call sees nothing here — there is no payload literal, and the
 * `save()` that follows carries no fields at all.
 *
 * Two conditions keep this off correct code. The source has to be an object the
 * taint model knows is the caller's, rather than a literal that names its fields
 * — `Object.assign(record, { [field]: body[field] })` inside a loop over a
 * permitted-field list is the correct form of exactly this code. And the record
 * has to actually be persisted, because copying request fields onto a local view
 * model changes nothing that outlives the request.
 */
function wholeObjectCopies(context: RuleContext, fn: ts.Node, scope: TaintScope): WholeObjectCopy[] {
  const out: WholeObjectCopy[] = [];

  for (const call of collect(fn, ts.isCallExpression)) {
    const callee = calleeName(call);
    if (normalizeKey(calleeTail(call)) !== "assign") continue;
    if (!/(^|\.)(Object|Reflect)$/.test(callee.slice(0, callee.lastIndexOf(".")))) continue;

    const target = call.arguments[0];
    if (!target) continue;
    // `Object.assign({}, a, b)` builds a fresh object; the record it becomes is
    // whatever binding the result is assigned to.
    const record = ts.isIdentifier(target) ? target.text : assignedBinding(call);
    if (!record) continue;

    for (const source of call.arguments.slice(1)) {
      // A literal names the fields it sets, however it spells the keys.
      if (ts.isObjectLiteralExpression(source)) continue;
      const resolved = resolveExpression(source, scope);
      if (ts.isObjectLiteralExpression(resolved) && !hasSpread(resolved)) continue;
      if (isAllowlisted(context, resolved)) continue;

      const origin = callerObjectOrigin(context, fn, source, scope);
      if (!origin) continue;

      const persist = persistenceOf(fn, record);
      if (!persist) continue;

      out.push({
        call,
        how: `${callee}()`,
        record,
        origin,
        persist,
        persistSubject: `${calleeName(persist)}()`
      });
      break;
    }
  }
  return out;
}

/** The binding a call's result is assigned to, for `const patch = Object.assign({}, body)`. */
function assignedBinding(call: ts.CallExpression): string | null {
  let current: ts.Node | undefined = call.parent;
  for (let depth = 0; current && depth < 4; depth += 1) {
    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) return current.name.text;
    if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(current.left)) {
      return current.left.text;
    }
    current = current.parent;
  }
  return null;
}

/**
 * The call that hands this record to storage, if the function contains one.
 *
 * Both spellings count: a repository is asked to save the entity
 * (`repository.save(account)`), and an active-record entity saves itself
 * (`account.save()`). Without one of them the copy is local to the request and
 * there is no row to over-write.
 */
function persistenceOf(fn: ts.Node, record: string): ts.CallExpression | null {
  let found: ts.CallExpression | null = null;
  walk(fn, (node) => {
    if (found || !ts.isCallExpression(node)) return;
    if (!PERSIST_METHODS.has(normalizeKey(calleeTail(node)))) return;
    if (ts.isPropertyAccessExpression(node.expression)) {
      const receiver = node.expression.expression;
      if (ts.isIdentifier(receiver) && receiver.text === record) {
        found = node;
        return;
      }
    }
    for (const argument of node.arguments) {
      if (ts.isIdentifier(argument) && argument.text === record) {
        found = node;
        return;
      }
      if (ts.isObjectLiteralExpression(argument)) {
        for (const property of argument.properties) {
          if (ts.isShorthandPropertyAssignment(property) && property.name.text === record) found = node;
          if (ts.isPropertyAssignment(property) && ts.isIdentifier(property.initializer) && property.initializer.text === record) {
            found = node;
          }
        }
      }
    }
  });
  return found;
}

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

/* ------------------------------------------------- registrations in other modules */

/** The function an endpoint's body belongs to. */
function endpointFunction(endpoint: Endpoint): ts.Node | null {
  const parent = endpoint.body.parent;
  return parent && ts.isFunctionLike(parent) && (parent as ts.FunctionLikeDeclaration).body === endpoint.body ? parent : null;
}

function registeredGateOf(context: RuleContext, endpoint: Endpoint): ReturnType<typeof registrationGate> {
  const fn = endpointFunction(endpoint);
  return fn ? registrationGate(context.file, [fn]) : null;
}

/**
 * Handlers declared in this module and registered with a router somewhere — often another
 * module: `router.post("/members/:id/role", requireAuth, updateRole)` in `routes.js`,
 * `updateRole` here. No registration in this file names them, so the endpoint models
 * above do not see them; `engine/handlers.ts` does, with the middleware in front.
 *
 * Used by the function-level authorization rule only. The missing-authentication rule
 * judges a handler by its siblings, and a gate mounted where the engine cannot see it —
 * `app.use("/api", requireAuth, router)` in a third file — would make every sibling look
 * unauthenticated alike; that rule keeps to the registrations it can read in full.
 */
function registeredHandlerEndpoints(context: RuleContext, declared: readonly Endpoint[]): Endpoint[] {
  const handlerOf = context.file.requestHandlerOf;
  if (!handlerOf) return [];
  const out: Endpoint[] = [];
  for (const fn of functionsIn(context.file.source)) {
    const handler = handlerOf(fn);
    // A handler with no path of its own — `http.createServer(fn)`, a catch-all — is a
    // dispatcher, whose branches `dispatchEndpoints` judges one by one.
    if (!handler || handler.isMiddleware || handler.file !== context.file || !handler.path) continue;
    const body = handler.fn.body;
    if (!body) continue;
    if (declared.some((endpoint) => endpoint.body === body || spans(endpoint.body, body) || spans(body, endpoint.body))) continue;
    const label = `${handler.method} ${handler.path}`;
    const gate = registrationGate(context.file, [fn]);
    out.push({
      kind: "registration",
      label,
      route: label,
      anchor: fn,
      body,
      gate: [],
      authenticated: Boolean(gate?.authenticates) || resolvesIdentity(context, body),
      stateChanging: STATE_CHANGING.has(handler.method)
    });
  }
  return out;
}

/* ------------------------------------------------- rule: function-level authorization */

export const privilegedOperationWithoutRoleCheck: Rule = {
  id: "privileged-operation-without-role-check",
  category: "broken_function_level_authorization",
  describes: "an administrative operation, or a resolved role never compared, in a handler with no authorization check",
  run(context: RuleContext) {
    const declared = collectEndpoints(context);
    // Dispatch branches are found against the declared endpoints only, exactly as before:
    // a registered server handler *is* the dispatcher, and must not cover its own branches.
    const endpoints = [...declared, ...dispatchEndpoints(context, declared)];
    for (const endpoint of [...endpoints, ...registeredHandlerEndpoints(context, endpoints)]) {
      if (unauthenticatedByDesign(endpoint.label)) continue;
      if (endpoint.route && DIAGNOSTIC_PATH.test(endpoint.route)) continue;
      // Authorising middleware in the registration, wherever it is written, is the check.
      if (registeredGateOf(context, endpoint)?.authorizes) continue;

      const check =
        findRoleCheck(context, endpoint.body) ??
        endpoint.gate.map((scope) => gateRoleCheck(context, scope)).find(Boolean) ??
        null;
      if (check) continue;

      const write = privilegedWriteIn(context, endpoint.body);
      // A sign-off is the same defect written in a schema that never says "role",
      // and it is looked for only where no role-bearing column already explains
      // the handler: one omitted check must not be reported twice.
      const approval = write ? null : approvalWriteIn(context, endpoint.body);
      const unusedRole = resolvedButUncomparedRole(context, endpoint);
      const privilegedByPath = Boolean(endpoint.route && PRIVILEGED_PATH.test(endpoint.route));

      /*
       * An endpoint with no identity at all is the missing-authentication defect, not
       * this one. Reporting both describes one omission twice with one fix.
       *
       * `privilegedByPath` used to excuse that outright, which contradicted the sentence
       * above and produced confident false positives on the commonest administrative
       * architecture there is: a framework that declares its gate as route-level
       * middleware config — Medusa's `defineMiddlewares([{ matcher: "/admin/*", … }])`,
       * Express's `app.use("/admin", requireStaff)`, a Strapi route's `config.policies` —
       * puts nothing in the handler at all, on purpose. The engine cannot see that gate
       * from this file, so "sits on a path reserved for operators, and checks nothing"
       * describes the middleware being invisible rather than the code being wrong.
       *
       * The path may still carry the finding past the identity requirement, but only
       * with evidence of the operation itself: a privileged column written, a sign-off,
       * or a role resolved and never compared. Those are statements about what the
       * handler does, and they survive not being able to see the gate.
       */
      if (!endpoint.authenticated && !(privilegedByPath && (write || approval || unusedRole))) continue;
      if (!write && !approval && !unusedRole && !privilegedByPath) continue;
      if (privilegedByPath && !write && !approval && !unusedRole && !servesStatefulData(context, endpoint.body)) continue;

      const control = write ? write.columns.some((column) => CONTROL_COLUMNS.has(normalizeKey(column))) : false;
      const anchor = write?.node ?? approval?.node ?? unusedRole?.node ?? endpoint.anchor;
      const route = endpoint.route ?? attributeRoute(context, anchor);

      const quoted = (columns: string[]): string => columns.map((column) => `\`${column}\``).join(", ");
      const what = write
        ? `writes ${quoted(write.columns)} on an existing row`
        : approval
          ? `signs off an existing row by writing ${quoted(approval.columns)}`
          : unusedRole
            ? "resolves the caller's own role and never compares it"
            : "sits on a path reserved for operators";

      context.report({
        ruleId: "privileged-operation-without-role-check",
        category: "broken_function_level_authorization",
        title: `${endpoint.label} ${what} with no authorization check`,
        severity: control || !endpoint.authenticated ? "critical" : "high",
        verification: unusedRole && !write ? "strong_evidence" : "needs_review",
        summary: summaryFor(endpoint, write, approval, unusedRole, privilegedByPath),
        impact: control
          ? "Any caller who reaches this endpoint can change who holds which role. In practice that means a viewer promotes itself to owner and then has every permission the application defines, including the ability to remove the real owner."
          : approval
            ? "Any caller the endpoint identifies can sign off any record it can name, their own included. Whatever the approval releases — a payment, a shipment, a published change, a granted permission — is released on their word alone, and the audit trail records them as the legitimate approver, so the trace of the abuse is indistinguishable from correct use."
            : "Any caller who reaches this endpoint performs an operation the application reserves for a subset of its members — changing a plan, a seat allowance, or another account's state — and is billed to, or borne by, the organisation rather than them.",
        remediation: `Compare the caller's role against the privilege this operation needs before performing it, and answer 403 when it does not match.${
          unusedRole ? " The role is already loaded here, so the fix is the comparison rather than another query." : ""
        }${
          approval
            ? " An approval needs two checks rather than one: that the caller holds the approving role, and that they are not the person who raised the record. Add the state precondition alongside them, so a row that is already decided cannot be decided again."
            : ""
        } Put the comparison in the same place for every administrative operation — a middleware, a procedure builder, or a helper such as the one a sibling in this module already uses — so a newly added operation inherits the check instead of needing to remember it.`,
        verificationPlan: approval
          ? `Sign in as an account that may raise a record here but must not approve one, create a record of your own, and call ${endpoint.label} on it. The response must be 403 and the row must still be unapproved; repeat as a privileged account against somebody else's record to confirm genuine sign-off still works.`
          : write || unusedRole
            ? `Sign in as an account with the lowest role this endpoint's tenant offers and call ${endpoint.label} against a row it should not be able to change. The response must be 403 and the row must be unchanged. Repeat as a privileged account to confirm the operation still works.`
            : `Sign in as an ordinary, non-administrative account and call ${endpoint.label}. The response must be 403 or 404 and must contain none of the data the route serves. Repeat with an administrative account to confirm the route still works, and compare the two responses: if they are the same, the route has no authorization at all.`,
        taxonomy: ["CWE-285", "CWE-862", "CWE-269", "OWASP-A01"],
        location: locationOf(context, anchor),
        ...(route ? { route } : {}),
        evidence: evidenceFor(context, endpoint, write, approval, unusedRole),
        reasoning: `No comparison, membership test, or authorization call involving a role, permission, or ownership claim appears in ${endpoint.label} or in its middleware, options, or procedure chain, while the handler ${
          write
            ? `updates ${write.columns.join(", ")}`
            : approval
              ? `moves an existing row into an approved state by writing ${approval.columns.join(", ")}, with no filter scoping the row to the caller and no comparison of the caller against the record's submitter`
              : unusedRole
                ? "loads the caller's role for the target tenant"
                : "serves a privileged path"
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

interface ApprovalWrite {
  node: ts.Node;
  /** The columns, or the `column: "value"` pairs, that record the decision. */
  columns: string[];
}

/**
 * A sign-off: an existing row moved into an approved state, with no check that the
 * caller is entitled to approve it.
 *
 * This is the other write whose value is a decision rather than content, and it is
 * missed by the role-column trigger for a mundane reason — an approval schema does
 * not contain the word "role" anywhere. `status: "approved"` plus
 * `approvedById: session.userId` reads as ordinary bookkeeping, and the tenant
 * check that usually sits above it makes the handler look guarded, which is
 * precisely the trap: proving the caller belongs to the organisation says nothing
 * about whether they may sign for it.
 *
 * Two shapes are silent on purpose. A write narrowed to the caller's own row is a
 * subject acting on their own record — consenting to a grant, accepting a transfer
 * addressed to them — and there is no privilege there to escalate. A handler that
 * compares the approver against the person who raised the record has performed the
 * control that matters most on an approval, and reporting it would send a reader
 * to code that already refuses the interesting case.
 */
function approvalWriteIn(context: RuleContext, node: ts.Node): ApprovalWrite | null {
  const file = context.file;
  for (const call of collect(node, ts.isCallExpression)) {
    const write = classifyWrite(context, call);
    // Creating a row that is already approved is how a seeded or auto-approved
    // record comes into existence. Moving an existing one into an approved state
    // is the decision, so only updates qualify.
    if (!write || write.kind !== "update") continue;

    const columns = new Set<string>();
    for (const property of collect(call, ts.isPropertyAssignment)) {
      const key = propertyKeyOf(property, file);
      if (!key || payloadContext(property) !== "write") continue;
      const normalized = normalizeKey(key);
      if (APPROVAL_COLUMNS.has(normalized)) {
        columns.add(key);
        continue;
      }
      // `status: "approved"`. The column name decides nothing here; the literal
      // does, which is why a computed value is left alone: a status assembled at
      // runtime may be any of the states the workflow defines.
      if (!WORKFLOW_STATUS_COLUMNS.has(normalized)) continue;
      const value = literalTextOf(property.initializer);
      if (value && APPROVED_STATE.test(value.trim())) columns.add(`${key}: "${value}"`);
    }
    // Raw SQL: `UPDATE purchase_orders SET status = 'approved', approved_by = $1`.
    const setClause = /\bset\b([\s\S]*?)(?:\bwhere\b|\breturning\b|$)/i.exec(write.subject);
    if (setClause?.[1]) {
      for (const assignment of setClause[1].split(",")) {
        const [rawName, rawValue = ""] = assignment.split("=");
        const name = (rawName ?? "").trim();
        if (name.length === 0) continue;
        const column = normalizeKey(name.split(".").pop() ?? name);
        if (APPROVAL_COLUMNS.has(column)) {
          columns.add(name);
          continue;
        }
        if (!WORKFLOW_STATUS_COLUMNS.has(column)) continue;
        const value = rawValue.trim().replace(/^['"`]|['"`]$/g, "");
        if (APPROVED_STATE.test(value)) columns.add(`${name} = '${value}'`);
      }
    }

    if (columns.size === 0) continue;
    if (writeScopedToCaller(context, call)) continue;
    if (comparesCallerToRecordSubject(context, node)) continue;
    return { node: call, columns: [...columns] };
  }
  return null;
}

/**
 * Was this write narrowed to a row the caller already owns?
 *
 * `update({ where: { id, userId: session.userId }, ... })` cannot select anybody
 * else's row, so whatever it decides it decides about the caller. Reading the
 * filter rather than the payload is the point: the same payload on an unfiltered
 * `where` is the finding, and the same filter with a different payload is nobody's
 * business.
 */
function writeScopedToCaller(context: RuleContext, call: ts.CallExpression): boolean {
  for (const property of collect(call, ts.isPropertyAssignment)) {
    const key = propertyKeyOf(property, context.file);
    if (!key || !FILTER_KEYS.has(normalizeKey(key))) continue;
    const text = property.initializer.getText(context.file.source);
    if (readsCaller(text)) return true;
  }
  return false;
}

/** Text that names the authenticated caller rather than the record. */
function readsCaller(text: string): boolean {
  return CALLER_REFERENCE.test(text) || isIdentityPath(text);
}

/**
 * Does the handler refuse the caller when they are the subject of the record?
 *
 * Separation of duties is the control an approval workflow exists to enforce: the
 * person who raised the request must not be the person who signs it. A handler
 * that compares the caller against the record's submitter has made that decision,
 * and a rule that reported it anyway would be pointing at the one line that does
 * the hard part. The comparison is recognised in both the forms it is written in —
 * inline, and factored into a helper whose name says it refuses rather than
 * records — and the helper form requires both halves to be present, so a log line
 * that happens to mention the submitter does not excuse the write.
 */
function comparesCallerToRecordSubject(context: RuleContext, node: ts.Node): boolean {
  const file = context.file;
  const namesRecordSubject = (text: string): boolean => !readsCaller(text) && RECORD_SUBJECT_COLUMN.test(text);
  let found = false;

  walk(node, (inner) => {
    if (found) return;

    if (ts.isBinaryExpression(inner)) {
      const kind = inner.operatorToken.kind;
      const isComparison =
        kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
        kind === ts.SyntaxKind.EqualsEqualsToken ||
        kind === ts.SyntaxKind.ExclamationEqualsToken;
      if (!isComparison) return;
      const left = inner.left.getText(file.source);
      const right = inner.right.getText(file.source);
      if ((readsCaller(left) && namesRecordSubject(right)) || (readsCaller(right) && namesRecordSubject(left))) {
        found = true;
      }
      return;
    }

    if (!ts.isCallExpression(inner)) return;
    if (!tokensOf(calleeName(inner)).some((token) => REFUSING_VERBS.has(token))) return;
    const args = inner.arguments.map((argument) => argument.getText(file.source));
    if (args.some(readsCaller) && args.some(namesRecordSubject)) found = true;
  });

  return found;
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
  approval: ApprovalWrite | null,
  unusedRole: UncomparedRole | null,
  privilegedByPath: boolean
): string {
  const gate = endpoint.authenticated
    ? "The caller is identified — a session, a token, or a membership is resolved — but being identified is treated as being entitled."
    : "Nothing in the handler or its middleware identifies the caller at all.";

  if (approval) {
    return `${endpoint.label} moves a row that already exists into an approved state, writing ${approval.columns
      .map((column) => `\`${column}\``)
      .join(", ")}. An approval is not content: it is the decision that the request may proceed, and whoever can write it decides that for the organisation. ${gate} No comparison of the caller's own role, permission, or ownership appears anywhere in the handler, its middleware, or its procedure chain; the row is not narrowed to the caller, so the identifier in the request selects which record gets signed; and nothing compares the approver against the person who raised it, so the requester can approve their own request.${
      endpoint.kind === "server-action"
        ? " Being invoked as though it were a local function is not a constraint on who may invoke it: the framework compiles it into an endpoint and will run it for any caller who can address it."
        : ""
    }`;
  }
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
  approval: ApprovalWrite | null,
  unusedRole: UncomparedRole | null
) {
  const evidence = [];
  if (write) {
    evidence.push(
      sourceEvidence(context, write.node, `The update writes ${write.columns.join(", ")}, which is an authorization decision rather than ordinary content.`)
    );
  }
  if (approval) {
    evidence.push(
      sourceEvidence(
        context,
        approval.node,
        `The update records the sign-off itself — ${approval.columns.join(", ")} — on a row selected by an identifier from the request rather than by the caller's own ownership of it.`
      )
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
          // The carrier branch names no credential at the log site: what it proves
          // is that an object the code reads a credential out of reaches the
          // logger, not that the field was populated on this path. That is worth
          // reporting and worth stating one notch below a credential written out
          // by name, so a reader triages the two in the right order.
          severity: named || (exposure.kind !== "credential-carrier" && credentials.length > 0) ? "high" : "medium",
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
  kind: "whole-input" | "whole-subject" | "credential" | "credential-carrier";
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

    // A caller-controlled object the same code reads a credential out of.
    const carrier = credentialCarrier(context, value, scope);
    if (carrier) {
      return {
        node: candidate,
        kind: "credential-carrier",
        what: `The whole \`${carrier.path}\` object`,
        description: `the entire \`${carrier.path}\` object, which this module reads \`${carrier.field}\` out of`
      };
    }
  }
  return null;
}

interface CredentialCarrier {
  /** The dotted path that reached the logger. */
  path: string;
  /** The credential-named property the module reads off that same path. */
  field: string;
  origin: string;
}

/**
 * An object that is the caller's and that carries a credential inside it.
 *
 * The named-field and whole-request branches above both work from vocabulary: a
 * property called `password`, an object called `body`. Outside a web framework
 * neither name appears. A queue payload is spelled `job.data`, an event envelope
 * `message.attributes`, and logging the whole thing is the ordinary way a failure
 * branch gets written — which is exactly how an OAuth token that lives for an hour
 * ends up in a log stream that is retained for a year.
 *
 * Two conditions carry the claim. The taint model has to say the object is
 * caller-controlled, which is what separates a payload from a configuration
 * object the application built itself. And the same module has to read a
 * credential-named property off *that same path*, which is what proves the object
 * has a credential in it rather than merely being untrusted. A call is never a
 * carrier: `scrub(job.data)` and `pick(payload, keys)` are the correct form of
 * this line, and their result is a different object from the one being tested.
 */
function credentialCarrier(context: RuleContext, value: ts.Node, scope: TaintScope): CredentialCarrier | null {
  if (!ts.isIdentifier(value) && !ts.isPropertyAccessExpression(value)) return null;
  const path = expressionName(value as ts.Expression);
  if (path.length === 0 || path.includes("(")) return null;

  const origin = taintOrigin(value, scope);
  if (!origin) return null;

  for (const access of collect(context.file.source, ts.isPropertyAccessExpression)) {
    if (!CREDENTIAL_FIELDS.has(normalizeKey(access.name.text))) continue;
    if (expressionName(access.expression) !== path) continue;
    return { path, field: access.name.text, origin };
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
