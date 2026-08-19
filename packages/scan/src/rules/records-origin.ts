import ts from "typescript";
import { collect, calleeTail, expressionName, walk } from "../ast/helpers.js";
import type { ParsedFile } from "../ast/parse.js";

/**
 * Where a value in a database predicate came from.
 *
 * This is the half of the object-level authorization rule that answers one question
 * and nothing else: could the caller have chosen this value? The rule proper
 * (`records.ts`) asks it about the value a primary key is compared to, and every
 * decision it makes afterwards depends on the answer being narrow and honest.
 *
 * It is deliberately separate from the engine's own `taint.ts`. That module answers
 * "can this value carry hostile text", which is the right question for injection and
 * the wrong one here: `Number(req.params.id)` cannot inject anything and is still
 * entirely the caller's choice of which row to read. It also treats every property of
 * a framework context as caller data, which would make `ctx.session.userId` look
 * attacker-controlled and turn every correctly scoped query into a false positive.
 *
 * What belongs upstream: `valueTaintOrigin` in `ast/taint.ts` already follows a value
 * through numeric coercion and is the natural home for the "caller chose this value"
 * notion; the distinction drawn here between a request container, an identity object,
 * and a row that came back out of the store would serve every rule that reasons about
 * ownership rather than about text.
 */

/* ------------------------------------------------------------------ vocabulary */

/** Methods that resolve exactly one stored record. */
export const READ_ONE = new Set([
  "findunique",
  "finduniqueorthrow",
  "findfirst",
  "findfirstorthrow",
  "findone",
  "findbyid",
  "findbypk",
  "getbyid",
  "queryone",
  "selectone",
  "oneornone"
]);

/** Methods that change exactly one stored record. */
export const WRITE_ONE = new Set([
  "update",
  "updateone",
  "findoneandupdate",
  "findbyidandupdate",
  "delete",
  "deleteone",
  "findoneanddelete",
  "findbyidanddelete",
  "destroy",
  "remove",
  "replaceone",
  "upsert"
]);

/** Entry points that take a statement written by hand. */
export const RAW_STATEMENT = new Set(["query", "execute", "exec", "raw", "unsafe", "one", "oneornone", "get", "all", "run"]);

/**
 * Searching a collection the process already holds.
 *
 * `find` belongs to Array.prototype, not to any store, so the receiver proves
 * nothing and a rule keyed on one is blind here. What identifies a record lookup is
 * the predicate: an arrow that compares an element's primary key to a value. Records
 * kept in memory are still somebody's records, and the seed data of a small service,
 * a cache, or a preloaded catalogue is exactly where this defect hides from a
 * database-shaped rule.
 */
export const IN_MEMORY_LOOKUP = new Set(["find", "findlast"]);

/**
 * Method names that mean "the data store" on their own. `update`, `delete` and
 * `query` do not: `map.delete(key)` and `array.find(predicate)` are the reason a
 * receiver check exists.
 */
export const UNAMBIGUOUS_STORE_METHOD = new Set([...READ_ONE, "updateone", "deleteone", "replaceone", "upsert"]);

export const STORE_RECEIVER =
  /\b(db|dbs|database|prisma|pool|pg|mysql|sqlite|client|conn|connection|knex|sequelize|drizzle|supabase|sql|tx|trx|orm|mongo|mongoose|collection|coll|datastore|store|table|models?|repo|repository|dao)\b/i;

/** Every store operation, used to decide that a value came out of the database. */
const STORE_METHOD = new Set([
  ...READ_ONE,
  ...WRITE_ONE,
  ...RAW_STATEMENT,
  "findmany",
  "findall",
  "select",
  "insert",
  "create",
  "createmany",
  "aggregate",
  "count",
  "groupby",
  "first",
  "returning"
]);

/** Columns that address a row by its own identity rather than by a relation. */
export const PRIMARY_KEY_COLUMN = /^(id|_id|uuid|guid|pk|objectid)$/i;

/** Columns that name who a row belongs to. */
export const OWNER_COLUMN =
  /\b(user_?id|owner_?id|account_?id|acct_?id|org_?id|organisation_?id|organization_?id|tenant_?id|workspace_?id|team_?id|company_?id|customer_?id|client_?id|member_?id|created_?by|owned_?by|requested_?by|belongs_?to|viewer_?id|actor_?id|subject_?id|principal_?id|author_?id|uploaded_?by)\b/i;

/** Property paths that hold the application's own view of who is asking. */
export const IDENTITY_SEGMENT =
  /^(session|viewer|user|currentuser|current_user|me|actor|principal|auth|identity|subject|membership|caller|claims|token_?payload)$/i;

/** Evidence that this route knows who is calling it. */
export const IDENTITY_EVIDENCE =
  /\b(requireUser|requireViewer|requireSession|requireAuth|requireLogin|requireMember|requireAccount|requireIdentity|authenticate|authenticated|currentUser|currentViewer|getUser|getViewer|getSession|getServerSession|getSessionByToken|useSession|verifySession|readSession|protectedProcedure|authedProcedure|privateProcedure|withAuth|withSession|ensureSignedIn|isSignedIn|getServerSideUser|session|viewer|actor|principal)\b/;

/**
 * Guards that authorise the caller *for this object*, as opposed to merely proving
 * they are signed in. `requireUser` is authentication; `requireProjectMember` is the
 * check this rule exists to notice the absence of, and a route that declares one has
 * done the work outside the query.
 */
export const OBJECT_AUTHZ_GUARD =
  /\b(?:require|ensure|assert|check|verify|has|can|is|with|use|load)[A-Za-z]*(?:Role|Roles|Member|Membership|Owner|Ownership|Access|Permission|Permissions|Admin|Entitlement|Scope|Tenant|Project|Workspace|Team|Org|Organisation|Organization)\b|\b(?:authorize|authorise|authorization|authorisation|acl|permit|ability|abilities|policyCheck|canAccess|guardResource)\b/;

/** Parameters that carry the caller's own data wholesale. */
const CALLER_PARAMETER = new Set(["formdata", "searchparams", "params"]);
const CALLER_PARAMETER_TYPE = /^(FormData|URLSearchParams)$/;

/** Parameters that are containers: only some paths through them are caller data. */
const REQUEST_PARAMETER = new Set(["req", "request", "ctx", "context", "c", "event"]);
const REQUEST_PARAMETER_TYPE = /^(Request|NextRequest|IncomingMessage|FastifyRequest|Context)$/;

/** Destructured sources that are the caller's data. */
const CALLER_SOURCE = new Set([
  "params",
  "searchparams",
  "query",
  "body",
  "input",
  "formdata",
  "form",
  "payload",
  "args",
  "rawbody"
]);

/** Segments that mean "the request", reached through a container. */
const CALLER_SEGMENT = new Set([
  "params",
  "param",
  "query",
  "queries",
  "body",
  "rawbody",
  "headers",
  "header",
  "cookies",
  "cookie",
  "url",
  "originalurl",
  "path",
  "pathname",
  "search",
  "searchparams",
  "nexturl",
  "req",
  "request",
  "form",
  "formdata",
  "files",
  "file",
  "input",
  "args",
  "payload"
]);

/**
 * Segments the framework or the auth layer attaches to the request. These are the
 * application's own data however deep the access goes, and treating them as the
 * caller's is what makes every correctly scoped query look like a defect.
 */
const SERVER_SEGMENT = new Set([
  "user",
  "session",
  "auth",
  "viewer",
  "account",
  "actor",
  "subject",
  "state",
  "locals",
  "principal",
  "identity",
  "membership",
  "tenant",
  "workspace",
  "org",
  "organization",
  "db",
  "prisma",
  "log",
  "logger",
  "app",
  "server",
  "env",
  "config"
]);

/** Accessors that read the caller's data off a framework context object. */
const CALLER_ACCESSOR = new Set([
  "param",
  "params",
  "query",
  "queries",
  "header",
  "headers",
  "cookie",
  "cookies",
  "get",
  "getall",
  "json",
  "text",
  "formdata",
  "parsebody",
  "valid",
  "searchparams"
]);

/** Calls that answer the caller. */
export const RESPONSE_METHOD = new Set([
  "json",
  "send",
  "end",
  "write",
  "render",
  "html",
  "text",
  "jsonp",
  "sendfile",
  "stream",
  "body"
]);
export const RESPONSE_RECEIVER = /^(res|reply|response|ctx|c|context|NextResponse|Response|stream|socket)$/;
/* ---------------------------------------------------------------- small helpers */

export function containsNode(container: ts.Node, node: ts.Node): boolean {
  return node.getStart() >= container.getStart() && node.getEnd() <= container.getEnd();
}

export function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

/** Every function containing this node, innermost first. */
export function enclosingFunctions(node: ts.Node): ts.Node[] {
  const chain: ts.Node[] = [];
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (isFunctionLike(current)) chain.push(current);
    current = current.parent;
  }
  return chain;
}

export function unwrap(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 8; depth += 1) {
    if (
      ts.isAwaitExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isTypeAssertionExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

export function rootIdentifier(node: ts.Node): string | null {
  const inner = unwrap(node);
  if (ts.isIdentifier(inner)) return inner.text;
  if (ts.isPropertyAccessExpression(inner) || ts.isElementAccessExpression(inner)) {
    return rootIdentifier(inner.expression);
  }
  if (ts.isCallExpression(inner)) return rootIdentifier(inner.expression);
  return null;
}

/** The name of every binding a pattern introduces, following renames and nesting. */
export function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const names: string[] = [];
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

export function propertyKey(property: ts.ObjectLiteralElementLike, file: ParsedFile): string {
  if (!property.name) return "";
  return property.name.getText(file.source).replace(/["'`]/g, "");
}

/** Does this branch stop the handler, so a failing guard cannot fall through? */
export function branchTerminates(statement: ts.Node): boolean {
  let stops = false;
  walk(statement, (node) => {
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) stops = true;
    if (ts.isCallExpression(node) && /(^|\.)(notFound|forbidden|unauthorized|throw|redirect)$/i.test(expressionName(node.expression))) {
      stops = true;
    }
  });
  return stops;
}

export function enclosingIf(node: ts.Node, limit: ts.Node): ts.IfStatement | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current && current !== limit) {
    if (ts.isIfStatement(current)) return current;
    current = current.parent;
  }
  return undefined;
}
/* --------------------------------------------------------------- caller origins */

export type Origin = "caller" | "server" | "unknown";

export interface Scope {
  file: ParsedFile;
  functions: ts.Node[];
  /** Local bindings, so a value can be traced back to what produced it. */
  bindings: Map<string, ts.Expression>;
  /** Names that hold the caller's own data. */
  callerNames: Set<string>;
  /** Names that hold a request container: only some paths through them are input. */
  requestNames: Set<string>;
}

/**
 * Is this function a GraphQL resolver? Its second parameter is the client's own
 * arguments, which no naming convention reveals — the resolver map does.
 */
function isResolver(fn: ts.Node, file: ParsedFile): boolean {
  const property = fn.parent;
  if (!property || !ts.isPropertyAssignment(property)) return false;
  const group = property.parent;
  if (!group || !ts.isObjectLiteralExpression(group)) return false;
  const groupProperty = group.parent;
  if (!groupProperty || !ts.isPropertyAssignment(groupProperty)) return false;
  const name = propertyKey(groupProperty, file);
  return name === "Query" || name === "Mutation" || name === "Subscription";
}

function readParameters(fn: ts.Node, scope: Scope): void {
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? ts.factory.createNodeArray([]);
  const resolver = isResolver(fn, scope.file);

  parameters.forEach((parameter, index) => {
    const typeName = parameter.type?.getText(scope.file.source).replace(/<.*>$/, "").trim() ?? "";

    if (resolver && index === 1) {
      for (const bound of boundNames(parameter.name)) scope.callerNames.add(bound);
      return;
    }

    if (ts.isIdentifier(parameter.name)) {
      const name = parameter.name.text;
      if (CALLER_PARAMETER.has(name.toLowerCase()) || CALLER_PARAMETER_TYPE.test(typeName)) {
        scope.callerNames.add(name);
        return;
      }
      if (REQUEST_PARAMETER.has(name.toLowerCase()) || REQUEST_PARAMETER_TYPE.test(typeName)) {
        scope.requestNames.add(name);
      }
      return;
    }

    if (!ts.isObjectBindingPattern(parameter.name)) return;
    for (const element of parameter.name.elements) {
      const source = element.propertyName && ts.isIdentifier(element.propertyName)
        ? element.propertyName.text
        : ts.isIdentifier(element.name)
          ? element.name.text
          : null;
      if (!source) continue;
      const key = source.toLowerCase();
      if (CALLER_SOURCE.has(key)) {
        for (const bound of boundNames(element.name)) scope.callerNames.add(bound);
        continue;
      }
      if (REQUEST_PARAMETER.has(key)) {
        for (const bound of boundNames(element.name)) scope.requestNames.add(bound);
      }
    }
  });
}

/**
 * The bindings and parameters a sink can see.
 *
 * Built over the *whole* enclosing chain plus module scope, because a lookup inside
 * a nested callback is routinely resolved from a parameter three functions up.
 */
export function buildScope(file: ParsedFile, sink: ts.Node): Scope {
  const scope: Scope = {
    file,
    functions: enclosingFunctions(sink),
    bindings: new Map(),
    callerNames: new Set(),
    requestNames: new Set()
  };

  for (const fn of scope.functions) readParameters(fn, scope);

  const roots: ts.Node[] = [file.source, ...scope.functions];
  for (const root of roots) {
    for (const declaration of collect(root, ts.isVariableDeclaration)) {
      if (!declaration.initializer) continue;
      for (const bound of boundNames(declaration.name)) {
        if (!scope.bindings.has(bound)) scope.bindings.set(bound, declaration.initializer);
      }
    }
  }
  return scope;
}

/** Every segment of a dotted path after the root, lower-cased. */
export function pathSegments(node: ts.Node, scope: Scope): string[] {
  const name = expressionName(node as ts.Expression);
  if (!name) return [];
  return name.split(".").slice(1).map((segment) => segment.toLowerCase());
}

export function isStoreCall(call: ts.CallExpression, file: ParsedFile): boolean {
  const tail = calleeTail(call).toLowerCase();
  if (!STORE_METHOD.has(tail)) return false;
  if (UNAMBIGUOUS_STORE_METHOD.has(tail)) return true;
  return STORE_RECEIVER.test(call.expression.getText(file.source));
}

function isCallerAccessor(call: ts.CallExpression, scope: Scope): boolean {
  if (!CALLER_ACCESSOR.has(calleeTail(call).toLowerCase())) return false;
  const root = rootIdentifier(call.expression);
  if (!root) return false;
  if (scope.callerNames.has(root)) return true;
  if (!scope.requestNames.has(root)) return false;
  // `ctx.session.get(...)` is the auth layer, not the request.
  return !pathSegments(call.expression, scope).some((segment) => SERVER_SEGMENT.has(segment));
}

/**
 * Where a value came from: the caller, the application itself, or somewhere this
 * analysis cannot follow.
 *
 * "server" is not a guess about safety, it is a statement that the caller could not
 * have chosen the value — an identity read, a constant, or a row the store just
 * handed back. That last one matters most: an id fetched under an ownership
 * predicate and then reused is the *correct* pattern, and calling it caller-supplied
 * turns every well-written two-step update into a false positive.
 */
export function classify(node: ts.Node, scope: Scope, seen: Set<ts.Node> = new Set()): Origin {
  if (seen.has(node) || seen.size > 40) return "unknown";
  seen.add(node);
  const inner = unwrap(node);

  if (
    ts.isStringLiteralLike(inner) ||
    ts.isNumericLiteral(inner) ||
    inner.kind === ts.SyntaxKind.TrueKeyword ||
    inner.kind === ts.SyntaxKind.FalseKeyword ||
    inner.kind === ts.SyntaxKind.NullKeyword
  ) {
    return "server";
  }

  if (ts.isIdentifier(inner)) {
    if (scope.callerNames.has(inner.text)) return "caller";
    if (IDENTITY_SEGMENT.test(inner.text)) return "server";
    const binding = scope.bindings.get(inner.text);
    if (binding && binding !== inner) return classify(binding, scope, seen);
    return "unknown";
  }

  if (ts.isPropertyAccessExpression(inner) || ts.isElementAccessExpression(inner)) {
    const root = rootIdentifier(inner);
    const segments = pathSegments(inner, scope);
    if (root && IDENTITY_SEGMENT.test(root)) return "server";
    if (segments.some((segment) => SERVER_SEGMENT.has(segment))) return "server";
    if (root && scope.callerNames.has(root)) return "caller";
    if (root && scope.requestNames.has(root) && segments.some((segment) => CALLER_SEGMENT.has(segment))) {
      return "caller";
    }
    return classify(inner.expression, scope, seen);
  }

  if (ts.isCallExpression(inner)) {
    if (isCallerAccessor(inner, scope)) return "caller";
    if (isStoreCall(inner, scope.file)) return "server";
    for (const argument of inner.arguments) {
      if (classify(argument, scope, seen) === "caller") return "caller";
    }
    if (ts.isPropertyAccessExpression(inner.expression)) {
      return classify(inner.expression.expression, scope, seen);
    }
    return "unknown";
  }

  if (ts.isNewExpression(inner)) {
    const constructed = expressionName(inner.expression);
    if (constructed !== "URL" && constructed !== "URLSearchParams") return "unknown";
    for (const argument of inner.arguments ?? []) {
      if (classify(argument, scope, seen) === "caller") return "caller";
    }
    return "unknown";
  }

  if (ts.isTemplateExpression(inner)) {
    for (const span of inner.templateSpans) {
      if (classify(span.expression, scope, seen) === "caller") return "caller";
    }
    return "server";
  }

  if (ts.isBinaryExpression(inner)) {
    const left = classify(inner.left, scope, seen);
    const right = classify(inner.right, scope, seen);
    if (left === "caller" || right === "caller") return "caller";
    return left === "server" && right === "server" ? "server" : "unknown";
  }

  if (ts.isConditionalExpression(inner)) {
    const whenTrue = classify(inner.whenTrue, scope, seen);
    return whenTrue === "caller" ? "caller" : classify(inner.whenFalse, scope, seen);
  }

  if (ts.isObjectLiteralExpression(inner) || ts.isArrayLiteralExpression(inner)) {
    for (const child of collect(inner, ts.isIdentifier)) {
      if (scope.callerNames.has(child.text)) return "caller";
    }
    return "unknown";
  }

  return "unknown";
}
