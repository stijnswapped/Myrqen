import ts from "typescript";
import { collect, calleeTail, expressionName, walk, functionName } from "../ast/helpers.js";
import { entryPointsOf } from "../ast/entrypoints.js";
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
  "findoneby",
  "findoneorfail",
  "findonebyorfail",
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
 * Reads that return rows rather than a row.
 *
 * A repository `find({ where: { id } })` is written with the plural method and
 * answers with an array of one, and the row inside that array reaches the caller
 * exactly as `findOne` would have. The method name says "many"; the filter says
 * "this record". The filter is the half that decides whether a record can be
 * addressed across an account boundary, so reading only the method name misses a
 * defect that the very same predicate under `findOne` would have reported.
 *
 * Every name here also belongs to something that is not a store — `find` most of
 * all — so a lookup is only read out of one of them when the receiver is a store
 * and the argument is a filter object rather than a callback.
 */
export const FILTERED_READ = new Set(["find", "findby", "findall", "findmany", "findandcount", "findandcountby"]);

/**
 * Calls that run a query a builder chain assembled somewhere above them.
 *
 * `createQueryBuilder('i').where('i.id = :id', { id }).getOne()` names no table and
 * takes no filter: everything that decides which row comes back was written into
 * earlier links of the chain. Reading only the arguments of the terminal call sees
 * an empty argument list and concludes there is no lookup here, which switches this
 * rule off for the half of TypeORM that is not the repository shortcut.
 */
export const BUILDER_READ = new Set(["getone", "getoneorfail", "getmany", "getrawone"]);

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
  /\b(requireUser|requireViewer|requireSession|requireAuth|requireLogin|requireMember|requireAccount|requireIdentity|authenticate|authenticated|currentUser|currentViewer|getUser|getViewer|getSession|getServerSession|getSessionByToken|useSession|verifySession|readSession|protectedProcedure|authedProcedure|privateProcedure|withAuth|withSession|ensureSignedIn|isSignedIn|getServerSideUser|session|viewer|actor|principal|requireApiKey|requireApiToken|requireServiceToken|requireClient|requireTenant|resolveApiKey|verifyApiKey|apiKey|apiToken|serviceToken)\b/;

/*
 * The machine-to-machine half of the same idea, added 2026-08-24.
 *
 * A service authenticated by an API key has an identity as surely as one holding a
 * session — the key resolves to an account, and reading another account's rows is
 * the same defect under a different credential. This vocabulary was session-shaped
 * only, so the ownership rule skipped every handler in an API-key service on the
 * grounds that "without an established identity there is no ownership relationship
 * to get wrong". holdout-5's metering family is exactly that shape and every
 * object-authorization case in it was silent.
 */

/**
 * Guards that authorise the caller *for this object*, as opposed to merely proving
 * they are signed in. `requireUser` is authentication; `requireProjectMember` is the
 * check this rule exists to notice the absence of, and a route that declares one has
 * done the work outside the query.
 */
export const OBJECT_AUTHZ_GUARD =
  /\b(?:require|ensure|assert|check|verify|has|can|is|with|use|load)[A-Za-z]*(?:Role|Roles|Member|Membership|Owner|Ownership|Access|Permission|Permissions|Admin|Entitlement|Tenant|Project|Workspace|Team|Org|Organisation|Organization)\b|\b(?:authorize|authorise|authorization|authorisation|acl|permit|ability|abilities|policyCheck|canAccess|guardResource)\b/;

/*
 * `Scope` was removed from that list on 2026-08-24, deliberately.
 *
 * A scope is a **capability**, not a relationship to an object: `requireScope(key,
 * "reports:read")` establishes that this credential may read reports at all, and
 * says nothing whatever about *whose* reports. Treating it as an object-level guard
 * suppressed the finding on a handler that read any customer's quota by path
 * parameter — the credential was entitled to the endpoint and the rule concluded it
 * was entitled to the row.
 *
 * `Tenant`, `Project`, `Workspace`, `Team` and `Org` stay: each of those names an
 * actual container the row belongs to.
 */

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
export const CALLER_SEGMENT = new Set([
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
  // A gateway event is a request container whose parts are spelled out rather
  // than nested under `params`: without these the path parameter of every Lambda
  // and API Gateway handler reads as a value of unknown origin.
  "pathparameters",
  "querystringparameters",
  "multivaluequerystringparameters",
  "pathparams",
  "queryparams",
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
  "config",
  /*
   * The rest of what hangs off a request container and belongs to the server.
   *
   * Extended when the default for a container was inverted below: with an allowlist of
   * input properties, anything unlisted was merely unknown, and a mistake cost a missed
   * finding. With a denylist, anything unlisted is the caller's, and a mistake invents a
   * flow out of the framework's own facilities — so the things a framework hangs off its
   * request object have to be named here rather than assumed absent.
   */
  "res",
  "response",
  "reply",
  "socket",
  "connection",
  "raw",
  "scope",
  "container",
  "services",
  "strapi",
  "plugins",
  "deps",
  "di",
  "injector",
  "runtime",
  "platform",
  "waitUntil",
  "next"
]);

/**
 * Is any word in this path segment one the server owns?
 *
 * Compared token by token rather than as a whole string. `SERVER_SEGMENT` holds `auth`,
 * and the property is spelled `auth_context` by Medusa, `authContext` by the next
 * framework and `authState` by the one after — three different strings for the same
 * thing, none of them equal to `auth`. Whole-string comparison was survivable while an
 * unmatched segment merely meant "unknown"; once the default for a request container
 * became "the caller's", an unmatched `auth_context` promoted the authenticated subject
 * itself to attacker-controlled, and the correctly scoped query that used it read as
 * unscoped. That is the worst failure this rule has: a confident finding on code that
 * does the right thing.
 */
export function ownedByServer(segment: string): boolean {
  if (SERVER_SEGMENT.has(segment)) return true;
  for (const token of segment.split(/[^a-z0-9]+/i)) {
    if (token.length > 0 && SERVER_SEGMENT.has(token.toLowerCase())) return true;
  }
  // `authContext` and `currentUser` carry no separator, so the camel boundary is the
  // only place to split them.
  for (const token of segment.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(" ")) {
    if (token.length > 0 && SERVER_SEGMENT.has(token.toLowerCase())) return true;
  }
  return false;
}

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
  /**
   * Free functions that return caller data when handed this entry point's request
   * object — h3's `getRouterParam(event, "id")`, `getQuery(event)`, `readBody(event)`.
   *
   * The adapters have declared these all along and this scope was the one consumer that
   * never read them. The taint model does (`analyzeFunction` puts them in
   * `scope.accessors`), which is why path traversal and injection were found in an h3
   * handler while an unscoped record lookup in the very same handler was not: the value
   * arrives through a call rather than through a property chain, and only the property
   * chain was recognised here. `event.context.params.id` reported; `getRouterParam(event,
   * "id")` did not, in otherwise identical code.
   */
  accessorNames: Set<string>;
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
 * Bindings the framework adapters named, which the parameter-name model cannot see.
 *
 * Reading parameter names works for the frameworks that hand the whole request over
 * under a conventional name. It works for nothing else: a NestJS `@Param('id') id`
 * is an ordinary string parameter, a SvelteKit endpoint destructures `params` out of
 * an event, and a Lambda handler is given `event`. The adapters already decided which
 * bindings hold data the caller chose — and, just as importantly, which look like it
 * and do not — so this rule asks them rather than guessing from spelling.
 *
 * A seed that names a request *container* is recorded as one rather than as caller
 * data outright, because only some paths through a container are the caller's:
 * `req.params.id` is theirs and `req.user.id` is the auth layer's, and collapsing
 * that distinction would make every correctly scoped query look like a defect.
 */
function readEntryPointBindings(scope: Scope): void {
  const entries = entryPointsOf(scope.file).filter((entry) => entry.node && scope.functions.includes(entry.node));
  if (entries.length === 0) return;

  const trusted = new Set(entries.flatMap((entry) => entry.trustedParameters ?? []));
  for (const name of trusted) {
    scope.callerNames.delete(name);
    scope.requestNames.delete(name);
  }

  for (const entry of entries) {
    for (const seed of entry.seeds ?? []) {
      if (trusted.has(seed.name)) continue;
      if (REQUEST_PARAMETER.has(seed.name.toLowerCase())) scope.requestNames.add(seed.name);
      else scope.callerNames.add(seed.name);
    }
    for (const accessor of entry.accessorFunctions ?? []) scope.accessorNames.add(accessor);
  }
}

/**
 * The bindings and parameters a sink can see.
 *
 * Built over the *whole* enclosing chain plus module scope, because a lookup inside
 * a nested callback is routinely resolved from a parameter three functions up.
 */
/**
 * Parameters a call in another file was observed handing caller data to.
 *
 * `readParameters` above admits a parameter as the caller's only when its **name** or its
 * **type** says so — `CALLER_PARAMETER`, `CALLER_PARAMETER_TYPE`. That is why a layered
 * application is invisible: a service method receives `invoiceId: string`, which is
 * neither, so nothing in the file is caller-controlled and every rule judging a sink
 * inside it stays silent. The value really did come from a URL; the name simply does not
 * say so, and no list of names ever will.
 *
 * `buildCallSiteIndex` answers it by observation instead. A parameter appears here
 * because a real call site in another file passed an argument this engine could already
 * prove was caller-controlled *there* — the distinction the earlier attempt at widening
 * taint was closed with, and what keeps this from being an assumption about what a
 * parameter might hold.
 *
 * Only the enclosing functions are consulted, and `trustedParameters` still runs
 * afterwards, so an adapter that says a binding is server-supplied keeps the last word.
 */
function readObservedParameters(scope: Scope, observed: Map<string, Map<number, string>> | undefined): void {
  if (!observed || observed.size === 0) return;
  for (const fn of scope.functions) {
    const name = functionName(fn);
    if (!name) continue;
    const byIndex = observed.get(name);
    if (!byIndex) continue;
    const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? [];
    for (const index of byIndex.keys()) {
      const parameter = parameters[index];
      if (!parameter) continue;
      for (const bound of boundNames(parameter.name)) scope.callerNames.add(bound);
    }
  }
}

export function buildScope(
  file: ParsedFile,
  sink: ts.Node,
  observedParameters?: Map<string, Map<number, string>>
): Scope {
  const scope: Scope = {
    file,
    functions: enclosingFunctions(sink),
    bindings: new Map(),
    callerNames: new Set(),
    requestNames: new Set(),
    accessorNames: new Set()
  };

  for (const fn of scope.functions) readParameters(fn, scope);
  readObservedParameters(scope, observedParameters);
  readEntryPointBindings(scope);

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

/**
 * A statement, rather than a receiver, as the evidence that a call reads the store.
 *
 * `one(sql, [walletId, session.userId])` is a project's own data-layer helper. It has no
 * store-shaped receiver and its name is on no list, so `isStoreCall` said no — and the
 * consequence is worse than a missed store read. `classify` falls through to "whatever
 * the arguments were", so the **row that came back** inherited the caller-ness of the id
 * that went in, and every predicate built from that row read as caller-supplied. A
 * correctly scoped wallet withdrawal, guarded twice, was reported as the defect.
 *
 * The argument answers what the name cannot: a call handed a string whose shape is a SQL
 * statement is reading the store, whatever the wrapper is called. Same reasoning already
 * applied to the SQL *sink* in `rules/injection.ts`, where exporting one `query()` from a
 * data-layer module meant nothing at all was reported.
 */
const SQL_STATEMENT_SHAPE =
  /\bselect\b[\s\S]*\bfrom\b|\binsert\s+into\b|\bupdate\b[\s\S]*\bset\b|\bdelete\s+from\b/i;

function readsAStatement(call: ts.CallExpression, file: ParsedFile): boolean {
  for (const argument of call.arguments) {
    const inner = unwrap(argument);
    const text = ts.isStringLiteralLike(inner)
      ? inner.text
      : ts.isNoSubstitutionTemplateLiteral(inner) || ts.isTemplateExpression(inner)
        ? inner.getText(file.source)
        : null;
    if (text && SQL_STATEMENT_SHAPE.test(text)) return true;
  }
  return false;
}

export function isStoreCall(call: ts.CallExpression, file: ParsedFile): boolean {
  if (readsAStatement(call, file)) return true;
  const tail = calleeTail(call).toLowerCase();
  if (!STORE_METHOD.has(tail)) return false;
  if (UNAMBIGUOUS_STORE_METHOD.has(tail)) return true;
  return storeReceiver(call, file);
}

/**
 * Declared types that mean "a handle on the data store".
 *
 * Read after the generic arguments are stripped, so `Repository<Invoice>` and
 * `Model<Report>` both answer yes. The trailing `\w*` alternatives matter more than
 * they look: a project's own `InvoiceRepository` or `BillingPrismaService` is the
 * usual spelling once dependency injection is involved.
 */
const STORE_TYPE =
  /^(?:\w*Repository|\w*EntityManager|\w*DataSource|QueryRunner|Connection|Model|Collection|Db|Database|Datastore|Pool|PoolClient|Knex|Sequelize|\w*Prisma\w*|\w*Store)$/;

/** Decorators that fill a member in with a store handle whatever its type says. */
const STORE_INJECTION = /^Inject(?:Repository|Model|Connection|DataSource|EntityManager|Client|Collection)$/;

const storeMemberCache = new WeakMap<ts.SourceFile, Set<string>>();

/**
 * Class members that hold a handle on the data store.
 *
 * Dependency injection hides the store behind a domain name: `this.invoices` is a
 * TypeORM `Repository<Invoice>` and `this.reports` is a Mongoose `Model<Report>`.
 * A receiver test that only knows the words `db` and `repo` sees an ordinary object
 * property and declines to read the query at all, which silently switches this rule
 * off for every controller written the way NestJS teaches. What names the store is
 * the declaration — the type the constructor asks for, or the injection decorator
 * that fills it in — and both are written in the same file as the query.
 */
export function storeMembers(file: ParsedFile): Set<string> {
  const cached = storeMemberCache.get(file.source);
  if (cached) return cached;

  const names = new Set<string>();
  const consider = (name: ts.Node | undefined, type: ts.TypeNode | undefined, declaration: ts.Node): void => {
    if (!name || !ts.isIdentifier(name)) return;
    const declared = (type?.getText(file.source) ?? "").replace(/<[\s\S]*$/, "").trim();
    const decorators = (ts.canHaveDecorators(declaration) ? ts.getDecorators(declaration) : undefined) ?? [];
    const injected = decorators.some((decorator) => {
      const expression = ts.isCallExpression(decorator.expression) ? decorator.expression.expression : decorator.expression;
      const called = ts.isPropertyAccessExpression(expression) ? expression.name.text : expressionName(expression);
      return STORE_INJECTION.test(called);
    });
    if (injected || (declared.length > 0 && STORE_TYPE.test(declared))) names.add(name.text);
  };

  for (const declaration of collect(file.source, ts.isClassLike)) {
    for (const member of declaration.members) {
      if (ts.isPropertyDeclaration(member)) consider(member.name, member.type, member);
      if (!ts.isConstructorDeclaration(member)) continue;
      // A constructor parameter carrying an accessibility modifier declares a member
      // of the class, which is how every injected repository is written.
      for (const parameter of member.parameters) consider(parameter.name, parameter.type, parameter);
    }
  }

  storeMemberCache.set(file.source, names);
  return names;
}

/** Is the thing this call hangs off the data store, by name or by declaration? */
export function storeReceiver(call: ts.CallExpression, file: ParsedFile): boolean {
  if (STORE_RECEIVER.test(call.expression.getText(file.source))) return true;
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const members = storeMembers(file);
  if (members.size === 0) return false;
  // `this.invoices.createQueryBuilder(…).where(…)` still hangs off `this.invoices`,
  // so the walk goes back through the builder links rather than reading the nearest
  // one and giving up.
  let receiver: ts.Node = unwrap(call.expression.expression);
  while (ts.isCallExpression(receiver) || ts.isPropertyAccessExpression(receiver)) {
    if (ts.isPropertyAccessExpression(receiver) && members.has(receiver.name.text)) return true;
    receiver = unwrap(receiver.expression);
  }
  return ts.isIdentifier(receiver) && members.has(receiver.text);
}

function isCallerAccessor(call: ts.CallExpression, scope: Scope): boolean {
  /*
   * A free function the adapter declared, handed the request object.
   *
   * Checked before the method form because it has no receiver to root: the callee is a
   * bare identifier, so `rootIdentifier` returns the accessor's own name and every test
   * below it fails. The request object must appear among the arguments — the adapter's
   * contract is "returns caller data *when called with this entry point's request
   * object*", and `getQuery(someOtherThing)` is not that call.
   */
  if (ts.isIdentifier(call.expression) && scope.accessorNames.has(call.expression.text)) {
    return call.arguments.some((argument) => {
      const argumentRoot = rootIdentifier(argument);
      return Boolean(argumentRoot && (scope.requestNames.has(argumentRoot) || scope.callerNames.has(argumentRoot)));
    });
  }
  if (!CALLER_ACCESSOR.has(calleeTail(call).toLowerCase())) return false;
  const root = rootIdentifier(call.expression);
  if (!root) return false;
  if (scope.callerNames.has(root)) return true;
  if (!scope.requestNames.has(root)) return false;
  // `ctx.session.get(...)` is the auth layer, not the request.
  return !pathSegments(call.expression, scope).some((segment) => ownedByServer(segment));
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
    if (segments.some((segment) => ownedByServer(segment))) return "server";
    if (root && scope.callerNames.has(root)) return "caller";
    /*
     * A path off a request container is the caller's unless it is the server's.
     *
     * This used to require the path to match `CALLER_SEGMENT` — `params`, `query`, `body`
     * and a dozen more. That is an allowlist of the property names frameworks happened to
     * have chosen when the list was written, and every framework since has chosen a new
     * one: Firebase's `onCall` hands the payload over as `request.data`, and `data` is on
     * no list, so `request.data.childId` classified as *unknown* and an unscoped document
     * read keyed by it was not a finding. Adding `data` would have fixed that corpus and
     * nothing else.
     *
     * Inverted instead, which is both more accurate and self-maintaining: the `SERVER_
     * SEGMENT` test three lines above has already returned for every path that belongs to
     * the framework — the session, the logger, the container, the response — so anything
     * still standing on a request object is, by elimination, what the requester sent. A
     * new framework's new name for the payload needs no change here; a new framework's
     * new name for its *own* facilities does, and that is the smaller and slower-moving
     * set.
     */
    if (root && scope.requestNames.has(root)) return "caller";
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

/* ------------------------------------------------------------------ identity */

/**
 * Decorators that hand a handler the authenticated subject.
 *
 * Every decorator-routed framework lets a project write its own, and the name is
 * the only thing that says what it resolves to. Nothing here is a request source:
 * `@Param` and `@Body` are deliberately absent, so a parameter is never read as the
 * subject merely because the caller filled it in.
 */
const IDENTITY_DECORATOR =
  /^(?:Current|Auth|Authed|Authenticated|Signed?In|Logged?In|Active|Request|Ctx|My)?(?:User|Users|Session|Viewer|Actor|Principal|Identity|Subject|Account|Member|Membership|Tenant|Org|Organisation|Organization|Workspace|Team|Me|Caller|Claims)$/i;

/**
 * Segments a framework or an auth layer attaches to the request to say who is asking.
 *
 * A strict subset of `SERVER_SEGMENT`: `req.db` and `req.log` are the application's
 * too and prove nothing about identity, and treating them as proof would let this
 * rule report an anonymous endpoint as an ownership failure when the finding it
 * actually deserves is that anybody at all can call it.
 */
const IDENTITY_ATTACHMENT = new Set([
  "user",
  "session",
  "auth",
  "viewer",
  "account",
  "actor",
  "subject",
  "principal",
  "identity",
  "membership",
  "currentuser"
]);

/**
 * Has this handler resolved who is calling it?
 *
 * The text search in `IDENTITY_EVIDENCE` finds the middleware names the Express
 * world uses and nothing else. A decorator-routed controller establishes identity
 * with a class-level guard whose name the handler never mentions, and reads the
 * subject as `req.user` or through a project-specific `@CurrentUser()` — none of
 * which contains any of those words. Without a structural answer the rule declines
 * to look at the very controllers where this defect is most expensive, because the
 * one thing it insists on seeing is written in a syntax it never read.
 */
export function identityEstablished(scope: Scope): boolean {
  for (const fn of scope.functions) {
    for (const parameter of (fn as ts.FunctionLikeDeclaration).parameters ?? []) {
      const decorators = (ts.canHaveDecorators(parameter) ? ts.getDecorators(parameter) : undefined) ?? [];
      for (const decorator of decorators) {
        const expression = ts.isCallExpression(decorator.expression) ? decorator.expression.expression : decorator.expression;
        const name = ts.isPropertyAccessExpression(expression) ? expression.name.text : expressionName(expression);
        if (IDENTITY_DECORATOR.test(name)) return true;
      }
      // A parameter named after the subject is the subject — unless an adapter has
      // already said the caller fills it in, in which case it is their data under a
      // misleading name.
      for (const bound of boundNames(parameter.name)) {
        if (IDENTITY_SEGMENT.test(bound) && !scope.callerNames.has(bound)) return true;
      }
    }
  }

  // Every level of the chain, because a lookup inside a nested callback is routinely
  // guarded by an identity the outer handler read and the callback never mentions.
  let found = false;
  for (const fn of scope.functions) {
    walk(fn, (node) => {
      if (found) return;
      if (!ts.isPropertyAccessExpression(node)) return;
      const root = rootIdentifier(node);
      if (!root || !scope.requestNames.has(root)) return;
      if (pathSegments(node, scope).some((segment) => IDENTITY_ATTACHMENT.has(segment))) found = true;
    });
    if (found) return true;
  }
  return false;
}
