import ts from "typescript";
import { collect, calleeTail, expressionName, walk } from "../ast/helpers.js";
import { lineOf, snippetAround, type ParsedFile } from "../ast/parse.js";
import { formatRoute, locationOf, routeHintFor, sourceEvidence, type Rule, type RuleContext } from "./context.js";
import { registrationGate } from "../engine/handlers.js";
import {
  BUILDER_READ,
  FILTERED_READ,
  IDENTITY_EVIDENCE,
  IDENTITY_SEGMENT,
  IN_MEMORY_LOOKUP,
  OBJECT_AUTHZ_GUARD,
  OWNER_COLUMN,
  PRIMARY_KEY_COLUMN,
  RAW_STATEMENT,
  READ_ONE,
  RESPONSE_METHOD,
  RESPONSE_RECEIVER,
  STORE_RECEIVER,
  UNAMBIGUOUS_STORE_METHOD,
  WRITE_ONE,
  boundNames,
  branchTerminates,
  buildScope,
  classify,
  containsNode,
  enclosingFunctions,
  enclosingIf,
  isFunctionLike,
  isStoreCall,
  pathSegments,
  propertyKey,
  rootIdentifier,
  identityEstablished,
  storeReceiver,
  unwrap,
  type Scope
} from "./records-origin.js";

/**
 * Records addressed by identifier without being scoped to the caller.
 *
 * This is the defect that costs companies the most and that pattern scanners never
 * find, because the code is correct in every respect except one: it asks the store
 * for a row by its primary key, having already established who is asking, and never
 * puts the two facts in the same sentence.
 *
 * Four shapes have to work, because real projects use all four:
 *
 *   pool.query("SELECT … WHERE id = $1", [orderId])       raw SQL with a bound id
 *   db.document.findUnique({ where: { id } })             an ORM object filter
 *   db.update(invoices).where(eq(invoices.id, invoiceId)) a query-builder chain
 *   orders.findOne({ _id: id })                           a document filter
 *
 * Three things decide a finding, and each of them is a question about *this*
 * statement rather than about the file around it:
 *
 *  1. **Read the predicate, never the statement.** `SELECT account_id, …` and
 *     `select: { workspaceId: true }` both mention the owner column while checking
 *     nothing: a projection hands the owner back to the caller, it does not limit
 *     the row to them. Only the WHERE clause, the `where:` property, the builder's
 *     `.where(…)` arguments, and a document filter are read.
 *  2. **The value the predicate compares the primary key to must be the caller's
 *     own choice.** An id that came back out of the store — a row just inserted, or
 *     a row already fetched under an ownership predicate — is not something the
 *     caller can substitute, and treating it as one is how this rule used to fire
 *     on correct code.
 *  3. **The record has to reach the caller.** A row that is returned in the
 *     response, or written to, is the caller's to lose. A row read only to make a
 *     local decision — a catalogue price, a stock level — is not the same defect,
 *     and reporting it teaches the reader to ignore the tool.
 *
 * The identity that makes ownership meaningful is usually established *outside* the
 * handler: `requireUser` in the route registration, `app.use(requireSession)` at
 * module scope, `protectedProcedure` in a tRPC chain. Testing one function body at a
 * time answers the wrong question, so the whole enclosing chain — the handler, its
 * registration call, and the module's middleware — is consulted.
 */

/* ------------------------------------------------------------------- predicates */

interface Predicate {
  /** Only what constrains which row is touched. */
  text: string;
  /** Values compared to a primary-key column. */
  keyValues: ts.Expression[];
  /** Values compared to an owner column. */
  ownerValues: ts.Expression[];
  /**
   * Every value the predicate constrains that is not the primary key.
   *
   * This is the row's scope, whatever the column is called. `OWNER_COLUMN` knows the
   * words the industry settled on, and a project that files records under
   * `projectId` or `siteId` is scoping them just as firmly under a word no list
   * contains — so the values are kept separately from the recognised owner columns
   * and asked about rather than assumed.
   */
  scopeValues: ts.Expression[];
  /** An owner column appears among the conditions. */
  /**
   * Does this predicate constrain a column that names who a row belongs to?
   *
   * Read from the parsed **columns**. It used to be `OWNER_COLUMN.test(text)` over the
   * predicate's own source, which meant a predicate named an owner whenever the
   * characters of an owner column appeared anywhere in it — **including inside a value
   * the caller supplied**. Combined with `predicateIsScoped`, which returns true when
   * `namesOwner` holds and `ownerValues` is empty, that excused a real defect:
   *
   *     Asset.findOne({ _id: assetId, $or: Asset.visibilityFilter(ctx.request.body.viewerId) })
   *
   * `viewerId` matches `viewer_?id`, no column named an owner so `ownerValues` was
   * empty, and the lookup read as scoped — while the application was letting the caller
   * nominate whose visibility to apply, which is the defect one level up.
   */
  namesOwner: boolean;
}

const EMPTY_PREDICATE: Predicate = { text: "", keyValues: [], ownerValues: [], scopeValues: [], namesOwner: false };

/** The full call chain a builder lookup belongs to: `db.update(x).set(y).where(z)`. */
function chainRoot(call: ts.CallExpression): ts.Node {
  let current: ts.Node = call;
  while (
    current.parent &&
    (ts.isPropertyAccessExpression(current.parent) ||
      ts.isCallExpression(current.parent) ||
      ts.isAwaitExpression(current.parent))
  ) {
    current = current.parent;
  }
  return current;
}

/** `eq(invoices.id, invoiceId)` and friends: a column and the value it must equal. */
function comparisonPairs(node: ts.Node, file: ParsedFile): Array<{ column: string; value: ts.Expression }> {
  const pairs: Array<{ column: string; value: ts.Expression }> = [];
  for (const call of collect(node, ts.isCallExpression)) {
    const tail = calleeTail(call).toLowerCase();
    if (!["eq", "equals", "is", "ne", "inarray", "sql"].includes(tail)) continue;
    const [left, right] = call.arguments;
    if (!left || !right) continue;
    const column = expressionName(left).split(".").pop() ?? "";
    pairs.push({ column, value: right });
  }
  return pairs;
}

/**
 * Operators that still address one row when they compare a primary key.
 *
 * `where("id", ">", cursor)` is a page boundary, not a record address: a row that
 * satisfies it is one of many, so counting it as a key predicate would report every
 * keyset-paginated list as an object-ownership defect.
 */
const IDENTIFYING_OPERATOR = new Set(["=", "==", "===", "is"]);

/**
 * A builder condition written as separate column and value arguments.
 *
 * Knex spells the commonest filter in Node as `where("id", value)`, and the
 * three-argument `where("id", "=", value)` beside it. Neither is an object literal
 * and neither is a `:placeholder` fragment, so both walk straight past
 * `filterPairs` and `fragmentPairs` and the lookup vanishes — which switches this
 * rule off for Knex, and for Adonis Lucid, which is built on it.
 *
 * Only a bare column name answers. A first argument containing an operator or a
 * space is a SQL fragment, which `fragmentPairs` reads with its bindings, and
 * treating it as a column here would pair the whole fragment with the bag.
 */
const BARE_COLUMN = /^[A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?$/;

function argumentPairs(call: ts.CallExpression, file: ParsedFile): Array<{ column: string; value: ts.Expression }> {
  const [first, second, third] = call.arguments;
  if (!first || !second) return [];
  const resolved = unwrap(first);
  if (!ts.isStringLiteralLike(resolved) || !BARE_COLUMN.test(resolved.text)) return [];
  const column = resolved.text.split(".").pop() ?? "";

  if (!third) return [{ column, value: second }];

  const operator = unwrap(second);
  if (!ts.isStringLiteralLike(operator)) return [];
  if (!IDENTIFYING_OPERATOR.has(operator.text.trim().toLowerCase())) return [];
  return [{ column, value: third }];
}

/**
 * Filter properties, at any depth, paired with the value they constrain.
 *
 * The node handed in may be a whole filter object (`{ id, workspaceId }`), a single
 * property of one (`_id: id`, which is how a document store is queried), or a
 * builder condition (`eq(invoices.id, invoiceId)`). All three have to yield the same
 * answer, so the walk starts at the node itself rather than at the objects inside it.
 */
function filterPairs(node: ts.Node, file: ParsedFile): Array<{ column: string; value: ts.Expression }> {
  const pairs: Array<{ column: string; value: ts.Expression }> = [];
  walk(node, (child) => {
    if (ts.isShorthandPropertyAssignment(child)) {
      pairs.push({ column: child.name.text, value: child.name });
      return;
    }
    if (ts.isPropertyAssignment(child)) {
      pairs.push({ column: propertyKey(child, file), value: child.initializer });
    }
  });
  return [...pairs, ...comparisonPairs(node, file)];
}

/**
 * A builder condition written as text, paired with the bag that fills it in.
 *
 * `where("m.id = :manifestId", { manifestId })` states the column in the fragment
 * and the value in the object beside it, and the two are joined by a name that
 * matches neither on its own: reading the object alone sees a property called
 * `manifestId`, which is not a primary key by any spelling, so the lookup vanishes.
 * Resolving the placeholder is what makes the fragment mean what it says — and it
 * cuts both ways, because the owner column an application adds in a second fragment
 * is just as invisible until the same join is made.
 */
function fragmentPairs(conditions: ts.Node[], file: ParsedFile): Array<{ column: string; value: ts.Expression }> {
  const fragments = conditions.map(unwrap).filter((node): node is ts.StringLiteralLike => ts.isStringLiteralLike(node));
  if (fragments.length === 0) return [];

  const bag = new Map<string, ts.Expression>();
  for (const node of conditions) {
    const resolved = unwrap(node);
    if (!ts.isObjectLiteralExpression(resolved)) continue;
    for (const property of resolved.properties) {
      if (ts.isShorthandPropertyAssignment(property)) bag.set(property.name.text, property.name);
      else if (ts.isPropertyAssignment(property)) bag.set(propertyKey(property, file), property.initializer);
    }
  }
  if (bag.size === 0) return [];

  const pairs: Array<{ column: string; value: ts.Expression }> = [];
  for (const fragment of fragments) {
    const condition = /\b(?:\w+\.)?(\w+)\s*=\s*:(\w+)/g;
    for (let match = condition.exec(fragment.text); match; match = condition.exec(fragment.text)) {
      const value = bag.get(match[2] ?? "");
      if (value) pairs.push({ column: match[1] ?? "", value });
    }
  }
  return pairs;
}

/** Property names a filter object uses for projection rather than for selection. */
const PROJECTION_KEY =
  /^(select|columns|returning|projection|fields|include|omit|with|orderby|order|sort|take|skip|limit|offset|cursor|data|set|distinct|having|populate|options)$/i;

/** The conditions an object filter states, with projections and payloads removed. */
function objectFilter(object: ts.ObjectLiteralExpression, file: ParsedFile): ts.Node[] {
  const named = object.properties.find(
    (property) => ts.isPropertyAssignment(property) && /^(where|filter|criteria|conditions|query|match|find)$/i.test(propertyKey(property, file))
  );
  if (named && ts.isPropertyAssignment(named)) return [named.initializer];

  const kept: ts.Node[] = [];
  for (const property of object.properties) {
    if (ts.isShorthandPropertyAssignment(property)) {
      kept.push(property);
      continue;
    }
    if (!ts.isPropertyAssignment(property)) continue;
    if (PROJECTION_KEY.test(propertyKey(property, file))) continue;
    kept.push(property);
  }
  return kept;
}

/** The conditions an arrow predicate states: `(candidate) => candidate.id === id`. */
function callbackPredicate(call: ts.CallExpression, file: ParsedFile): Predicate | null {
  const callback = call.arguments.find(
    (argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)
  );
  if (!callback) return null;
  const parameter = (callback as ts.FunctionLikeDeclaration).parameters[0];
  const element = parameter && ts.isIdentifier(parameter.name) ? parameter.name.text : null;
  if (!element) return null;

  const keyValues: ts.Expression[] = [];
  const ownerValues: ts.Expression[] = [];
  const scopeValues: ts.Expression[] = [];
  for (const comparison of collect(callback, ts.isBinaryExpression)) {
    const kind = comparison.operatorToken.kind;
    if (kind !== ts.SyntaxKind.EqualsEqualsEqualsToken && kind !== ts.SyntaxKind.EqualsEqualsToken) continue;
    const sides: Array<[ts.Expression, ts.Expression]> = [
      [comparison.left, comparison.right],
      [comparison.right, comparison.left]
    ];
    for (const [side, other] of sides) {
      if (!ts.isPropertyAccessExpression(side)) continue;
      if (rootIdentifier(side) !== element) continue;
      const column = side.name.text;
      if (PRIMARY_KEY_COLUMN.test(column)) {
        keyValues.push(other);
        continue;
      }
      scopeValues.push(other);
      if (OWNER_COLUMN.test(column)) ownerValues.push(other);
    }
  }
  if (keyValues.length === 0) return null;
  return {
    text: callback.getText(file.source),
    keyValues,
    ownerValues,
    scopeValues,
    namesOwner: ownerValues.length > 0
  };
}

/* ------------------------------------------------------------------- raw SQL */

const PLACEHOLDER = String.raw`(?:\$(?<ordinal>\d+)|\?|:(?<named>[A-Za-z_]\w*))`;

/** The statement text, following one level of aliasing through a local binding. */
function statementTextOf(argument: ts.Expression, scope: Scope): string | null {
  const resolved = unwrap(argument);
  if (ts.isStringLiteralLike(resolved)) return resolved.text;
  if (ts.isTemplateExpression(resolved)) return resolved.getText(scope.file.source);
  if (ts.isNoSubstitutionTemplateLiteral(resolved)) return resolved.text;
  if (ts.isIdentifier(resolved)) {
    const binding = scope.bindings.get(resolved.text);
    if (binding && binding !== resolved) return statementTextOf(binding, scope);
  }
  return null;
}

/** `WHERE …` and nothing else: the SELECT list is a projection, not a condition. */
function whereClauseOf(sql: string): { text: string; offset: number } | null {
  const match = /\bwhere\b/i.exec(sql);
  if (!match) return null;
  const start = match.index + match[0].length;
  const tail = sql.slice(start);
  const end = /\b(order\s+by|group\s+by|limit|offset|returning|for\s+update|on\s+conflict)\b/i.exec(tail);
  return { text: end ? tail.slice(0, end.index) : tail, offset: start };
}

/** The value bound to the nth placeholder of a statement. */
function boundValue(
  sql: string,
  where: { text: string; offset: number },
  match: RegExpExecArray,
  values: ts.Expression[]
): ts.Expression | null {
  const { ordinal: numbered, named } = match.groups ?? {};
  // A named parameter is bound by an object, not by position: not resolvable here.
  if (named) return null;
  if (numbered) return values[Number(numbered) - 1] ?? null;
  // A positional `?` is the nth question mark in the whole statement.
  const absolute = where.offset + match.index + match[0].length;
  const ordinal = (sql.slice(0, absolute).match(/\?/g) ?? []).length - 1;
  return values[ordinal] ?? null;
}

function sqlPredicate(sql: string, values: ts.Expression[]): Predicate | null {
  const where = whereClauseOf(sql);
  if (!where) return null;

  const keyValues: ts.Expression[] = [];
  const ownerValues: ts.Expression[] = [];
  const scopeValues: ts.Expression[] = [];
  let addressesOneRow = false;
  let namesOwnerColumn = false;

  const condition = new RegExp(String.raw`\b(?:\w+\.)?(?<column>\w+)\s*=\s*${PLACEHOLDER}`, "gi");
  for (let match = condition.exec(where.text); match; match = condition.exec(where.text)) {
    const column = match.groups?.column ?? "";
    const value = boundValue(sql, where, match, values);
    // Set from the column itself, before the value is resolved: a predicate that
    // constrains `account_id` names an owner whether or not the binding for it can be
    // followed, and pretending otherwise reads an unresolvable owner clause as no
    // owner clause at all.
    if (OWNER_COLUMN.test(column)) namesOwnerColumn = true;
    if (PRIMARY_KEY_COLUMN.test(column)) {
      addressesOneRow = true;
      if (value) keyValues.push(value);
      continue;
    }
    if (!value) continue;
    scopeValues.push(value);
    if (OWNER_COLUMN.test(column)) ownerValues.push(value);
  }

  /*
   * A read whose only condition is an owner column the caller filled in.
   *
   *   WHERE customer_id = ?1 AND period = ?2   -- bind(c.req.param('customerId'), …)
   *
   * There is no primary key here, so nothing "addresses one row" and this used to
   * return null — the rule never ran. But the caller has named whose rows to return
   * and the authenticated tenant appears nowhere in the predicate, which is the
   * multi-tenant boundary failing in its plainest form. It addresses *an owner's*
   * rows rather than one row, and that is the same defect a page wider.
   *
   * The owner value becomes the addressing identifier, so the checks downstream do
   * the rest of the work unchanged: `lookupAt` only proceeds when one of them is
   * caller-supplied, and `predicateIsScoped` still clears the predicate when the
   * owner column is filled from the session. `WHERE user_id = ?` bound to
   * `session.user.id` therefore stays silent, as it must.
   */
  if (!addressesOneRow && ownerValues.length > 0) {
    keyValues.push(...ownerValues);
    addressesOneRow = true;
  }

  if (!addressesOneRow) return null;
  return { text: where.text, keyValues, ownerValues, scopeValues, namesOwner: namesOwnerColumn };
}

/* ------------------------------------------------------------------- the sink */

interface Lookup {
  call: ts.CallExpression;
  scope: Scope;
  predicate: Predicate;
  /** The caller-supplied value the primary key is compared to. */
  identifier: ts.Expression;
  mutating: boolean;
  collection: string;
  /** The whole statement, used only for prose and for corroborating evidence. */
  statement: string;
}

/**
 * Links a fluent query builder uses to name the table it addresses.
 *
 * Drizzle and Kysely put the table in `.from(orders)` or `.update(orders)`, not in
 * the call that runs the query. `insert` is deliberately absent: an insert names
 * no existing row, so there is no ownership question to ask about it.
 */
const BUILDER_TABLE_LINK = new Set([
  "from",
  "update",
  "delete",
  "deletefrom",
  "updatetable",
  // Kysely's own table link. The comment above named Kysely as supported and this set
  // did not contain the link Kysely uses, so every `selectFrom("scorecards as s")` chain
  // read as a builder with no table and was declined. `insertInto` stays out for the
  // same reason `insert` does: an insert names no existing row to own.
  "selectfrom"
]);

/**
 * Does this call name its table by calling the store itself?
 *
 * Knex addresses a table as `db("invoices").where(…)` rather than through a
 * `.from(…)` link, so a rule that only reads `BUILDER_TABLE_LINK` sees a chain with
 * no table and declines to treat it as a lookup. The store-shaped callee is what
 * separates it from an ordinary one-argument function call.
 */
function namesTheTableItself(call: ts.CallExpression): boolean {
  if (call.arguments.length !== 1) return false;
  const callee = call.expression;
  // Read the callee's own name rather than its source text: this runs for every
  // call in every chain, and `getText()` re-slices the file each time — enough to
  // quadruple the cost of scanning a large file.
  const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : undefined;
  if (!name || !STORE_RECEIVER.test(name)) return false;
  const table = unwrap(call.arguments[0] as ts.Expression);
  return ts.isStringLiteralLike(table);
}

/** Is this call itself the receiver of a further link in the same chain? */
function isChainedFurther(call: ts.CallExpression): boolean {
  let node: ts.Node = call;
  while (node.parent && (ts.isParenthesizedExpression(node.parent) || ts.isAwaitExpression(node.parent))) {
    node = node.parent;
  }
  const parent = node.parent;
  if (!parent || !ts.isPropertyAccessExpression(parent) || parent.expression !== node) return false;
  return Boolean(parent.parent && ts.isCallExpression(parent.parent) && parent.parent.expression === parent);
}

/**
 * A fluent query-builder chain that addresses rows of one table.
 *
 * `db.select().from(orders).where(eq(orders.id, params.id)).limit(1)` contains no
 * method name this rule already knows. The table arrives through `.from`, the
 * filter through `.where`, and the terminal link is whichever modifier the
 * developer happened to write last — `limit`, `orderBy`, `execute`, `returning`,
 * or nothing at all. Keying on the terminal name therefore switches the whole rule
 * off for Drizzle and Kysely, which is most of the TypeScript ORM population, and
 * the shape it switches off for is the commonest form object-ownership defects
 * take.
 *
 * Recognised by shape instead: a store-shaped receiver, a link that names a table,
 * and a `where`. Only the outermost link answers, so one statement yields one
 * lookup rather than one per link. `orderBy` and `limit` on an array cannot reach
 * here, because an array has neither a store receiver nor a `.from(table)`.
 */
function isFluentBuilderLookup(call: ts.CallExpression, file: ParsedFile): boolean {
  if (isChainedFurther(call)) return false;
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  if (!storeReceiver(call, file)) return false;

  const chain = chainRoot(call);
  let namesTable = false;
  let filters = false;
  for (const inner of collect(chain, ts.isCallExpression)) {
    const tail = calleeTail(inner).toLowerCase();
    if (BUILDER_TABLE_LINK.has(tail) && inner.arguments.length > 0) namesTable = true;
    if (namesTheTableItself(inner)) namesTable = true;
    if (/^(and)?where$/.test(tail) && inner.arguments.length > 0) filters = true;
  }
  return namesTable && filters;
}

/** Methods that hand back at most one row, whatever the predicate matched. */
const SINGLE_ROW_METHOD = new Set([
  ...READ_ONE,
  "first",
  "get",
  "one",
  "single",
  "singleorthrow",
  "getone",
  "getoneorfail",
  // Kysely terminates a single-row read with these rather than with `limit(1)`, so a
  // chain ending in one looked like a listing and a listing is deliberately not this
  // rule's finding.
  "executetakefirst",
  "executetakefirstorthrow"
]);

/**
 * Does this read return a single row?
 *
 * Either the method says so, or the chain caps it with `limit(1)` / `take(1)`. A
 * read of many rows filtered by one caller value is a listing, and reporting it as
 * an object-ownership defect would report every search endpoint.
 */
function returnsOneRow(call: ts.CallExpression, chain: ts.Node): boolean {
  if (SINGLE_ROW_METHOD.has(calleeTail(call).toLowerCase())) return true;
  for (const inner of collect(chain, ts.isCallExpression)) {
    const tail = calleeTail(inner).toLowerCase();
    if (tail !== "limit" && tail !== "take") continue;
    const argument = inner.arguments[0];
    if (argument && ts.isNumericLiteral(argument) && argument.text === "1") return true;
  }
  return false;
}

/** The table or collection this statement addresses, as a reader would name it. */
function collectionOf(call: ts.CallExpression, statement: string, file: ParsedFile): string {
  if (ts.isPropertyAccessExpression(call.expression)) {
    // `this.invoices.createQueryBuilder("i").where(…).getOne()` names the table two
    // links back: the segments in between are the builder assembling the query, and
    // naming a finding after one of them tells the reader nothing they can act on.
    const segments = expressionName(call.expression.expression)
      .split(".")
      .filter((segment) => segment.length > 0 && !segment.endsWith("()") && segment !== "this");
    const tail = segments[segments.length - 1];
    if (tail && !STORE_RECEIVER.test(tail) && !/^query$/i.test(tail)) return tail;
  }
  const table = /\b(?:from|into|update|join)\s+["'`]?([a-z_][a-z0-9_]*)/i.exec(statement);
  if (table) return table[1]!;
  const model = /\.\s*(?:update|insert|delete|select|from)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(statement);
  if (model) return model[1]!;
  return "the record store";
}

/** Does this statement change the row it addresses? */
function isMutating(call: ts.CallExpression, statement: string, sql: string | null): boolean {
  const tail = calleeTail(call).toLowerCase();
  if (WRITE_ONE.has(tail)) return true;
  if (sql) return /^\s*(update|delete|insert|merge|replace)\b/i.test(sql);
  return /\b(?:db|database|client|conn|tx|trx|knex|prisma)\s*\.\s*(?:update|delete)\s*\(/i.test(statement);
}

/**
 * The lookup this call performs, or null when it does not address one record by a
 * value the caller chose.
 */
/** Links that carry the statement text and the bound values of a prepared chain. */
const PREPARE_LINK = new Set(["prepare", "preparestatement", "createstatement"]);
const BIND_LINK = new Set(["bind", "bindvalues", "values", "params"]);

/**
 * The statement and bindings of a prepared-statement chain.
 *
 * Cloudflare D1 and better-sqlite3 both spell a query as
 *
 *   db.prepare("SELECT … WHERE customer_id = ?1").bind(customerId, period).all()
 *
 * where the terminal call takes **no arguments at all**. `lookupAt` reads the SQL
 * out of the call it is looking at, finds nothing, and gives up — so the whole
 * ownership rule was switched off for every D1 query, on a platform this engine
 * ships an adapter for. The text is one link back and the values are two.
 */
function preparedStatement(chain: ts.Node, scope: Scope): { sql: string; values: ts.Expression[] } | null {
  let sql: string | null = null;
  const values: ts.Expression[] = [];
  for (const inner of collect(chain, ts.isCallExpression)) {
    const tail = calleeTail(inner).toLowerCase();
    if (PREPARE_LINK.has(tail) && inner.arguments[0]) {
      const text = statementTextOf(inner.arguments[0], scope);
      if (text) sql = text;
      continue;
    }
    if (BIND_LINK.has(tail)) {
      for (const argument of inner.arguments) {
        const resolved = unwrap(argument);
        if (ts.isArrayLiteralExpression(resolved)) values.push(...resolved.elements);
        else values.push(argument);
      }
    }
  }
  return sql === null ? null : { sql, values };
}

function lookupAt(call: ts.CallExpression, context: RuleContext, scope: Scope): Lookup | null {
  const file = context.file;
  const tail = calleeTail(call).toLowerCase();
  const isRecordMethod = READ_ONE.has(tail) || WRITE_ONE.has(tail);
  const isRawStatement = RAW_STATEMENT.has(tail);
  const isInMemory = IN_MEMORY_LOOKUP.has(tail);
  const chain = chainRoot(call);
  // Two shapes that answer with rows and hand back the one row the caller named.
  // `repository.find({ where: { id } })` states its filter as an argument; a builder
  // states it in earlier links of the chain, so the terminal `getOne()` taking no
  // arguments says nothing about whether it addresses a record. Both are only read
  // as lookups when a store answers them and the filter is an object rather than a
  // callback, which is what keeps `array.find` out.
  const isFilteredRead =
    (storeReceiver(call, file) &&
      ((FILTERED_READ.has(tail) && call.arguments.some((argument) => ts.isObjectLiteralExpression(unwrap(argument)))) ||
        (BUILDER_READ.has(tail) && chain !== call))) ||
    isFluentBuilderLookup(call, file);
  if (!isRecordMethod && !isRawStatement && !isInMemory && !isFilteredRead) return null;
  if (!isInMemory && !isFilteredRead && !UNAMBIGUOUS_STORE_METHOD.has(tail) && !storeReceiver(call, file)) {
    // Without a store-shaped receiver, `map.get(key)` and `set.delete(value)` are
    // indistinguishable from a query by name alone.
    if (!isRawStatement) return null;
  }

  const statement = chain.getText(file.source);
  let predicate: Predicate | null = null;
  let sql: string | null = null;

  if (isInMemory) {
    predicate = callbackPredicate(call, file);
    // `find` is both an array method and a repository method. With no element
    // predicate the filter object below is the only reading left that makes sense.
    if (!predicate && !isFilteredRead) return null;
  }

  // A prepared chain states the SQL a link or two back rather than here.
  if (!predicate && call.arguments.length === 0 && (isRawStatement || isFilteredRead)) {
    const prepared = preparedStatement(chain, scope);
    if (prepared && /\b(select|update|delete|insert|from|where)\b/i.test(prepared.sql)) {
      sql = prepared.sql;
      predicate = sqlPredicate(prepared.sql, prepared.values);
    }
  }

  for (const argument of predicate ? [] : call.arguments) {
    const text = statementTextOf(argument, scope);
    if (text && /\b(select|update|delete|insert|from|where)\b/i.test(text)) {
      sql = text;
      const values = call.arguments
        .slice(1)
        .flatMap((other) => (ts.isArrayLiteralExpression(unwrap(other) as ts.Expression) ? (unwrap(other) as ts.ArrayLiteralExpression).elements : [other]));
      predicate = sqlPredicate(text, [...values]);
      break;
    }
  }

  if (!predicate) {
    const conditions: ts.Node[] = [];
    // Column-and-value arguments are read per call, because the pairing is
    // positional: flattening them into `conditions` would lose which value
    // belonged to which column.
    const separated: Array<{ column: string; value: ts.Expression }> = [];
    for (const argument of call.arguments) {
      const resolved = unwrap(argument);
      if (ts.isObjectLiteralExpression(resolved)) conditions.push(...objectFilter(resolved, file));
    }
    if (/^(and)?where$/.test(tail)) separated.push(...argumentPairs(call, file));
    // A builder chain states its conditions in `.where(...)`, away from the call
    // that names the table.
    if (chain !== call) {
      for (const inner of collect(chain, ts.isCallExpression)) {
        // `andWhere` narrows the same way `where` does. `orWhere` does not — a row
        // that satisfies either side is still returned — so counting one as a scope
        // would excuse a query that never constrained anything.
        if (!/^(and)?where$/.test(calleeTail(inner).toLowerCase())) continue;
        conditions.push(...inner.arguments);
        separated.push(...argumentPairs(inner, file));
      }
    }
    /*
     * A record addressed positionally, with no filter object anywhere in the chain.
     *
     *     db.collection("children").doc(childId).get()                 // Firestore
     *     container("permits").item(permitId, siteId).read()           // Cosmos DB
     *
     * A document store does not have a `where`. It names the collection, then names the
     * document, and both are arguments rather than properties — so `conditions` is empty,
     * this function returned null, and object-level authorization was structurally
     * unreachable for the two most widely deployed document databases there are. Run 7
     * missed both, in handlers where the entry point, the caller's data and the store
     * were all recognised.
     *
     * Read by shape and not by method name: a link whose only argument is a **string
     * literal** names a collection, and the next link that takes a **non-literal**
     * argument names one record inside it. `.doc`, `.item`, `.document`, `.child`, `.key`
     * and whatever the next SDK calls it all satisfy that without being listed. The
     * terminal call still has to return a single row, and `lookupAt` below still discards
     * the whole thing unless the addressing value is caller-controlled — so
     * `collection("rates").doc("gbp").get()` and a document keyed from the session are
     * both unaffected.
     */
    if (conditions.length === 0 && separated.length === 0) {
      const positional = positionalAddress(chain, call, file);
      // The addressing value must be the caller's, exactly as it must be for every other
      // shape: a document keyed from the session, or from a constant, is not this defect.
      if (positional && classify(positional.key, scope) === "caller") {
        return {
          call,
          scope,
          predicate: {
            text: positional.text,
            keyValues: [positional.key],
            ownerValues: [],
            scopeValues: positional.rest,
            namesOwner: false
          },
          identifier: positional.key,
          mutating: isMutating(call, statement, sql),
          collection: positional.collection,
          statement
        };
      }
    }
    if (conditions.length === 0) return null;

    const pairs = [
      ...conditions.flatMap((node) => filterPairs(node, file)),
      ...fragmentPairs(conditions, file),
      ...separated
    ];
    const keyValues = pairs.filter((pair) => PRIMARY_KEY_COLUMN.test(pair.column)).map((pair) => pair.value);
    /*
     * A row addressed by its business reference rather than by `id`.
     *
     *     .from(consignments).where(eq(consignments.reference, ref)).limit(1)
     *
     * `PRIMARY_KEY_COLUMN` is `/^(id|_id|uuid|guid|pk|objectid)$/i`, so this
     * addresses no row as far as the rule is concerned and it never runs. Real
     * applications address rows by `reference`, `slug`, `code`, `waybill`,
     * `invoice_number` — the corpus brief handed to this project's own blind authors
     * uses `:reference` as its example — and holdout-6 lost an object-ownership case
     * to exactly this.
     *
     * Answered by shape rather than by a longer list of column names, because the
     * list would need every noun: **a read that returns a single row, whose only
     * non-owner condition is one value the caller supplied, addresses a record —
     * whatever that column is called.** All three parts are required. `limit(1)` or a
     * single-row method is what makes it an address rather than a filter; one
     * condition is what makes it *the* address; and `lookupAt` below still discards
     * it unless the value is caller-controlled, so `where(status, "open").limit(1)`
     * and a lookup keyed from the session are both unaffected.
     */
    if (keyValues.length === 0 && returnsOneRow(call, chain)) {
      const addressing = pairs.filter((pair) => !OWNER_COLUMN.test(pair.column));
      if (addressing.length === 1) keyValues.push(addressing[0]!.value);
    }
    const ownerValues = pairs.filter((pair) => OWNER_COLUMN.test(pair.column)).map((pair) => pair.value);
    const scopeValues = pairs.filter((pair) => !PRIMARY_KEY_COLUMN.test(pair.column)).map((pair) => pair.value);
    if (keyValues.length === 0) return null;
    const text = conditions.map((node) => node.getText(file.source)).join(", ");
    predicate = {
      text,
      keyValues,
      ownerValues,
      scopeValues,
      namesOwner: pairs.some((pair) => OWNER_COLUMN.test(pair.column))
    };
  }

  const identifier = predicate.keyValues.find((value) => classify(value, scope) === "caller");
  if (!identifier) return null;


  return {
    call,
    scope,
    predicate,
    identifier,
    mutating: isMutating(call, statement, sql),
    collection: collectionOf(call, statement, file),
    statement
  };
}

/**
 * The collection and the document a positional chain addresses.
 *
 * Walks the chain in source order. The first link whose sole argument is a string
 * literal names the collection; the first link after it whose first argument is not a
 * literal names the record. Requires the chain to end in a single-row operation, which is
 * what separates addressing one document from listing a collection.
 */
function positionalAddress(
  chain: ts.Node,
  terminal: ts.CallExpression,
  file: ParsedFile
): { collection: string; key: ts.Expression; rest: ts.Expression[]; text: string } | null {
  if (!returnsOneRow(terminal, chain) && !WRITE_ONE.has(calleeTail(terminal).toLowerCase())) return null;
  if (!storeReceiver(terminal, file) && !isFluentBuilderLookup(terminal, file)) return null;

  /*
   * Innermost link first, ordered by where each one *ends*.
   *
   * Every call in `a.b(x).c(y).d()` begins at `a`, so ordering by start is a tie and the
   * traversal order was whatever `collect` happened to produce. The end position is what
   * distinguishes them: `a.b(x)` closes before `a.b(x).c(y)`, which closes before the
   * whole expression. Getting this wrong reads the terminal call as the collection.
   */
  const links = collect(chain, ts.isCallExpression).sort((a, b) => a.getEnd() - b.getEnd());
  let collection: string | null = null;
  for (const link of links) {
    const first = link.arguments[0] ? unwrap(link.arguments[0]) : null;
    if (collection === null) {
      if (link.arguments.length === 1 && first && ts.isStringLiteralLike(first) && first.text.length > 0) {
        collection = first.text;
      }
      continue;
    }
    if (!first || ts.isStringLiteralLike(first) || ts.isObjectLiteralExpression(first)) continue;
    if (ts.isFunctionLike(first) || ts.isArrowFunction(first)) continue;
    return {
      collection,
      key: link.arguments[0] as ts.Expression,
      rest: link.arguments.slice(1) as ts.Expression[],
      text: link.getText(file.source)
    };
  }
  return null;
}

/* -------------------------------------------------------------- scoping checks */

/**
 * Is the collection being searched already the caller's own?
 *
 * `const mine = await listWorkspacesForUser(db, viewer.userId); mine.find((w) => w.id === id)`
 * is correct code: the list never held anybody else's rows, so picking one out of it
 * by identifier cannot cross an account boundary. The scoping is on the line above
 * the lookup, and a rule that cannot see one line up reports the most obviously
 * correct code in the file.
 */
function collectionScopedToCaller(call: ts.CallExpression, scope: Scope): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const receiver = rootIdentifier(call.expression.expression);
  if (!receiver) return false;
  const binding = scope.bindings.get(receiver);
  if (!binding) return false;
  const source = unwrap(binding);
  if (!ts.isCallExpression(source)) return false;

  // The identity can sit anywhere in the producing call's arguments — second
  // positional (`listForUser(db, viewer.userId)`), inside an options object, or
  // inside the array of a `Promise.all([...])` that fetches several lists at once.
  for (const argument of source.arguments) {
    if (identityValue(argument, scope)) return true;
    for (const inner of collect(argument, ts.isPropertyAccessExpression)) {
      if (identityValue(inner, scope)) return true;
    }
    for (const inner of collect(argument, ts.isIdentifier)) {
      if (identityValue(inner, scope)) return true;
    }
  }
  return false;
}

/** Is this expression the authenticated subject, rather than something named after it? */
function identityValue(node: ts.Node, scope: Scope): boolean {
  /*
   * A predicate computed *from* the caller's identity is the caller's identity.
   *
   *   { _id: assetId, $or: Asset.visibilityFilter(ctx.state.user.id) }
   *
   * The `$or` value is a call, so nothing about it is identity-shaped by name —
   * the receiver is `Asset` and the method is `visibilityFilter`. What makes it a
   * scope is its argument. Refusing to look one level in reports a Mongo query
   * that filters by exactly who is asking, which is the shape any non-trivial
   * visibility model has.
   *
   * One level only, and the argument must be identity-shaped *by segment* rather
   * than by the whole path's text. That is deliberately stricter than the test
   * below: `OWNER_COLUMN` is matched against the full expression there, so
   * `req.body.viewerId` reads as owner-shaped, and recursing into the general test
   * would let `visibilityFilter(req.body.viewerId)` — an application letting the
   * caller nominate whose visibility to use — excuse itself. A segment named
   * `session`, `user`, `auth` or `claims` cannot be spelled by a request body.
   */
  const call = unwrap(node);
  if (ts.isCallExpression(call)) {
    return call.arguments.some((argument) => {
      const root = rootIdentifier(argument);
      const shaped =
        (root !== null && IDENTITY_SEGMENT.test(root)) ||
        pathSegments(argument, scope).some((segment) => IDENTITY_SEGMENT.test(segment));
      return shaped && classify(argument, scope) !== "caller";
    });
  }
  const root = rootIdentifier(node);
  const name = expressionName(node as ts.Expression);
  const shaped =
    (root !== null && IDENTITY_SEGMENT.test(root)) ||
    pathSegments(node, scope).some((segment) => IDENTITY_SEGMENT.test(segment)) ||
    (name !== "" && OWNER_COLUMN.test(name));
  if (!shaped) return false;
  // `listForUser(db, req.query.userId)` names the owner and scopes nothing: the
  // caller chose whose list to read, which is the same defect one level up.
  return classify(node, scope) !== "caller";
}

/**
 * Can evidence sitting at `node` say anything about `sink`?
 *
 * In a single-handler dispatcher every route shares one function body, so the
 * correct ownership filter on the route below is not evidence about the route above
 * it — at most one of those branches ever runs. Evidence has to sit on a path that
 * actually reaches the lookup, which means every branch that encloses the evidence
 * must enclose the lookup too.
 */
function governs(node: ts.Node, sink: ts.Node, outer: ts.Node): boolean {
  let current: ts.Node | undefined = node;
  while (current && current !== outer) {
    const parent: ts.Node | undefined = current.parent;
    const isBranch =
      (parent !== undefined &&
        ts.isIfStatement(parent) &&
        (parent.thenStatement === current || parent.elseStatement === current)) ||
      ts.isCaseClause(current) ||
      ts.isDefaultClause(current) ||
      ts.isCatchClause(current);
    if (isBranch && !containsNode(current, sink)) return false;
    if (!parent) break;
    current = parent;
  }
  return true;
}

/** Does the predicate itself constrain the row to the caller's own? */
function predicateIsScoped(lookup: Lookup): boolean {
  if (lookup.predicate.namesOwner) {
    if (lookup.predicate.ownerValues.length === 0) return true;
    // An owner column compared to something the caller supplied is not a scope.
    return lookup.predicate.ownerValues.some((value) => classify(value, lookup.scope) !== "caller");
  }
  /*
   * A column this analysis does not recognise, constrained by the caller's own
   * identity, is an ownership predicate regardless of what it is called.
   *
   * `OWNER_COLUMN` is a list of names, and a list of names cannot keep up with
   * what applications call their tenants. holdout-5 reported
   *
   *   WHERE id = $1 AND merchant_id = $2      -- [refundId, session.merchantId]
   *
   * as an object-ownership defect because `merchant_id` is not on the list, and no
   * plausible list contains `merchant_id`, `practice_id`, `landlord_id`,
   * `shop_id` and whatever the next domain calls its boundary.
   *
   * The value answers where the name cannot: `identityValue` requires something
   * rooted in the caller's identity that the caller did not choose, which is the
   * definition of a scope. A predicate filtered by who is asking is scoped to who
   * is asking.
   */
  return lookup.predicate.scopeValues.some((value) => identityValue(value, lookup.scope));
}

/**
 * Was the scope this row is filtered by already proved to be the caller's?
 *
 * The most careful multi-tenant code there is reads
 *
 *   const membership = await db.membership.findFirst({ where: { orgId, userId: viewer.id } });
 *   if (!membership) throw new NotFound();
 *   const row = await db.record.findFirst({ where: { orgId, id } });
 *
 * and every value in the second predicate came out of the URL. Judged one statement
 * at a time that is a primary-key lookup with a caller-supplied tenant beside it —
 * the exact shape this rule reports — and reporting it would be wrong twice over:
 * the caller cannot reach another tenant's row, and a tool that cannot tell this
 * apart from the defect is a tool that gets switched off.
 *
 * What separates them is a proof standing between the two statements: a store read
 * that pairs the same scope value with the authenticated subject and whose answer
 * stops the handler. That is an ownership check written as a membership lookup, and
 * it holds however the column is spelled — which matters, because half of these
 * columns are called `projectId` or `siteId` and no vocabulary of owner names will
 * ever contain them all.
 */
function scopeProvenForCaller(lookup: Lookup, chain: ts.Node[]): boolean {
  const roots = new Set<string>();
  for (const value of lookup.predicate.scopeValues) {
    const root = rootIdentifier(value);
    if (root) roots.add(root);
  }
  if (roots.size === 0) return false;
  return chain.some((outer) => scopeProvenWithin(lookup, outer, roots));
}

function scopeProvenWithin(lookup: Lookup, outer: ts.Node, roots: Set<string>): boolean {
  const file = lookup.scope.file;

  for (const call of collect(outer, ts.isCallExpression)) {
    if (call === lookup.call) continue;
    if (!isStoreCall(call, file)) continue;
    // A proof has to run before the statement it protects, and on a path that
    // actually reaches it.
    if (call.getEnd() > lookup.call.getStart()) continue;
    if (!governs(call, lookup.call, outer)) continue;

    const constrainsScope = collect(call, ts.isIdentifier).some((identifier) => roots.has(identifier.text));
    if (!constrainsScope) continue;

    let namesIdentity = false;
    for (const argument of call.arguments) {
      if (namesIdentity) break;
      for (const inner of collect(argument, ts.isPropertyAccessExpression)) {
        if (identityValue(inner, lookup.scope)) namesIdentity = true;
      }
      for (const inner of collect(argument, ts.isIdentifier)) {
        if (identityValue(inner, lookup.scope)) namesIdentity = true;
      }
    }
    if (!namesIdentity) continue;

    if (resultGatesHandler(call, outer, file)) return true;
  }
  return false;
}

/** The names that hold this lookup's result, following straight aliasing. */
function resultNames(lookup: Lookup, outer: ts.Node): Set<string> {
  const names = new Set<string>();
  let current: ts.Node | undefined = lookup.call;
  while (current && current !== outer) {
    if (ts.isVariableDeclaration(current)) {
      for (const bound of boundNames(current.name)) names.add(bound);
      break;
    }
    if (isFunctionLike(current)) break;
    current = current.parent;
  }

  for (let pass = 0; pass < 3; pass += 1) {
    let changed = false;
    for (const declaration of collect(outer, ts.isVariableDeclaration)) {
      if (!declaration.initializer) continue;
      /*
       * `const rows = result.results ?? []` still holds the rows.
       *
       * A defaulting operator is the ordinary way to unwrap a driver's result, and
       * reading only plain access chains lost the trail at the first `??`. The
       * consequence is not a missed name, it is the whole rule switching off: with
       * `rows` unlinked from the lookup, nothing the handler returns is recognised
       * as the record, `recordReachesCaller` answers false, and a query returning
       * any tenant's rows is reported as nothing at all.
       *
       * Only the left side is followed. The fallback is a literal the developer
       * supplied and holds no record.
       */
      let source = unwrap(declaration.initializer);
      if (
        ts.isBinaryExpression(source) &&
        (source.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken ||
          source.operatorToken.kind === ts.SyntaxKind.BarBarToken)
      ) {
        source = unwrap(source.left);
      }
      /*
       * `const enrolment = snapshot.data()` still holds the record.
       *
       * A document store hands back a wrapper and the payload is obtained by *calling*
       * it — `snapshot.data()` in Firestore, `.toObject()` in Mongoose, `.toJSON()`
       * elsewhere — so the trail ended at the first such call and the row was judged
       * never to reach the caller. The whole handler then read as a lookup nobody looks
       * at, which is the one shape this rule deliberately ignores, so a cross-account
       * document read produced nothing.
       *
       * Only an argument-less call on something already known to hold the row counts.
       * That is what separates unwrapping from transforming: `snapshot.data()` is the same
       * record under a new name, while `rows.filter(fn)` or `pick(row, fields)` are
       * decisions the handler made and are followed by the ordinary rules below.
       */
      if (ts.isCallExpression(source) && source.arguments.length === 0 && ts.isPropertyAccessExpression(source.expression)) {
        source = unwrap(source.expression.expression);
      }
      const isAccessChain =
        ts.isIdentifier(source) || ts.isPropertyAccessExpression(source) || ts.isElementAccessExpression(source);
      if (!isAccessChain) continue;
      const root = rootIdentifier(source);
      if (!root || !names.has(root)) continue;
      for (const bound of boundNames(declaration.name)) {
        if (!names.has(bound)) {
          names.add(bound);
          changed = true;
        }
      }
    }
    if (!changed) break;
  }
  return names;
}

function isResponseCall(node: ts.Node, file: ParsedFile): boolean {
  if (ts.isNewExpression(node)) return /^(Next)?Response$/.test(expressionName(node.expression));
  if (!ts.isCallExpression(node)) return false;
  if (ts.isPropertyAccessExpression(node.expression)) {
    if (!RESPONSE_METHOD.has(calleeTail(node).toLowerCase())) return false;
    const receiver = expressionName(node.expression.expression);
    const tail = receiver.split(".").pop() ?? receiver;
    return RESPONSE_RECEIVER.test(tail) || RESPONSE_RECEIVER.test(receiver);
  }
  // A project's own `json(response, 200, order)` answers the caller exactly as
  // `res.json(order)` does. What identifies one is not its name — every codebase
  // spells it differently — but that the response object is handed to it.
  return node.arguments.some((argument) => {
    const root = rootIdentifier(argument);
    return Boolean(root && RESPONSE_RECEIVER.test(root));
  });
}

/**
 * Functions this file calls by name.
 *
 * A route handler is handed to a framework and is never invoked by the module that
 * declares it, so a value it returns leaves the process. A helper the file calls
 * itself returns to the next line of the same program — and counting that as "the
 * record reached the caller" turns every session lookup into a false report:
 * `currentUser` resolving a cookie to a user row reads the identity store by an
 * identifier the caller supplied, which is what authentication *is*.
 */
const locallyCalled = new WeakMap<ts.SourceFile, Set<string>>();

function locallyCalledNames(file: ParsedFile): Set<string> {
  const cached = locallyCalled.get(file.source);
  if (cached) return cached;
  const names = new Set<string>();
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (ts.isIdentifier(call.expression)) names.add(call.expression.text);
  }
  locallyCalled.set(file.source, names);
  return names;
}

/** The name a function is known by, however it was declared. */
function nameOfFunction(fn: ts.Node): string | undefined {
  if (ts.isFunctionDeclaration(fn) && fn.name) return fn.name.text;
  if (ts.isMethodDeclaration(fn) && ts.isIdentifier(fn.name)) return fn.name.text;
  const parent = fn.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  return undefined;
}

/** Does returning from here hand the value to the caller, or to the next line? */
function returnLeavesTheProcess(statement: ts.Node, file: ParsedFile): boolean {
  let current: ts.Node | undefined = statement.parent;
  while (current) {
    if (isFunctionLike(current)) {
      const name = nameOfFunction(current);
      return !name || !locallyCalledNames(file).has(name);
    }
    current = current.parent;
  }
  return true;
}

/** `ctx.body = { … }`: the Koa way of answering, which is not a call. */
function isBodyAssignment(node: ts.Node): node is ts.BinaryExpression {
  if (!ts.isBinaryExpression(node)) return false;
  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return false;
  return /\.(body|payload)$/.test(expressionName(node.left as ts.Expression));
}

/**
 * Does the row reach the caller, or does the caller change it?
 *
 * A record read only to make a local decision — a catalogue price, a stock count —
 * is not the defect this rule describes, and firing on one is how a scanner earns
 * the reputation the product exists to avoid.
 */
function recordReachesCaller(lookup: Lookup, chain: ts.Node[]): boolean {
  if (lookup.mutating) return true;
  if (chain.some((fn) => reachesCallerWithin(lookup, fn))) return true;
  return chain.some((fn) => rowKeysAWrite(lookup, fn));
}

/**
 * The row was not returned — it chose which row gets written.
 *
 *   const ticket = await prisma.ticket.findUnique({ where: { id: params.ticketId } })
 *   …
 *   await prisma.ticket.update({ where: { id: ticket.id }, data: { ownerId: recipient.id } })
 *
 * Nothing about the ticket reaches the response, so "does the record reach the caller"
 * answered no and a transfer of somebody else's ticket read as clean. The read is the
 * authorization decision: it fixes which row the write lands on, and a caller who can
 * choose the identifier can choose the row. That is a strictly worse outcome than a
 * disclosure, and it was the one shape this rule's two escape routes — the row is
 * returned, or the lookup itself mutates — both missed, because the read and the write
 * are separate calls.
 *
 * `ownershipChecked` still applies, so the correct two-step form (fetch, compare the
 * owner against the caller, then write) stays silent.
 */
function rowKeysAWrite(lookup: Lookup, outer: ts.Node): boolean {
  const names = resultNames(lookup, outer);
  if (names.size === 0) return false;
  const file = lookup.scope.file;
  for (const call of collect(outer, ts.isCallExpression)) {
    if (call === lookup.call) continue;
    if (!WRITE_ONE.has(calleeTail(call).toLowerCase())) continue;
    if (!isStoreCall(call, file)) continue;
    if (collect(call, ts.isIdentifier).some((identifier) => names.has(identifier.text))) return true;
  }
  return false;
}

function reachesCallerWithin(lookup: Lookup, outer: ts.Node): boolean {
  const names = resultNames(lookup, outer);
  const file = lookup.scope.file;

  let reaches = false;
  const consider = (reference: ts.Node): void => {
    if (reaches) return;
    let current: ts.Node | undefined = reference.parent;
    let child: ts.Node = reference;
    while (current) {
      if (
        ts.isReturnStatement(current) &&
        current.expression &&
        containsNode(current.expression, child) &&
        returnLeavesTheProcess(current, file)
      ) {
        reaches = true;
        return;
      }
      if ((ts.isCallExpression(current) || ts.isNewExpression(current)) && isResponseCall(current, file)) {
        reaches = true;
        return;
      }
      if (isBodyAssignment(current) && containsNode(current.right, child)) {
        reaches = true;
        return;
      }
      child = current;
      current = current.parent;
    }
  };

  // The call may be returned without ever being bound to a name.
  consider(lookup.call);

  walk(outer, (node) => {
    if (reaches) return;
    if (!ts.isIdentifier(node) || !names.has(node.text)) return;
    const parent = node.parent;
    if (parent && ts.isVariableDeclaration(parent) && parent.name === node) return;
    if (parent && ts.isPropertyAssignment(parent) && parent.name === node) return;
    if (parent && ts.isBindingElement(parent) && parent.name === node) return;
    // A same-named binding in a sibling route's branch is a different value.
    if (!governs(node, lookup.call, outer)) return;
    consider(node);
  });

  return reaches;
}

/**
 * Is the row's owner compared to the caller, or is the pair handed to a guard?
 *
 * Two shapes count. The first compares an owner field of *this* record to the
 * identity and stops the handler when they differ. The second passes the identifier
 * and the identity to one call — `checkReportAccess(db, id, viewer.userId)` — and
 * stops on its answer; that is the same control written as a function, and a rule
 * that only understands the inline comparison reports every codebase that factored
 * it out.
 */
function ownershipChecked(lookup: Lookup, chain: ts.Node[]): boolean {
  return chain.some((fn) => ownershipCheckedWithin(lookup, fn));
}

function ownershipCheckedWithin(lookup: Lookup, outer: ts.Node): boolean {
  const file = lookup.scope.file;
  const names = resultNames(lookup, outer);
  const identifierRoot = rootIdentifier(lookup.identifier);

  for (const comparison of collect(outer, ts.isBinaryExpression)) {
    const kind = comparison.operatorToken.kind;
    const isEquality =
      kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      kind === ts.SyntaxKind.EqualsEqualsToken ||
      kind === ts.SyntaxKind.ExclamationEqualsToken;
    if (!isEquality) continue;
    const text = comparison.getText(file.source);
    if (!OWNER_COLUMN.test(text)) continue;
    // A correct ownership filter on a neighbouring route says nothing about this
    // lookup, however alike the two read and whatever names they share.
    if (!governs(comparison, lookup.call, outer)) continue;
    const mentionsRecord = collect(comparison, ts.isIdentifier).some((identifier) => names.has(identifier.text));
    if (!mentionsRecord) continue;
    const sides = [comparison.left, comparison.right];
    if (!sides.some((side) => classify(side, lookup.scope) === "server")) continue;
    /*
     * The other side has to be the caller, not merely something the caller did not type.
     *
     * `classify` calls a row the store handed back "server", and it is right to: an id
     * fetched under an ownership predicate and reused is the correct two-step pattern.
     * But a row fetched under a predicate the *caller* supplied is server-origin and
     * still caller-chosen, so comparing the record's owner against it constrains nothing:
     *
     *   const recipient = await prisma.account.upsert({ where: { email: body.email } });
     *   if (recipient.id === ticket.ownerId) return status(409);
     *
     * That reads as an ownership check and is a duplicate-transfer check. The caller
     * picks both sides, so it can never fail for the ticket they are stealing. This
     * rule's own description is "compares an owner field of *this* record to the
     * identity", and that is what is required here — the same `IDENTITY_SEGMENT` test
     * the guard-call branch below already applies to its arguments.
     */
    const comparedToIdentity = sides.some((side) => {
      const root = rootIdentifier(side);
      if (root && IDENTITY_SEGMENT.test(root)) return true;
      return pathSegments(side, lookup.scope).some((segment) => IDENTITY_SEGMENT.test(segment));
    });
    if (!comparedToIdentity) continue;
    const guard = enclosingIf(comparison, outer);
    if (guard) {
      if (branchTerminates(guard.thenStatement) || (guard.elseStatement && branchTerminates(guard.elseStatement))) {
        return true;
      }
      continue;
    }
    // A comparison whose result is thrown or returned is the same control.
    if (branchTerminates(comparison.parent)) return true;
  }

  for (const call of collect(outer, ts.isCallExpression)) {
    if (call === lookup.call) continue;
    if (!governs(call, lookup.call, outer)) continue;
    const name = expressionName(call.expression);
    /*
     * The check may be handed the key, or the row the key fetched.
     *
     * Reading only the key misses the commonest correct shape there is: fetch the
     * row, learn which tenant it belongs to, then ask whether the caller belongs to
     * that tenant.
     *
     *   const folder = await prisma.folder.findUnique({ where: { id } });
     *   const membership = await getMembership(session.user.id, folder.workspaceId);
     *   if (!membership) return NextResponse.json({ … }, { status: 404 });
     *
     * `getMembership` receives no argument rooted in `id`, so the old condition
     * rejected it and the rule reported code that enforces the boundary twice.
     * Check-after-fetch is not a weaker pattern than filtering by owner in the
     * query — for a tenant derived from the row it is the only way to write it.
     *
     * Nothing else is relaxed: the call still has to govern the lookup, still has
     * to receive the caller's identity, and still has to either be named as an
     * authorization guard or gate the handler on its result.
     */
    const takesSubject = call.arguments.some((argument) => {
      const root = rootIdentifier(argument);
      if (!root) return false;
      return (identifierRoot !== undefined && root === identifierRoot) || names.has(root);
    });
    if (!takesSubject) continue;
    const takesIdentity = call.arguments.some((argument) => {
      const root = rootIdentifier(argument);
      const segments = pathSegments(argument, lookup.scope);
      return Boolean(
        (root && IDENTITY_SEGMENT.test(root)) || segments.some((segment) => IDENTITY_SEGMENT.test(segment))
      );
    });
    if (!takesIdentity) continue;
    if (OBJECT_AUTHZ_GUARD.test(name)) return true;
    if (resultGatesHandler(call, outer, file)) return true;
  }

  /*
   * A membership lookup: prove the caller belongs to the thing, then gate on the row.
   *
   *     const membership = await db.query.memberships.findFirst({
   *       where: and(eq(memberships.workspaceId, workspaceId),
   *                  eq(memberships.userId, session.userId)),
   *     });
   *     if (!membership) return { ok: false, message: "Workspace not found" };
   *
   * This is the canonical ownership check in a multi-tenant application, and none of
   * the tests above see it: the guard is not a call *taking* the identity, it is a
   * query *constraining* on it, so `rootIdentifier` of the sole argument is an object
   * literal and answers nothing.
   *
   * It was invisible and the corpus did not show it, because the case that exercises it
   * was silent for an unrelated reason — `namesOwner` was read off the predicate's raw
   * text and the value happened to be called `workspaceId`, which matched
   * `workspace_?id`. Fixing that revealed this. The luck was doing the work.
   *
   * Recognised by shape, and all four parts are required: a query that governs the
   * statement, constraining one column with the caller's own identity **and** another
   * with the value the statement addresses, whose falsy result stops the handler. The
   * table's name is irrelevant — `memberships`, `collaborators`, `team_members`, or
   * whatever the next application calls it.
   */
  const identifierRootName = identifierRoot;
  for (const call of collect(outer, ts.isCallExpression)) {
    if (call === lookup.call) continue;
    if (!governs(call, lookup.call, outer)) continue;
    if (!resultGatesHandler(call, outer, file)) continue;

    const conditions: ts.Node[] = [];
    for (const argument of call.arguments) {
      const resolved = unwrap(argument);
      if (ts.isObjectLiteralExpression(resolved)) conditions.push(...objectFilter(resolved, file));
    }
    if (conditions.length === 0) continue;
    const pairs = conditions.flatMap((node) => filterPairs(node, file));
    if (pairs.length < 2) continue;

    const provesCaller = pairs.some((pair) => identityValue(pair.value, lookup.scope));
    if (!provesCaller) continue;
    const provesSubject = pairs.some((pair) => {
      const root = rootIdentifier(pair.value);
      if (!root) return false;
      return (identifierRootName !== undefined && root === identifierRootName) || names.has(root);
    });
    if (provesSubject) return true;
  }

  return false;
}

/** Is the answer to this call tested, with a branch that stops the handler? */
function resultGatesHandler(call: ts.CallExpression, outer: ts.Node, file: ParsedFile): boolean {
  const inCondition = enclosingIf(call, outer);
  if (inCondition && containsNode(inCondition.expression, call) && branchTerminates(inCondition.thenStatement)) {
    return true;
  }

  let declaration: ts.Node | undefined = call;
  while (declaration && declaration !== outer && !ts.isVariableDeclaration(declaration)) {
    declaration = declaration.parent;
  }
  if (!declaration || !ts.isVariableDeclaration(declaration)) return false;
  const names = new Set(boundNames(declaration.name));

  for (const statement of collect(outer, ts.isIfStatement)) {
    const mentions = collect(statement.expression, ts.isIdentifier).some((identifier) => names.has(identifier.text));
    if (!mentions) continue;
    if (branchTerminates(statement.thenStatement)) return true;
  }
  void file;
  return false;
}

/* -------------------------------------------------------------- route context */

/**
 * The text of everything that wraps this handler: the route registration and its
 * middleware, the procedure builder it hangs off, and the module's own middleware.
 *
 * `requireUser` almost never appears inside the function it protects, so a rule that
 * reads only the handler body cannot tell an authenticated route from an anonymous
 * one — and cannot tell an authorised one from either.
 */
/**
 * Text around a handler that might carry its guard.
 *
 * `includeImports` decides whether the file's import statements count, and the two
 * callers want opposite answers.
 *
 * An import proves that a name is *available*, never that this handler used it. Fed
 * to `OBJECT_AUTHZ_GUARD` it silences the rule for every handler in the file as soon
 * as any one line imports `requireMembership` — which is the single commonest shape
 * a real object-ownership defect takes: one route in the file checks membership, the
 * route next to it forgot, and the file imports the helper because the careful route
 * needs it. holdout-5 contains exactly that, its author said so in as many words,
 * and this engine was silent on it.
 *
 * Fed to `IDENTITY_EVIDENCE` the same text is harmless, because that test only ever
 * *enables* a report: it establishes that the file is authenticated code at all, and
 * an import of `requireSession` is fair evidence of that. So imports go to the
 * enabling test and not to the suppressing one.
 */
function surroundingText(context: RuleContext, chain: ts.Node[], includeImports: boolean): string {
  const parts: string[] = [];
  // Every level of the chain, because the guard can sit on any of them: a Fastify
  // route options object wraps the handler, a tRPC builder wraps the resolver, and
  // an Express registration wraps both inside an outer plugin function.
  for (const fn of chain) {
    // A decorator-routed handler declares its middleware above itself rather than
    // around itself: `@UseGuards(WorkspaceMemberGuard)` on the method or on the
    // class is the same statement Express writes as `app.use(...)`, and a walk that
    // only goes outwards through calls never sees it.
    for (const node of [fn, ...enclosingClasses(fn)]) {
      const decorators = (ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined) ?? [];
      for (const decorator of decorators) parts.push(decorator.getText(context.file.source));
    }
    let current: ts.Node | undefined = fn.parent;
    while (current && !ts.isSourceFile(current)) {
      if (ts.isCallExpression(current)) {
        parts.push(current.expression.getText(context.file.source));
        for (const argument of current.arguments) {
          if (argument === fn || containsNode(argument, fn)) continue;
          parts.push(argument.getText(context.file.source));
        }
      }
      current = current.parent;
    }
  }
  for (const statement of context.file.source.statements) {
    const text = statement.getText(context.file.source);
    if (text.length > 400) continue;
    // A registration applies the guard; an import only makes it reachable.
    if (/\.\s*(use|addHook|register|decorate)\s*\(/.test(text)) parts.push(text);
    else if (includeImports && ts.isImportDeclaration(statement)) parts.push(text);
  }
  return parts.join("  ");
}

/** The class declarations a handler sits inside, innermost first. */
function enclosingClasses(node: ts.Node): ts.Node[] {
  const found: ts.Node[] = [];
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isClassLike(current)) found.push(current);
    current = current.parent;
  }
  return found;
}

/**
 * The endpoint a sink belongs to.
 *
 * A tRPC procedure is addressed by its dotted path and has no HTTP method, so
 * prefixing one with a verb names an endpoint that does not exist. (`routeFor` in
 * `context.ts` always prefixes; that belongs upstream.)
 */
function routeOf(context: RuleContext, node: ts.Node): string | undefined {
  const hint = routeHintFor(context, node);
  if (!hint) return undefined;
  return formatRoute(hint.method, hint.path);
}

/* ---------------------------------------------------------------- corroboration */

/**
 * Evidence in the file that this collection's rows belong to somebody.
 *
 * Never a gate — a first-of-its-kind query has no sibling to compare against, and
 * requiring one would excuse exactly the single-endpoint file where this defect is
 * most common. It decides how strongly the finding is stated.
 */
function corroboration(lookup: Lookup, file: ParsedFile): string[] {
  const found: string[] = [];
  const owner = OWNER_COLUMN.exec(lookup.statement);
  if (owner) found.push(`the row it returns carries \`${owner[0]}\`, so these rows do belong to an account`);

  const collection = lookup.collection.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (collection.length >= 3) {
    const sibling = new RegExp(
      `\\b${collection}\\b[\\s\\S]{0,400}?(?:where\\b|where\\s*:)[\\s\\S]{0,200}?${OWNER_COLUMN.source}`,
      "i"
    );
    if (sibling.test(file.text)) {
      found.push(`another query on \`${lookup.collection}\` in this file does constrain the rows by owner`);
    }
  }
  return found;
}

/* --------------------------------------------------------------------- the rule */

export const recordScopedToCaller: Rule = {
  id: "record-not-scoped-to-caller",
  category: "broken_object_level_authorization",
  describes: "records addressed by identifier without being scoped to the authenticated subject",
  run(context: RuleContext) {
    const reported = new Set<number>();

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const scope = buildScope(context.file, call, context.taintedParameters);
      const chain = scope.functions;
      // A statement at module scope is initialisation, not a request handler.
      if (chain.length === 0) continue;

      const lookup = lookupAt(call, context, scope);
      if (!lookup) continue;
      if (predicateIsScoped(lookup)) continue;
      if (scopeProvenForCaller(lookup, chain)) continue;
      if (collectionScopedToCaller(call, scope)) continue;

      /*
       * The middleware the route was registered behind, wherever the registration is
       * written. A layered application puts `router.get(path, requireAuth, show)` in one
       * module and `show` in another, and read one file at a time the controller has no
       * identity and no guard. `engine/handlers.ts` carries both across.
       */
      const gate = registrationGate(context.file, chain);
      const gateNames = gate ? gate.names.join("  ") : "";

      // Without an established identity there is no ownership relationship to get
      // wrong: an anonymous endpoint is a different finding, from a different rule.
      const handlers = chain.map((fn) => fn.getText(context.file.source)).join("  ");
      if (
        !IDENTITY_EVIDENCE.test(`${handlers}  ${surroundingText(context, chain, true)}  ${gateNames}`) &&
        !identityEstablished(scope) &&
        !gate?.authenticates
      ) {
        continue;
      }

      // A route that declares an object-level guard has done this check outside the
      // query. `requireUser` is not one of those; `requireProjectMember` is. Imports
      // are excluded here: see `surroundingText`.
      if (OBJECT_AUTHZ_GUARD.test(`${surroundingText(context, chain, false)}  ${gateNames}`)) continue;

      if (!recordReachesCaller(lookup, chain)) continue;
      if (ownershipChecked(lookup, chain)) continue;

      const line = lineOf(context.file, call);
      if (reported.has(line)) continue;
      reported.add(line);

      const support = corroboration(lookup, context.file);
      const verb = lookup.mutating ? "modified" : "read";
      const route = routeOf(context, call);

      context.report({
        ruleId: "record-not-scoped-to-caller",
        category: "broken_object_level_authorization",
        title: lookup.mutating
          ? `${lookup.collection} is modified by identifier without checking who owns it`
          : `${lookup.collection} is read by identifier without checking who owns it`,
        severity: lookup.mutating ? "critical" : "high",
        verification: support.length > 0 ? "strong_evidence" : "needs_review",
        summary:
          `This handler establishes who the caller is, then addresses a single row in \`${lookup.collection}\` ` +
          `using \`${lookup.identifier.getText(context.file.source)}\` — a value the caller supplies — as the only ` +
          `condition that selects it. The authenticated subject is not part of the predicate, nothing between the ` +
          `statement and the response compares the row's owner to that subject, and the row is ` +
          `${lookup.mutating ? "written to" : "returned to the caller"}. Changing the identifier in the request ` +
          `therefore addresses somebody else's record.` +
          (support.length > 0 ? ` Two details settle it: ${support.join("; and ")}.` : ""),
        impact: lookup.mutating
          ? `A signed-in user can alter another account's ${lookup.collection} row by changing one identifier in the request. Depending on the columns written that ranges from silently corrupting another tenant's data to escalating the attacker's own access, and it leaves no trace that distinguishes it from legitimate use.`
          : `A signed-in user can read another account's ${lookup.collection} row by changing one identifier in the request. Where the row carries contact details, financial figures, or document contents this is a data breach that needs no exploit — only a second account and a loop over identifiers.`,
        remediation:
          `Make ownership part of the statement rather than a step beside it: add the authenticated subject to the ` +
          `predicate so the row cannot be selected at all unless it belongs to the caller. Answer 404 rather than ` +
          `403 when the row exists but is not theirs, so the identifier space cannot be enumerated${
            support.length > 0 ? `, matching the scoping the neighbouring query already applies` : ""
          }.`,
        verificationPlan:
          `Create two accounts. As the first, ${lookup.mutating ? "submit this request against" : "request"} a ` +
          `\`${lookup.collection}\` identifier that belongs to the second${route ? ` on \`${route}\`` : ""}. The ` +
          `response must be 404 or 403 with no row in the body and no change to the row; the same request made by ` +
          `the owner must still succeed.`,
        taxonomy: ["CWE-639", "CWE-284", "OWASP-A01"],
        location: locationOf(context, call),
        ...(route ? { route } : {}),
        evidence: [
          sourceEvidence(
            context,
            call,
            `The row is ${verb} by identifier alone, in a handler that has already resolved who is calling.`
          ),
          {
            kind: "source",
            description: `The conditions that select the row are \`${lookup.predicate.text.trim().replace(/\s+/g, " ").slice(0, 160)}\` — no owner column among them, and no terminating ownership comparison follows.`,
            snippet: snippetAround(context.file, call, 1),
            location: `${context.file.relativePath}:${line}`
          }
        ],
        reasoning:
          `The route establishes an identity and declares no object-level guard. \`${lookup.collection}\` is ` +
          `addressed by a primary-key predicate whose value classifies as caller-supplied, the predicate names no ` +
          `owner column (projections and payloads excluded from that test), the row ` +
          `${lookup.mutating ? "is written" : "reaches the response"}, and no ownership comparison or ` +
          `identity-plus-identifier guard stops the handler.` +
          (support.length > 0 ? ` Corroborated by: ${support.join("; ")}.` : "")
      });
    }
  }
};
