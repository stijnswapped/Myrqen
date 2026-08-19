import ts from "typescript";
import { collect, calleeTail, expressionName, walk } from "../ast/helpers.js";
import { lineOf, snippetAround, type ParsedFile } from "../ast/parse.js";
import { locationOf, routeHintFor, sourceEvidence, type Rule, type RuleContext } from "./context.js";
import {
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
  pathSegments,
  propertyKey,
  rootIdentifier,
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
  /** An owner column appears among the conditions. */
  namesOwner: boolean;
}

const EMPTY_PREDICATE: Predicate = { text: "", keyValues: [], ownerValues: [], namesOwner: false };

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
      if (PRIMARY_KEY_COLUMN.test(column)) keyValues.push(other);
      else if (OWNER_COLUMN.test(column)) ownerValues.push(other);
    }
  }
  if (keyValues.length === 0) return null;
  return {
    text: callback.getText(file.source),
    keyValues,
    ownerValues,
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
  let addressesOneRow = false;

  const condition = new RegExp(String.raw`\b(?:\w+\.)?(?<column>\w+)\s*=\s*${PLACEHOLDER}`, "gi");
  for (let match = condition.exec(where.text); match; match = condition.exec(where.text)) {
    const column = match.groups?.column ?? "";
    const value = boundValue(sql, where, match, values);
    if (PRIMARY_KEY_COLUMN.test(column)) {
      addressesOneRow = true;
      if (value) keyValues.push(value);
    } else if (OWNER_COLUMN.test(column) && value) {
      ownerValues.push(value);
    }
  }

  if (!addressesOneRow) return null;
  return { text: where.text, keyValues, ownerValues, namesOwner: OWNER_COLUMN.test(where.text) };
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

/** The table or collection this statement addresses, as a reader would name it. */
function collectionOf(call: ts.CallExpression, statement: string, file: ParsedFile): string {
  if (ts.isPropertyAccessExpression(call.expression)) {
    const receiver = expressionName(call.expression.expression);
    const tail = receiver.split(".").pop() ?? receiver;
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
function lookupAt(call: ts.CallExpression, context: RuleContext, scope: Scope): Lookup | null {
  const file = context.file;
  const tail = calleeTail(call).toLowerCase();
  const isRecordMethod = READ_ONE.has(tail) || WRITE_ONE.has(tail);
  const isRawStatement = RAW_STATEMENT.has(tail);
  const isInMemory = IN_MEMORY_LOOKUP.has(tail);
  if (!isRecordMethod && !isRawStatement && !isInMemory) return null;
  if (!isInMemory && !UNAMBIGUOUS_STORE_METHOD.has(tail) && !STORE_RECEIVER.test(call.expression.getText(file.source))) {
    // Without a store-shaped receiver, `map.get(key)` and `set.delete(value)` are
    // indistinguishable from a query by name alone.
    if (!isRawStatement) return null;
  }

  const chain = chainRoot(call);
  const statement = chain.getText(file.source);
  let predicate: Predicate | null = null;
  let sql: string | null = null;

  if (isInMemory) {
    predicate = callbackPredicate(call, file);
    if (!predicate) return null;
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
    for (const argument of call.arguments) {
      const resolved = unwrap(argument);
      if (ts.isObjectLiteralExpression(resolved)) conditions.push(...objectFilter(resolved, file));
    }
    // A builder chain states its conditions in `.where(...)`, away from the call
    // that names the table.
    if (chain !== call) {
      for (const inner of collect(chain, ts.isCallExpression)) {
        if (calleeTail(inner).toLowerCase() !== "where") continue;
        conditions.push(...inner.arguments);
      }
    }
    if (conditions.length === 0) return null;

    const pairs = conditions.flatMap((node) => filterPairs(node, file));
    const keyValues = pairs.filter((pair) => PRIMARY_KEY_COLUMN.test(pair.column)).map((pair) => pair.value);
    const ownerValues = pairs.filter((pair) => OWNER_COLUMN.test(pair.column)).map((pair) => pair.value);
    if (keyValues.length === 0) return null;
    const text = conditions.map((node) => node.getText(file.source)).join(", ");
    predicate = { text, keyValues, ownerValues, namesOwner: OWNER_COLUMN.test(text) };
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
  if (!lookup.predicate.namesOwner) return false;
  if (lookup.predicate.ownerValues.length === 0) return true;
  // An owner column compared to something the caller supplied is not a scope.
  return lookup.predicate.ownerValues.some((value) => classify(value, lookup.scope) !== "caller");
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
      const source = unwrap(declaration.initializer);
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
  return chain.some((fn) => reachesCallerWithin(lookup, fn));
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
    const takesIdentifier = call.arguments.some((argument) => {
      const root = rootIdentifier(argument);
      return Boolean(root && identifierRoot && root === identifierRoot);
    });
    if (!takesIdentifier) continue;
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
function surroundingText(context: RuleContext, chain: ts.Node[]): string {
  const parts: string[] = [];
  // Every level of the chain, because the guard can sit on any of them: a Fastify
  // route options object wraps the handler, a tRPC builder wraps the resolver, and
  // an Express registration wraps both inside an outer plugin function.
  for (const fn of chain) {
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
    if (ts.isImportDeclaration(statement) || /\.\s*(use|addHook|register|decorate)\s*\(/.test(text)) parts.push(text);
  }
  return parts.join("  ");
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
  if (hint.method === "ANY" || !hint.path.startsWith("/")) return hint.path;
  return `${hint.method} ${hint.path}`;
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
      const scope = buildScope(context.file, call);
      const chain = scope.functions;
      // A statement at module scope is initialisation, not a request handler.
      if (chain.length === 0) continue;

      const lookup = lookupAt(call, context, scope);
      if (!lookup) continue;
      if (predicateIsScoped(lookup)) continue;
      if (collectionScopedToCaller(call, scope)) continue;

      // Without an established identity there is no ownership relationship to get
      // wrong: an anonymous endpoint is a different finding, from a different rule.
      const around = surroundingText(context, chain);
      const handlers = chain.map((fn) => fn.getText(context.file.source)).join("  ");
      if (!IDENTITY_EVIDENCE.test(`${handlers}  ${around}`)) continue;

      // A route that declares an object-level guard has done this check outside the
      // query. `requireUser` is not one of those; `requireProjectMember` is.
      if (OBJECT_AUTHZ_GUARD.test(around)) continue;

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
