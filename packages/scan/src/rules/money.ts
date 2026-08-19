import ts from "typescript";
import { calleeTail, collect, enclosingFunction, literalTextOf, walk } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, resolveExpression, type TaintScope } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { locationOf, sourceEvidence, taintEvidence, type RuleContext } from "./context.js";

/* ------------------------------------------------------------------ *
 * Money that the caller should not be deciding
 *
 * Two defects live here, both of which read as ordinary code:
 *
 *  - the price a purchase settles at comes from the request rather than from
 *    the catalogue, and
 *  - a balance is read, checked, and written back in application code, so two
 *    concurrent requests both pass the check.
 *
 * Neither is a pattern match on a dangerous function. What makes each one a
 * defect is something the file does *not* contain, which is why they survive
 * review and why the rules below are written around the missing constraint.
 * ------------------------------------------------------------------ */

/**
 * Field names that carry a price rather than a quantity or a transfer amount.
 *
 * The distinction is deliberate and it is the whole precision story. A caller
 * naming an `amountCents` is ordinary — that is what a withdrawal, a transfer,
 * or a donation *is*. A caller naming a `unitPriceCents` or a `discountCents`
 * is deciding what the seller charges, which is never the caller's to decide.
 * `amount`, `balance`, `quantity` and a bare `cents` are therefore excluded,
 * and the cost of excluding them is stated in the report rather than hidden.
 */
const PRICE_TOKEN = new Set([
  "price",
  "prices",
  "pricing",
  "cost",
  "costs",
  "fee",
  "fees",
  "total",
  "totals",
  "subtotal",
  "discount",
  "rebate",
  "tariff",
  "msrp"
]);

/** Evidence that this function settles money rather than merely handling it. */
const SETTLEMENT =
  /\b(charge|charges|authorize|authorise|capture|payment|payments|paymentintent|checkout|refund|payout|invoice)\b/i;

/** Array methods whose callback receives one element of the receiver. */
const ELEMENT_CALLBACKS = new Map<string, number>([
  ["map", 0],
  ["forEach", 0],
  ["filter", 0],
  ["flatMap", 0],
  ["find", 0],
  ["findIndex", 0],
  ["findLast", 0],
  ["some", 0],
  ["every", 0],
  ["sort", 0],
  ["reduce", 1],
  ["reduceRight", 1]
]);

const COMPARISON_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.LessThanToken,
  ts.SyntaxKind.LessThanEqualsToken,
  ts.SyntaxKind.GreaterThanToken,
  ts.SyntaxKind.GreaterThanEqualsToken
]);

/** camelCase, snake_case and kebab-case split into lowercase words. */
function tokensOf(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+|\s+/)
    .filter(Boolean)
    .map((token) => token.toLowerCase());
}

function namesAPrice(name: string): boolean {
  return tokensOf(name).some((token) => PRICE_TOKEN.has(token));
}

/* ------------------------------------------------------------------ *
 * A stricter reading of "caller-controlled"
 *
 * The engine's taint model assumes an unknown function that receives
 * attacker-controlled data returns data influenced by it. That is the right
 * default for injection — a project's own normaliser must not end the flow —
 * but it is wrong for the question this rule asks. `findBySkus(skus)` is a
 * *lookup keyed by* caller input; what comes back is the catalogue, and the
 * catalogue is exactly the authority the caller is not allowed to override.
 * Treating its rows as caller data reports the correct implementation as the
 * defect.
 *
 * So this walks the same shapes with one difference: an unknown call breaks the
 * chain unless it was handed the request object itself, which is what a body
 * parser looks like and a repository lookup never does.
 * ------------------------------------------------------------------ */

/** Reads that hand back caller data whole. */
const READER_METHODS = new Set(["get", "getAll", "param", "header", "json", "text", "formData", "valid"]);

/** Calls that transform a value without changing whose value it is. */
const VALUE_PRESERVING = new Set([
  "String",
  "Number",
  "parseInt",
  "parseFloat",
  "BigInt",
  "trim",
  "toString",
  "toLowerCase",
  "toUpperCase",
  "normalize",
  "replace",
  "replaceAll",
  "slice",
  "substring",
  "split",
  "at",
  "concat",
  "decodeURIComponent",
  "decodeURI",
  "JSON.parse"
]);

/** Iteration that yields the receiver's own elements. */
const ITERATION_METHODS = new Set(["map", "filter", "flatMap", "slice", "concat", "sort", "reverse", "flat"]);

/** Callees that return the *server's* view of who is asking, never the request. */
const RESOLVES_SUBJECT = /auth|session|viewer|current|principal|identity|token|verify|login|signin/i;

/**
 * Request parameters that carry the caller's payload rather than the framework's
 * services. `ctx.pricing` and `ctx.db` hang off the same object as `ctx.params`,
 * and only one of the three is the caller's.
 */
const PAYLOAD_PARAMETER = /^(input|body|payload|form|formData|args|data)$/;

/** Properties of a request object that hold what the caller sent. */
const PAYLOAD_PROPERTY = new Set(["body", "query", "params", "searchParams", "input", "payload", "form", "data"]);

/** Is this identifier one of the handler's own request parameters? */
function isRequestParameter(name: string, scope: TaintScope): boolean {
  const root = scope.roots.get(name);
  return Boolean(root && root.declaration === scope.fn);
}

/** Why this expression is the caller's own value, or null when it is not. */
function callerValueOrigin(
  node: ts.Node,
  scope: TaintScope,
  elements: Set<string>,
  depth = 0
): string | null {
  if (depth > 8) return null;

  if (ts.isIdentifier(node)) {
    if (elements.has(node.text)) return `\`${node.text}\`, one element of a caller-supplied collection`;
    if (isRequestParameter(node.text, scope)) return `\`${node.text}\`, the inbound request`;
    const initializer = scope.initializers.get(node.text);
    return initializer ? callerValueOrigin(initializer, scope, elements, depth + 1) : null;
  }

  if (ts.isPropertyAccessExpression(node)) {
    // A property the server attached to the request is the application's own
    // data however deep the access goes.
    if (SERVER_ATTACHED.test(node.name.text)) return null;
    return callerValueOrigin(node.expression, scope, elements, depth + 1);
  }
  if (ts.isElementAccessExpression(node)) {
    return callerValueOrigin(node.expression, scope, elements, depth + 1);
  }

  if (
    ts.isAwaitExpression(node) ||
    ts.isParenthesizedExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node)
  ) {
    return callerValueOrigin(node.expression, scope, elements, depth + 1);
  }

  if (ts.isBinaryExpression(node)) {
    return (
      callerValueOrigin(node.left, scope, elements, depth + 1) ??
      callerValueOrigin(node.right, scope, elements, depth + 1)
    );
  }
  if (ts.isConditionalExpression(node)) {
    return (
      callerValueOrigin(node.whenTrue, scope, elements, depth + 1) ??
      callerValueOrigin(node.whenFalse, scope, elements, depth + 1)
    );
  }

  if (ts.isCallExpression(node)) {
    const tail = calleeTail(node);
    const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : undefined;

    if (receiver && (READER_METHODS.has(tail) || ITERATION_METHODS.has(tail))) {
      const origin = callerValueOrigin(receiver, scope, elements, depth + 1);
      if (origin) return origin;
    }
    if (VALUE_PRESERVING.has(tail)) {
      if (receiver) {
        const origin = callerValueOrigin(receiver, scope, elements, depth + 1);
        if (origin) return origin;
      }
      for (const argument of node.arguments) {
        const origin = callerValueOrigin(argument, scope, elements, depth + 1);
        if (origin) return origin;
      }
      return null;
    }

    // A body parser is handed the request object itself: `readJson(request)`,
    // `parseBody(req)`. A repository lookup is handed a value derived from it,
    // and what it returns is the server's record — which is the whole point of
    // the distinction this rule needs.
    if (RESOLVES_SUBJECT.test(node.expression.getText())) return null;
    for (const argument of node.arguments) {
      if (!ts.isIdentifier(argument)) continue;
      if (!isRequestParameter(argument.text, scope)) continue;
      return `\`${argument.text}\`, the inbound request body`;
    }
    return null;
  }

  return null;
}

/** Properties middleware attaches to a request; never the caller's own data. */
const SERVER_ATTACHED =
  /^(user|session|auth|viewer|account|actor|subject|state|locals|principal|identity|membership|tenant|workspace|db|log|logger)$/;

/**
 * May this expression stand as the *receiver* of a price read?
 *
 * A bare framework context is excluded: `ctx.priceList`, `c.pricing` and
 * `req.app` all read the server's own furniture off an object the engine calls
 * a request parameter, and reporting those would flag every correct handler in
 * a tRPC codebase.
 */
function isPriceBearingReceiver(node: ts.Node, scope: TaintScope, elements: Set<string>): boolean {
  if (ts.isIdentifier(node)) {
    if (elements.has(node.text)) return true;
    if (isRequestParameter(node.text, scope)) return PAYLOAD_PARAMETER.test(node.text);
    const initializer = scope.initializers.get(node.text);
    return initializer ? isPriceBearingReceiver(initializer, scope, elements) : false;
  }
  if (ts.isPropertyAccessExpression(node)) {
    if (PAYLOAD_PROPERTY.has(node.name.text)) return Boolean(callerValueOrigin(node, scope, elements));
    return isPriceBearingReceiver(node.expression, scope, elements) && !SERVER_ATTACHED.test(node.name.text);
  }
  if (
    ts.isAwaitExpression(node) ||
    ts.isParenthesizedExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node)
  ) {
    return isPriceBearingReceiver(node.expression, scope, elements);
  }
  if (ts.isElementAccessExpression(node)) return isPriceBearingReceiver(node.expression, scope, elements);
  if (ts.isCallExpression(node)) return Boolean(callerValueOrigin(node, scope, elements));
  return false;
}

/**
 * Local names bound to one element of a caller-controlled collection.
 *
 * `input.items.reduce((sum, item) => …)` and `for (const item of basket.items)`
 * both hand `item` straight from the request, and intra-procedural taint stops
 * at the callback boundary. Without this the most common shape of a basket —
 * a list of lines, each with its own price — is invisible.
 */
function callerElements(fn: ts.Node, scope: TaintScope): Set<string> {
  const names = new Set<string>();
  const body = (fn as ts.FunctionLikeDeclaration).body;
  if (!body) return names;

  // Two passes, because a collection may be recognised only after a binding it
  // feeds has been seen.
  for (let pass = 0; pass < 2; pass += 1) {
    walk(body, (node) => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const position = ELEMENT_CALLBACKS.get(node.expression.name.text);
        if (position === undefined) return;
        if (!callerValueOrigin(node.expression.expression, scope, names)) return;
        for (const argument of node.arguments) {
          if (!ts.isArrowFunction(argument) && !ts.isFunctionExpression(argument)) continue;
          const parameter = argument.parameters[position];
          if (parameter && ts.isIdentifier(parameter.name)) names.add(parameter.name.text);
        }
        return;
      }
      if (ts.isForOfStatement(node)) {
        if (!callerValueOrigin(node.expression, scope, names)) return;
        const declarations = ts.isVariableDeclarationList(node.initializer)
          ? node.initializer.declarations
          : undefined;
        const name = declarations?.[0]?.name;
        if (name && ts.isIdentifier(name)) names.add(name.text);
      }
    });
  }

  return names;
}

/** Is this read consumed only by a comparison? */
function onlyCompared(node: ts.Node): boolean {
  let current: ts.Node = node;
  let parent = current.parent;
  while (
    parent &&
    (ts.isParenthesizedExpression(parent) ||
      ts.isAsExpression(parent) ||
      ts.isNonNullExpression(parent) ||
      ts.isPrefixUnaryExpression(parent))
  ) {
    current = parent;
    parent = parent.parent;
  }
  if (!parent || !ts.isBinaryExpression(parent)) return false;
  return COMPARISON_OPERATORS.has(parent.operatorToken.kind);
}

interface PriceRead {
  node: ts.Node;
  field: string;
  origin: string;
}

/** Reads of a price-named field off caller-controlled data, in source order. */
function clientPriceReads(fn: ts.Node, scope: TaintScope, elements: Set<string>): PriceRead[] {
  const found: PriceRead[] = [];
  const seen = new Set<number>();

  const add = (node: ts.Node, field: string, receiver: ts.Node) => {
    if (seen.has(node.getStart())) return;
    if (onlyCompared(node)) return;
    const origin = callerValueOrigin(receiver, scope, elements);
    if (!origin) return;
    seen.add(node.getStart());
    found.push({ node, field, origin });
  };

  walk(fn, (node) => {
    if (ts.isPropertyAccessExpression(node)) {
      if (!namesAPrice(node.name.text)) return;
      if (!isPriceBearingReceiver(node.expression, scope, elements)) return;
      add(node, node.name.text, node.expression);
      return;
    }
    if (ts.isElementAccessExpression(node)) {
      const key = literalTextOf(node.argumentExpression);
      if (!key || !namesAPrice(key)) return;
      if (!isPriceBearingReceiver(node.expression, scope, elements)) return;
      add(node, key, node.expression);
      return;
    }
    // `formData.get("unitPriceCents")`, `searchParams.get("totalCents")`.
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const tail = node.expression.name.text;
      if (!READER_METHODS.has(tail)) return;
      const key = literalTextOf(node.arguments[0] ?? node);
      if (!key || !namesAPrice(key)) return;
      if (!isPriceBearingReceiver(node.expression.expression, scope, elements)) return;
      add(node, key, node.expression.expression);
    }
  });

  return found.sort((a, b) => a.node.getStart() - b.node.getStart());
}

/**
 * The price a purchase settles at, taken from the request.
 *
 * The catalogue is the only authority on what something costs. When the amount
 * charged is derived from a price the client sent, the customer sets their own
 * price, and the code looks completely ordinary while doing it — which is why
 * this survives both review and testing.
 */
export function reportClientControlledPricing(context: RuleContext): void {
  // `functionsIn` yields a handler and every callback inside it, so the same read
  // is visited more than once. Reporting it once keeps one defect to one finding.
  const reported = new Set<number>();
  for (const fn of functionsIn(context.file.source)) {
    if (ts.isSourceFile(fn)) continue;
    const text = fn.getText(context.file.source);
    // Only a flow that actually settles money is in scope. An admin screen that
    // writes a price to the catalogue is doing exactly its job.
    if (!SETTLEMENT.test(text)) continue;

    const scope = analyzeFunction(context.file, fn);
    const elements = callerElements(fn, scope);
    const reads = clientPriceReads(fn, scope, elements);
    if (reads.length === 0) continue;

    const first = reads[0]!;
    if (reported.has(first.node.getStart())) continue;
    reported.add(first.node.getStart());
    const fields = [...new Set(reads.map((read) => read.field))];

    context.report({
      ruleId: "client-controlled-pricing",
      category: "business_logic_price_manipulation",
      title: `The price this charge settles at comes from the request field \`${first.field}\``,
      severity: "high",
      verification: "strong_evidence",
      summary: `This handler settles a payment, and the amount it settles is built from ${fields.map((field) => `\`${field}\``).join(", ")} — ${fields.length > 1 ? "fields read" : "a field read"} off ${first.origin}, rather than from the price the catalogue holds. Whatever validation runs first constrains the shape of the number, not the caller's right to choose it.`,
      impact:
        "A caller who edits the submitted price buys at a price they picked — one cent, or zero. Where a discount or a negative value is accepted the order total inverts and the payment provider is asked to credit the customer. Nothing in the response distinguishes this from a normal purchase, so it is discovered in reconciliation rather than in monitoring.",
      remediation:
        "Load the authoritative price for each line from the product record inside this handler and compute the total from that alone. Treat any price the client sends as a display value only: compare it if you want to detect a stale basket, and reject the request when it disagrees, but never let it reach the amount that is charged.",
      verificationPlan:
        "Submit the same request twice, once unmodified and once with the price field reduced to 1. Confirm both produce the same order total and the same amount at the payment provider, or that the modified request is refused.",
      taxonomy: ["CWE-602", "CWE-841", "OWASP-A04"],
      location: locationOf(context, first.node),
      ...routeOf(context, first.node),
      evidence: [
        sourceEvidence(context, first.node, `A price-bearing field is read from caller-supplied data here.`),
        taintEvidence(first.origin, "the amount this handler charges")
      ],
      reasoning: `\`${first.field}\` is read from caller-controlled data inside a function that settles a payment, and the value is used rather than only compared against a server-side price.`
    });
  }
}

/* ------------------------------------------------------------------ *
 * Read-modify-write on a balance
 * ------------------------------------------------------------------ */

/** Statements that write a stored quantity back. */
const UPDATE_STATEMENT = /\bupdate\b[\s\S]*\bset\b/i;

/** Columns whose value is a countable resource two requests can race over. */
const LEDGER_COLUMN = /\b\w*(balance|credits?|tokens?|points|stock|inventory|funds|quota|seats?)\w*\b/i;

/** The application already serialises this work, so the race is handled. */
const SERIALISED =
  /\bBEGIN\b|\bCOMMIT\b|\$transaction|\.transaction\s*\(|withTransaction|SERIALIZABLE|FOR UPDATE|\bSELECT\b[\s\S]*\bFOR\s+UPDATE\b|pessimistic|\.lock\s*\(|advisory_lock/i;

/** A retried request resolves to the same outcome, so a double submit is safe. */
const IDEMPOTENT = /idempot|request[_-]?key|dedup|ON\s+CONFLICT|\bupsert\b/i;

/** Query-executing calls whose first argument is the statement. */
const STATEMENT_SINK = /^(query|execute|run|exec|\$?(query|execute)Raw(Unsafe)?)$/;

/**
 * A balance read in one statement and written back in another.
 *
 * The check and the write are correct in isolation; what is missing is anything
 * that makes them one operation. Two requests that interleave between the read
 * and the write both see the old balance, both pass the sufficiency check, and
 * the second write overwrites the first — the money leaves twice and the ledger
 * shows one debit.
 *
 * Static analysis cannot observe the interleaving, so this is reported as
 * needs_review: the evidence settles that nothing serialises the pair, not that
 * the race has been won.
 */
export function reportNonAtomicLedgerUpdate(context: RuleContext): void {
  for (const fn of functionsIn(context.file.source)) {
    if (ts.isSourceFile(fn)) continue;
    const scope = analyzeFunction(context.file, fn);
    // `db.transaction(async (tx) => …)` puts the read and the write inside a
    // callback whose own text says nothing about the transaction wrapping it, so
    // the guard has to be looked for in the enclosing scopes too.
    if (isSerialised(context, fn)) continue;

    for (const call of collect(fn, ts.isCallExpression)) {
      if (!STATEMENT_SINK.test(calleeTail(call))) continue;
      const statementArgument = call.arguments[0];
      if (!statementArgument) continue;
      const statement = resolveExpression(statementArgument, scope).getText(context.file.source);
      if (!UPDATE_STATEMENT.test(statement)) continue;

      const column = columnAssignedFrom(statement);
      if (!column || !LEDGER_COLUMN.test(column)) continue;

      // `SET balance_cents = balance_cents - $1` settles the arithmetic in the
      // database, which is the fix. Only a value computed in JavaScript and
      // handed back as a parameter has the gap.
      const computed = computedParameter(call);
      if (!computed) continue;

      // The write has to be paired with a read: this is a read-modify-write,
      // not a blind decrement.
      if (!readsColumnEarlier(fn, context, column, call)) continue;

      // A conditional update carries its own guard: the row only changes when it
      // still has the funds, and the row count says whether it did.
      if (new RegExp(`where[\\s\\S]*${column}\\s*[<>]=?`, "i").test(statement)) continue;

      context.report({
        ruleId: "non-atomic-ledger-update",
        category: "race_condition_double_spend",
        title: `\`${column}\` is read, checked, and written back without anything making the pair atomic`,
        severity: "high",
        verification: "needs_review",
        summary: `This handler selects \`${column}\`, compares it in application code, and then writes a new value computed in JavaScript. Between the read and the write there is no transaction, no row lock, and no idempotency key, so two requests that arrive together both read the same starting value and the second write overwrites the first rather than building on it.`,
        impact:
          "Two concurrent requests are both authorised against the same funds, so the resource is spent twice and the ledger records one deduction. In a wallet or payout flow this is a direct financial loss bounded only by how many requests an attacker can land inside the window, and it reconciles as a discrepancy rather than as an attack.",
        remediation:
          "Make the check and the write one statement: `UPDATE … SET " +
          `${column} = ${column} - $1 WHERE … AND ${column} >= $1\`` +
          ", and treat a row count of zero as insufficient funds. Where more than one row is involved, run the whole sequence inside a transaction with the row locked (`SELECT … FOR UPDATE`), and accept a caller-supplied idempotency key so a retried request resolves to the original outcome instead of a second one.",
        verificationPlan:
          "Drive this endpoint with two identical requests in flight at once, repeatedly, against a starting balance that only covers one. Confirm exactly one succeeds and that the final balance never goes negative. A single sequential request will always pass and proves nothing.",
        taxonomy: ["CWE-362", "CWE-367", "OWASP-A04"],
        location: locationOf(context, call),
        ...routeOf(context, call),
        evidence: [
          sourceEvidence(context, call, `\`${column}\` is written back from a value computed in application code.`),
          {
            kind: "source",
            description: `No transaction, row lock, or idempotency key appears anywhere in this handler, so nothing serialises the read against the write.`,
            location: `${context.file.relativePath}:${locationOf(context, call).line}`
          }
        ],
        reasoning: `A statement updating \`${column}\` receives a parameter computed by arithmetic in application code; the same column is selected earlier in this function; and the handler contains no transaction, lock, conditional predicate on \`${column}\`, or idempotency key.`
      });
      break;
    }
  }
}

/** Is this work serialised or made idempotent, here or by an enclosing scope? */
function isSerialised(context: RuleContext, fn: ts.Node): boolean {
  let current: ts.Node | undefined = fn;
  while (current) {
    const text = current.getText(context.file.source);
    if (SERIALISED.test(text) || IDEMPOTENT.test(text)) return true;
    current = enclosingFunction(current);
  }
  return false;
}

/** The column an `UPDATE … SET <column> = …` statement writes. */
function columnAssignedFrom(statement: string): string | null {
  const match = /\bset\b\s+([a-z_][a-z0-9_."]*)\s*=/i.exec(statement);
  return match ? match[1]!.replace(/"/g, "").split(".").pop()! : null;
}

/** Does a parameter of this call carry a value the application computed? */
function computedParameter(call: ts.CallExpression): boolean {
  const isArithmetic = (node: ts.Expression): boolean => {
    if (!ts.isBinaryExpression(node)) return false;
    return (
      node.operatorToken.kind === ts.SyntaxKind.MinusToken ||
      node.operatorToken.kind === ts.SyntaxKind.PlusToken ||
      node.operatorToken.kind === ts.SyntaxKind.AsteriskToken
    );
  };
  for (const argument of call.arguments.slice(1)) {
    if (ts.isArrayLiteralExpression(argument)) {
      for (const element of argument.elements) {
        if (!ts.isOmittedExpression(element) && isArithmetic(element)) return true;
      }
      continue;
    }
    if (isArithmetic(argument)) return true;
  }
  return false;
}

/** Is the same column selected earlier in this function? */
function readsColumnEarlier(fn: ts.Node, context: RuleContext, column: string, write: ts.CallExpression): boolean {
  let found = false;
  walk(fn, (node) => {
    if (found || !ts.isCallExpression(node)) return;
    if (node.getStart() >= write.getStart()) return;
    if (!STATEMENT_SINK.test(calleeTail(node))) return;
    const statement = node.arguments[0]?.getText(context.file.source) ?? "";
    if (!/\bselect\b/i.test(statement)) return;
    if (new RegExp(`\\b${column}\\b`, "i").test(statement)) found = true;
  });
  return found;
}
