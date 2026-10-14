import ts from "typescript";
import { calleeName, calleeTail, collect, enclosingFunction, isConstantString, literalTextOf, walk } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, resolveExpression, rootOf, type TaintScope } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { locationOf, sourceEvidence, taintEvidence, type RuleContext } from "./context.js";

/* ------------------------------------------------------------------ *
 * Money that the caller should not be deciding
 *
 * Three defects live here, all of which read as ordinary code:
 *
 *  - the price a purchase settles at comes from the request rather than from
 *    the catalogue,
 *  - a balance is read, checked, and written back in application code, so two
 *    concurrent requests both pass the check, and
 *  - a single-use thing — a gift card, a voucher, the last seat — is checked as
 *    unconsumed and then consumed by a write that does not repeat the check.
 *
 * None of them is a pattern match on a dangerous function. What makes each one
 * a defect is something the file does *not* contain, which is why they survive
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

/**
 * Names that hold an amount of money rather than a count of things.
 *
 * This set answers a different question from `PRICE_TOKEN`, and the two must not
 * be merged. `PRICE_TOKEN` asks "is the caller deciding what the seller
 * charges", which is why `amount` is excluded from it. This set asks "is the
 * arithmetic in front of me money arithmetic", where `amountCents` is exactly
 * what a running total is called. The caller's authority is still decided by the
 * operand; the destination only says the sum is money.
 */
const MONEY_TOKEN = new Set([
  "price",
  "prices",
  "cost",
  "costs",
  "fee",
  "fees",
  "total",
  "totals",
  "subtotal",
  "subtotals",
  "sum",
  "sums",
  "amount",
  "amounts",
  "charge",
  "charges",
  "due",
  "payable",
  "gross",
  "net",
  "quote",
  "quoted"
]);

/**
 * A cheap pre-check so the AST work below only runs on functions that talk about
 * money at all. Every shape this rule can report needs a price-named field, so a
 * function whose text never mentions one cannot produce a finding.
 */
const MENTIONS_A_PRICE = /price|pricing|cost|fee|total|subtotal|discount|rebate|tariff|msrp/i;

/** Arithmetic that builds an amount out of other amounts. */
const MONETARY_ARITHMETIC = new Set([
  ts.SyntaxKind.AsteriskToken,
  ts.SyntaxKind.PlusToken,
  ts.SyntaxKind.MinusToken
]);

/** Compound assignments that fold one more amount into a running total. */
const ACCUMULATING_ASSIGNMENT = new Set([
  ts.SyntaxKind.PlusEqualsToken,
  ts.SyntaxKind.MinusEqualsToken,
  ts.SyntaxKind.AsteriskEqualsToken
]);

/** Every operator that gives a value a name, including the accumulating ones. */
const ASSIGNMENT_OPERATORS = new Set([ts.SyntaxKind.EqualsToken, ...ACCUMULATING_ASSIGNMENT]);

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

function namesMoney(name: string): boolean {
  return tokensOf(name).some((token) => MONEY_TOKEN.has(token));
}

/** The binding an assignment writes to, or null when the target is computed. */
function assignedName(target: ts.Node): string | null {
  if (ts.isIdentifier(target)) return target.text;
  if (ts.isPropertyAccessExpression(target)) return target.name.text;
  if (ts.isElementAccessExpression(target)) return literalTextOf(target.argumentExpression);
  return null;
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

/** Does this call hand back the same value under a different representation? */
function isValuePreserving(node: ts.CallExpression, tail: string): boolean {
  return VALUE_PRESERVING.has(tail) || VALUE_PRESERVING.has(calleeName(node));
}

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
    // The dotted name is checked as well as the tail, because `JSON.parse` is
    // listed under its full name and is *the* way a body arrives outside
    // Express: an API Gateway or Worker handler reads `JSON.parse(event.body)`.
    // Matching only the tail lost the caller's payload at the first line of
    // every one of those handlers.
    if (isValuePreserving(node, tail)) {
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

/**
 * Is this read consumed only by a comparison?
 *
 * This is the discriminator that separates the correct implementation from the
 * defect, so it has to see the comparison however it is spelled. The submitted
 * price and the catalogue price rarely have the same runtime type — one came out
 * of JSON, the other out of a column — so the check is nearly always written
 * `Number(line.unitPriceCents) !== product.unitPriceCents`. A coercion changes
 * the representation and nothing else, so stepping out through it is what keeps
 * a handler that *refuses* a stale price from being reported as one that trusts
 * it.
 */
function onlyCompared(node: ts.Node): boolean {
  let current: ts.Node = node;
  let parent = current.parent;
  while (parent) {
    if (
      ts.isParenthesizedExpression(parent) ||
      ts.isAsExpression(parent) ||
      ts.isNonNullExpression(parent) ||
      ts.isPrefixUnaryExpression(parent)
    ) {
      current = parent;
      parent = parent.parent;
      continue;
    }
    // `Number(x) !== y` compares x. The coerced value is not stored, returned,
    // or charged: the call exists only so the two sides are comparable.
    if (
      ts.isCallExpression(parent) &&
      parent.arguments.includes(current as ts.Expression) &&
      isValuePreserving(parent, calleeTail(parent))
    ) {
      current = parent;
      parent = parent.parent;
      continue;
    }
    break;
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

/* ------------------------------------------------------------------ *
 * Deciding an amount is not always spelled "charge"
 *
 * The settlement vocabulary above finds the handler that calls the payment
 * provider, and misses the one that answers `POST /checkout/quote`. A quote is
 * not a lesser flow: the number it returns is the number the order is written
 * from, so a caller who names their own unit price there buys at that price a
 * request later. The same is true of the invoice line, the renewal preview, and
 * the shipping estimate.
 *
 * What those all have in common is not a word. It is that an amount of money is
 * *assembled* — multiplied by a quantity, folded into a running total — out of a
 * price. So the second way into this rule is the arithmetic itself, with the
 * authority question unchanged: the total is only a defect when one of the
 * numbers going into it is the caller's.
 * ------------------------------------------------------------------ */

/**
 * A sub-expression that is both named as a price and derived from the caller.
 *
 * Both halves are load-bearing. `product.unitPriceCents * quantity` names a
 * price and is correct, because the price came from the record the server
 * loaded; `line.quantity * 2` is the caller's and is correct, because a quantity
 * is the caller's to choose. Only the intersection is the defect.
 */
function callerPriceOperand(node: ts.Node, scope: TaintScope, elements: Set<string>): string | null {
  let found: string | null = null;
  walk(node, (inner) => {
    if (found) return;
    if (ts.isIdentifier(inner)) {
      // The `x` in `line.x` is a property name, not a binding; resolving it as
      // one would read an unrelated local that happens to share the name.
      const parent = inner.parent;
      if (parent && ts.isPropertyAccessExpression(parent) && parent.name === inner) return;
      if (parent && ts.isPropertyAssignment(parent) && parent.name === inner) return;
      if (!namesAPrice(inner.text)) return;
      if (!callerValueOrigin(inner, scope, elements)) return;
      found = inner.text;
      return;
    }
    if (ts.isPropertyAccessExpression(inner)) {
      if (!namesAPrice(inner.name.text)) return;
      if (!isPriceBearingReceiver(inner.expression, scope, elements)) return;
      found = inner.name.text;
      return;
    }
    if (ts.isElementAccessExpression(inner)) {
      const key = literalTextOf(inner.argumentExpression);
      if (!key || !namesAPrice(key)) return;
      if (!isPriceBearingReceiver(inner.expression, scope, elements)) return;
      found = key;
    }
  });
  return found;
}

/**
 * The money-named binding an arithmetic result is finally given.
 *
 * A total is seldom written in one expression: it is declared, accumulated in a
 * loop, or returned out of a `reduce` and named at the call site. Walking up
 * through the wrappers that only move the value along finds the name it lands
 * under, and that name is what says the arithmetic was money rather than a page
 * count or a retry budget.
 */
function monetaryDestination(node: ts.Node): string | null {
  let current: ts.Node = node;
  let parent = current.parent;
  for (let depth = 0; parent && depth < 12; depth += 1) {
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return namesMoney(parent.name.text) ? parent.name.text : null;
    }
    if (ts.isPropertyAssignment(parent)) {
      const name = ts.isIdentifier(parent.name) || ts.isStringLiteralLike(parent.name) ? parent.name.text : null;
      return name && namesMoney(name) ? name : null;
    }
    if (ts.isBinaryExpression(parent) && ASSIGNMENT_OPERATORS.has(parent.operatorToken.kind)) {
      const target = assignedName(parent.left);
      return target && namesMoney(target) ? target : null;
    }
    if (
      ts.isParenthesizedExpression(parent) ||
      ts.isAsExpression(parent) ||
      ts.isNonNullExpression(parent) ||
      ts.isConditionalExpression(parent) ||
      ts.isReturnStatement(parent) ||
      ts.isArrowFunction(parent) ||
      ts.isFunctionExpression(parent) ||
      // `Math.round(subtotal + shipping)` and `lines.reduce(…)` both keep the
      // amount an amount; the name it is stored under is one level further up.
      ts.isCallExpression(parent) ||
      (ts.isBinaryExpression(parent) && MONETARY_ARITHMETIC.has(parent.operatorToken.kind))
    ) {
      current = parent;
      parent = parent.parent;
      continue;
    }
    return null;
  }
  return null;
}

/**
 * Does this function build an amount of money out of a price the caller sent?
 *
 * Recognising the arithmetic rather than the vocabulary is what lets the rule
 * see a quote endpoint, a line-item loop, or an invoice preview. It stays narrow
 * because both ends are constrained: the value going in must be a caller-chosen
 * price, and the value coming out must be named as money.
 */
function assemblesMonetaryTotal(fn: ts.Node, scope: TaintScope, elements: Set<string>): boolean {
  let found = false;
  walk(fn, (node) => {
    if (found || !ts.isBinaryExpression(node)) return;
    const operator = node.operatorToken.kind;

    // `subtotalCents += unitPriceCents * quantity` — the running total names
    // itself, which is the shape a basket loop always takes.
    if (ACCUMULATING_ASSIGNMENT.has(operator)) {
      const target = assignedName(node.left);
      if (!target || !namesMoney(target)) return;
      if (!callerPriceOperand(node.right, scope, elements)) return;
      found = true;
      return;
    }

    if (!MONETARY_ARITHMETIC.has(operator)) return;
    if (!callerPriceOperand(node, scope, elements)) return;
    if (!monetaryDestination(node)) return;
    found = true;
  });
  return found;
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
    // Nothing here can fire without a price-named field, so a function that
    // never mentions one is skipped before any AST work happens.
    if (!MENTIONS_A_PRICE.test(text)) continue;

    const scope = analyzeFunction(context.file, fn);
    const elements = callerElements(fn, scope);
    const reads = clientPriceReads(fn, scope, elements);
    if (reads.length === 0) continue;

    // Only a flow that decides an amount is in scope. A handler settles money
    // when it calls the payment provider, and equally when it assembles the
    // amount that a later call will settle — a quote, an invoice line, a renewal
    // preview. An admin screen that writes a price to the catalogue does
    // neither: it stores the number rather than computing money from it, which
    // is exactly its job.
    const settles = SETTLEMENT.test(text);
    if (!settles && !assemblesMonetaryTotal(fn, scope, elements)) continue;

    const first = reads[0]!;
    if (reported.has(first.node.getStart())) continue;
    reported.add(first.node.getStart());
    const fields = [...new Set(reads.map((read) => read.field))];

    context.report({
      ruleId: "client-controlled-pricing",
      category: "business_logic_price_manipulation",
      title: settles
        ? `The price this charge settles at comes from the request field \`${first.field}\``
        : `The amount this handler quotes is computed from the request field \`${first.field}\``,
      severity: "high",
      verification: "strong_evidence",
      summary: `This handler ${settles ? "settles a payment, and the amount it settles" : "computes an amount of money, and that amount"} is built from ${fields.map((field) => `\`${field}\``).join(", ")} — ${fields.length > 1 ? "fields read" : "a field read"} off ${first.origin}, rather than from the price the catalogue holds. Whatever validation runs first constrains the shape of the number, not the caller's right to choose it.`,
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
        taintEvidence(first.origin, settles ? "the amount this handler charges" : "the amount this handler computes")
      ],
      reasoning: `\`${first.field}\` is read from caller-controlled data inside a function that ${settles ? "settles a payment" : "assembles an amount of money out of it"}, and the value is used rather than only compared against a server-side price.`
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
/**
 * The statement a query call runs, wherever its text actually lives.
 *
 * Two forms, and the rule used to read only the first:
 *
 *     pool.query("update wallets set balance_cents = $1 where id = $2", [next, id])
 *     debitWallet.run(amountCents, walletId)
 *
 * The second is a prepared handle — `const debitWallet = db.query("update …")` at
 * module scope — and its call site carries no SQL at all. Reading argument 0 there
 * finds a number, concludes there is no statement, and switches the rule off for
 * every codebase that prepares its statements once, which is the shape performance
 * advice tells people to write.
 */
function statementTextFor(call: ts.CallExpression, scope: TaintScope, context: RuleContext): string {
  const direct = call.arguments[0];
  if (direct) {
    const text = resolveExpression(direct, scope).getText(context.file.source);
    if (/\b(update|select|insert|delete)\b/i.test(text)) return text;
  }
  if (ts.isPropertyAccessExpression(call.expression)) {
    const handle = preparedStatementText(call.expression.expression, context);
    if (handle) return handle;
    return resolveExpression(call.expression.expression, scope).getText(context.file.source);
  }
  return "";
}

/**
 * The statement a module-level prepared handle was built from.
 *
 * `resolveExpression` deliberately follows only module-level *string* constants,
 * because substituting an arbitrary initializer into an expression's text is how a
 * rule starts reasoning about code that is not there. A prepared handle is the one
 * shape worth resolving anyway, and it is resolved narrowly: a `const` at module
 * scope whose initializer is a call taking a constant string. That is
 * `db.query("update …")`, `db.prepare("update …")`, and nothing else.
 */
function preparedStatementText(receiver: ts.Node, context: RuleContext): string | null {
  if (!ts.isIdentifier(receiver)) return null;
  for (const statement of context.file.source.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== receiver.text) continue;
      const initializer = declaration.initializer;
      if (!initializer || !ts.isCallExpression(initializer)) return null;
      if (!/^(query|prepare|prepareStatement)$/.test(calleeTail(initializer))) return null;
      for (const argument of initializer.arguments) {
        if (isConstantString(argument)) return argument.getText(context.file.source);
      }
      return null;
    }
  }
  return null;
}

/**
 * Does this statement settle the arithmetic in the database?
 *
 * `set balance_cents = balance_cents - ?` is atomic on its own: two concurrent
 * decrements both apply. That is why the rule requires a value computed in
 * application code — except that atomic arithmetic is not the same as a *correct*
 * transition. The authorising comparison can still be sitting in application code:
 *
 *     if (wallet.balance_cents < amountCents) return problem(402, …);   // the check
 *     …
 *     debitWallet.run(amountCents, walletId);   // set balance = balance - ?, no predicate
 *
 * Both requests pass the check, both decrements apply, and the balance goes
 * negative. The correct sibling in the same service repeats the check in the
 * write — `where id = $wallet and balance_cents >= $amount` — which the caller
 * already skips on.
 */
function settlesArithmeticInDatabase(statement: string, column: string): boolean {
  return new RegExp(`set\\s+[\\w."]*${column}\\s*=\\s*[\\w."]*${column}\\s*[-+]`, "i").test(statement);
}

/**
 * Was the authorising comparison made in application code on the value that was
 * read?
 *
 * This is what separates a race from an ordinary counter. `views = views + 1` has
 * no check to lose; a balance that was read, compared, and then decremented does.
 * One level of aliasing is followed, because the comparison is frequently against
 * a derived quantity — `remaining = ceiling - committed; if (amount > remaining)`.
 */
function comparesColumnInApplicationCode(
  fn: ts.Node,
  scope: TaintScope,
  column: string,
  write: ts.CallExpression,
  context: RuleContext
): boolean {
  const mentions = (node: ts.Node, depth: number): boolean => {
    const text = node.getText(context.file.source);
    if (new RegExp(`\\b${column}\\b`, "i").test(text)) return true;
    if (depth >= 2) return false;
    let found = false;
    walk(node, (inner) => {
      if (found || !ts.isIdentifier(inner)) return;
      const initializer = scope.initializers.get(inner.text);
      if (initializer && mentions(initializer, depth + 1)) found = true;
    });
    return found;
  };

  let found = false;
  walk(fn, (node) => {
    if (found || !ts.isBinaryExpression(node)) return;
    if (node.getStart() >= write.getStart()) return;
    const operator = node.operatorToken.kind;
    if (
      operator !== ts.SyntaxKind.LessThanToken &&
      operator !== ts.SyntaxKind.GreaterThanToken &&
      operator !== ts.SyntaxKind.LessThanEqualsToken &&
      operator !== ts.SyntaxKind.GreaterThanEqualsToken
    ) {
      return;
    }
    if (mentions(node.left, 0) || mentions(node.right, 0)) found = true;
  });
  return found;
}

export function reportNonAtomicLedgerUpdate(context: RuleContext): void {
  // Two shapes of one defect, and one finding per function between them. The
  // arithmetic shape below and the state-transition shape further down overlap
  // on the handler that both decrements a balance and marks a row consumed, and
  // reporting that handler twice would describe one race as two.
  const reported = new Set<ts.Node>();
  reportLedgerReadModifyWrite(context, reported);
  reportSingleUseStateTransition(context, reported);
  // Last of the three. A chain that flips a status *and* adjusts a balance is one
  // race, and the state-transition rule describes it in the terms the developer
  // will recognise — reporting the balance as well would be the same defect twice.
  reportBuilderLedgerUpdate(context, reported);
}

/**
 * A read-modify-write spelled as a fluent query builder.
 *
 * Drizzle and Kysely put the table in `.update(t)`, the new value in `.set({…})`
 * and the filter in `.where(…)`, so there is no statement string for the
 * string-based rule above to read:
 *
 *     await db.update(schema.giftCards)
 *       .set({ balanceCents: card.balanceCents - applied })   // computed in memory
 *       .where(eq(schema.giftCards.id, card.id));             // identity only
 *
 * The read-modify-write evidence is stronger here than in the string form and does
 * not need a text search: the new value is arithmetic *on a property of the row
 * that was read*, which is the whole shape. What is missing is any predicate
 * repeating that value, so two requests that both read the same balance both write
 * their own version of it and the second overwrites the first.
 */
function reportBuilderLedgerUpdate(context: RuleContext, reported: Set<ts.Node>): void {
  for (const fn of functionsIn(context.file.source)) {
    if (ts.isSourceFile(fn) || reported.has(fn)) continue;
    if (isSerialised(context, fn)) continue;

    for (const call of collect(fn, ts.isCallExpression)) {
      if (calleeTail(call) !== "where" || call.arguments.length === 0) continue;

      // Walk the chain this `.where` terminates, collecting the links that matter.
      let updates = false;
      let assignment: ts.PropertyAssignment | null = null;
      let root: ts.Node = call;
      while (ts.isCallExpression(root) && ts.isPropertyAccessExpression(root.expression)) {
        const link = root.expression.name.text;
        if (link === "update" || link === "set") {
          const outer: ts.CallExpression = root;
          if (link === "update" && outer.arguments.length > 0) updates = true;
          if (link === "set") {
            const argument = outer.arguments[0];
            if (argument && ts.isObjectLiteralExpression(argument)) {
              for (const property of argument.properties) {
                if (!ts.isPropertyAssignment(property)) continue;
                const value = property.initializer;
                if (!ts.isBinaryExpression(value)) continue;
                const operator = value.operatorToken.kind;
                if (
                  operator !== ts.SyntaxKind.MinusToken &&
                  operator !== ts.SyntaxKind.PlusToken &&
                  operator !== ts.SyntaxKind.AsteriskToken
                ) {
                  continue;
                }
                assignment = property;
              }
            }
          }
        }
        root = root.expression.expression;
      }
      if (!updates || !assignment) continue;

      const column = ts.isIdentifier(assignment.name)
        ? assignment.name.text
        : ts.isStringLiteralLike(assignment.name)
          ? assignment.name.text
          : null;
      if (!column || !LEDGER_COLUMN.test(column)) continue;

      // The new value has to be arithmetic on the row's own previous value. A
      // `set({ balanceCents: input.amount * 2 })` is a different defect and is not
      // this rule's to report.
      const columnPattern = new RegExp(`\\.\\s*${column}\\b`, "i");
      if (!columnPattern.test(assignment.initializer.getText(context.file.source))) continue;

      /*
       * A filter that carries anything beyond the row's identity already makes the
       * write conditional, and the builder hands back the rows it changed:
       *
       *     .where(and(eq(t.id, row.id), eq(t.status, "active")))
       *     .returning({ id: t.id });
       *     if (spent.length === 0) return alreadyRedeemed();
       *
       * That is a compare-and-swap. The second request changes no rows and the
       * handler finds out. So the test is not "does the filter repeat this column"
       * but "does the filter say anything other than which row" — a narrower rule
       * would report the guarded form, which is the one that got this right.
       */
      const filter = call.arguments.map((argument) => argument.getText(context.file.source)).join(" ");
      // The leaf of each dotted path, not every segment: `schema.vouchers.id` names
      // the column `id`, and counting `vouchers` as a predicate would make every
      // filter look conditional.
      const namesOnlyIdentity = [...filter.matchAll(/(?:[A-Za-z_][A-Za-z0-9_]*\.)+([A-Za-z_][A-Za-z0-9_]*)/g)]
        .map((match) => match[1]!)
        .every((property) => /^(id|uuid|.*_id|.*Id)$/.test(property));
      if (!namesOnlyIdentity) continue;

      context.report({
        ruleId: "non-atomic-ledger-update",
        category: "race_condition_double_spend",
        title: `\`${column}\` is read, computed in application code, and written back with a filter that only names the row`,
        severity: "high",
        verification: "needs_review",
        summary: `This handler reads a row, computes a new \`${column}\` in JavaScript from the value it read, and writes it with a builder whose filter selects the row by identity alone. Nothing serialises the read against the write — no transaction, no row lock, no predicate repeating the value that was checked — so two requests that arrive together both read the same starting value and the second write overwrites the first rather than building on it.`,
        impact:
          "Two concurrent requests are both authorised against the same funds, so the resource is spent twice and the ledger records one deduction. In a wallet, gift-card, or stock flow this is a direct loss bounded only by how many requests an attacker can land inside the window, and it reconciles as a discrepancy rather than as an attack.",
        remediation: `Settle the arithmetic in the database and make the check part of the write: \`set({ ${column}: sql\\\`\${table}.${column} - \${amount}\\\` })\` with a filter that also requires \`${column}\` to still be sufficient, and treat a row count of zero as insufficient. Where more than one table changes, run the sequence inside the builder's transaction with the row locked, and accept an idempotency key so a retried request resolves to the original outcome.`,
        verificationPlan: `Drive this endpoint with two identical requests in flight at once, repeatedly, from a starting \`${column}\` that only covers one. Confirm exactly one succeeds and that the final value never goes negative. A single sequential request will always pass and proves nothing.`,
        taxonomy: ["CWE-362", "CWE-367", "OWASP-A04"],
        location: locationOf(context, assignment),
        ...routeOf(context, call),
        evidence: [
          sourceEvidence(
            context,
            assignment,
            `\`${column}\` is written back from a value computed in application code.`
          ),
          {
            kind: "source",
            description:
              "The builder's filter names the row and nothing else, so the write applies whatever the value read earlier turned out to be.",
            location: `${context.file.relativePath}:${locationOf(context, call).line}`
          }
        ],
        reasoning: `A fluent \`update(...).set(...)\` assigns \`${column}\` from arithmetic on the row's own previous value; the filter repeats no predicate on \`${column}\`; and the handler contains no transaction, lock, or idempotency key.`
      });
      reported.add(fn);
      break;
    }
  }
}

function reportLedgerReadModifyWrite(context: RuleContext, reported: Set<ts.Node>): void {
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
      const statement = statementTextFor(call, scope, context);
      if (!UPDATE_STATEMENT.test(statement)) continue;

      const column = columnAssignedFrom(statement);
      if (!column || !LEDGER_COLUMN.test(column)) continue;

      /*
       * Two ways the pair fails to be atomic, and the rule used to read only the
       * first.
       *
       * A value computed in JavaScript and handed back as a parameter loses the
       * second write entirely. Arithmetic settled in the database does not — but
       * it still loses the *check*, when the comparison that authorised the write
       * stayed in application code and was not repeated in the predicate. The
       * second form is what the corrected sibling of every pair here fixes by
       * adding `and balance_cents >= $amount` to the WHERE.
       */
      const computed = computedParameter(call);
      const checkLeftBehind =
        settlesArithmeticInDatabase(statement, column) &&
        comparesColumnInApplicationCode(fn, scope, column, call, context);
      if (!computed && !checkLeftBehind) continue;

      // The write has to be paired with a read: this is a read-modify-write,
      // not a blind decrement.
      if (!readsColumnEarlier(fn, context, column, call, scope)) continue;

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
      reported.add(fn);
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
function readsColumnEarlier(
  fn: ts.Node,
  context: RuleContext,
  column: string,
  write: ts.CallExpression,
  scope: TaintScope
): boolean {
  let found = false;
  walk(fn, (node) => {
    if (found || !ts.isCallExpression(node)) return;
    if (node.getStart() >= write.getStart()) return;
    if (!STATEMENT_SINK.test(calleeTail(node)) && calleeTail(node) !== "get") return;
    // The read is a prepared handle as often as it is an inline statement, so the
    // same resolution the write uses applies here.
    const statement = statementTextFor(node, scope, context);
    if (!/\bselect\b/i.test(statement)) return;
    if (new RegExp(`\\b${column}\\b`, "i").test(statement)) found = true;
  });
  return found;
}

/* ------------------------------------------------------------------ *
 * Check-then-act on something that may only be spent once
 *
 * The rule above needs arithmetic in order to see anything. The wider and more
 * expensive form of the same defect has none: a gift card, a voucher, a
 * single-use invite or the last seat is read, its state is inspected and found
 * unconsumed, and the consumption is then written by a statement that never
 * mentions the state the decision rested on. Every line is correct on its own.
 * What is absent is the link between the check and the act, so two requests that
 * overlap between them both observe the unconsumed state and both write the
 * consumption — and the instrument pays out twice while the row records one use.
 *
 * The correct version of the same handler puts the state it checked into the
 * predicate of the write, so exactly one of two concurrent requests matches a
 * row and the other is refused on a row count of zero. That single difference —
 * a predicate carrying the guard's own column — is what this rule decides on.
 *
 * Read-then-write is the shape of most application code, so three conditions
 * hold the precision and all three are required. The read must be a *guard*: a
 * branch on a state column whose failing side leaves the handler. The write must
 * change *that same column*, which is what makes it the act the guard
 * authorised rather than an unrelated update. And the thing being consumed must
 * be spendable — money, a countable resource, or a bearer instrument — because
 * two editors who both publish a draft have raced and lost nothing.
 *
 * The shape is recognised in three dialects, because which one a project uses is
 * an accident of its stack and the defect is identical in all of them: a SQL
 * statement handed to any wrapper, a query-builder object with `where` and
 * `data`, and a builder chain that puts `.set()` and `.where()` in separate
 * calls. A rule that knew only raw SQL would be silent across most of the
 * modern JavaScript ecosystem.
 * ------------------------------------------------------------------ */

/**
 * States that a row passes through exactly once.
 *
 * A branch on one of these is a branch on a transition, not a filter. `status`
 * and `state` are here because they are how every schema spells the lifecycle of
 * a voucher, an order, or a payout; the consumption verbs are here because a
 * boolean column is spelled `redeemed` or `used` rather than `status`.
 */
const SINGLE_USE_STATE = new Set([
  "status",
  "state",
  "redeemed",
  "redemption",
  "used",
  "consumed",
  "claimed",
  "spent",
  "settled",
  "captured",
  "paid",
  "processed",
  "fulfilled",
  "reserved",
  "revoked",
  "void",
  "voided",
  "cancelled",
  "canceled",
  "expired",
  "remaining",
  "available",
  "active"
]);

/**
 * Columns whose value is worth racing for.
 *
 * This is the gate that keeps the rule off the ordinary lifecycle update. The
 * test is anchored so that a column merely *containing* a value word —
 * `total_count`, `pricing_tier` — does not pass as money.
 */
const SPENDABLE_COLUMN =
  /^\w*(balance|credit|debit|fund|point|token|voucher|coupon|stock|inventory|quota|seat|amount|cents|payout|payable|refund|redeem|redemption|allowance|entitlement)\w*$/i;

/**
 * Entities that hold a bearer instrument or an amount of money.
 *
 * A row in one of these is worth its face value to whoever holds it, which is
 * what makes a duplicated state transition a loss rather than an inconsistency.
 * Matched against the one table or model the write names, so the surface this
 * widens is a single identifier per statement.
 */
const SPENDABLE_ENTITY =
  /(gift[_-]?card|voucher|coupon|promo|redemption|redeem|credit|debit|wallet|balance|ledger|invite|invitation|referral|licen[cs]e|entitlement|allowance|quota|reward|bonus|payout|withdrawal|transfer|refund|payment|invoice|order|seat|reservation|inventory|stock|token|ticket|claim)/i;

/**
 * Idempotency the datastore will actually enforce.
 *
 * `IDEMPOTENT` above is deliberately generous, and for the arithmetic shape that
 * is the right trade. It is far too generous here: passing an `idempotency_key`
 * as one more column of an INSERT names a key without enforcing anything, and a
 * handler that does exactly that — echoing the client's retry header into the
 * receipt — is the one that pays the instrument out twice. Only a conflict
 * target, an upsert, or a lookup of the key before the work runs makes a retry
 * resolve to the first outcome instead of a second one.
 */
const IDEMPOTENCY_ENFORCED = /ON\s+CONFLICT|ON\s+DUPLICATE\s+KEY|\bupsert\b|\bmerge\s+into\b/i;

/** The name of a key whose earlier use is looked up to reject a replay. */
const IDEMPOTENCY_KEY = /idempotenc|request[_-]?key|dedup|\bnonce\b/i;

/**
 * A predicate that carries the row's version rather than its state.
 *
 * `WHERE id = $1 AND version = $2` is a compare-and-set written the other way
 * round: the update matches nothing once anyone else has touched the row, so the
 * second of two concurrent requests is refused even though the state column
 * itself does not appear. Missing this would report the optimistic-locking fix
 * as the bug.
 */
const OPTIMISTIC_PREDICATE = /\b\w*(version|revision|etag|xmin|updated_?at|modified_?at|lock_?token|row_?version)\w*\b/i;

/** `select … from <table>`, however many lines the statement is spread over. */
const SELECT_SOURCE = /\bselect\b[\s\S]*?\bfrom\s+([^\s;()]+)/i;

/** `update <table> set …`, which is the act half of a check-then-act pair. */
const UPDATE_TARGET = /\bupdate\s+([^\s;()]+)\s+set\b/i;

/**
 * Methods that read exactly one stored row.
 *
 * Deliberately only the unambiguous ones. A bare `get` or `load` is as likely to
 * be a cache or a config lookup as a row read, and the guard this rule needs has
 * to be a guard on stored state.
 */
const SINGLE_ROW_READ = new Set([
  "findUnique",
  "findUniqueOrThrow",
  "findFirst",
  "findFirstOrThrow",
  "findOne",
  "findById",
  "findByPk",
  "findOneBy",
  "findOneOrFail",
  "getRow"
]);

/** Methods that write a stored row through a query builder rather than SQL. */
const ROW_WRITE = new Set([
  "update",
  "updateOne",
  "updateMany",
  "findOneAndUpdate",
  "findByIdAndUpdate",
  "replaceOne",
  "save"
]);

/** Keys under which a builder call holds the rows it selects. */
const FILTER_KEY = /^(where|filter|query|criteria|conditions?)$/i;

/** Keys under which a builder call holds the values it writes. */
const DATA_KEY = /^(data|set|update|values|\$set|\$inc|\$unset|\$currentDate)$/i;

/** Keys under which a builder call names the columns it reads back. */
const PROJECTION_KEY = /^(select|columns|projection|attributes|fields)$/i;

/** A row this handler read, and what it read it from. */
interface RowBinding {
  /** The table or model, normalised so both sides of the pair can be compared. */
  entity: string;
  /** The columns the read named, when it named any. */
  columns: string[];
  /** How a reader would describe where the row came from. */
  described: string;
}

/** A guard on a single-use column of a row, whose failing branch leaves. */
interface StateGuard {
  row: RowBinding;
  column: string;
  node: ts.Node;
}

/** A write that changes stored state, in whichever dialect it was spelled. */
interface StateWrite {
  node: ts.CallExpression;
  entity: string;
  /** The columns this write assigns. */
  assigned: string[];
  /** The predicate deciding which rows change, as source text. */
  predicate: string;
  /** How the remediation should be phrased for this dialect. */
  sql: boolean;
}

/** `balanceCents` and `balance_cents` name the same column. */
function sameColumn(left: string, right: string): boolean {
  return tokensOf(left).join("_") === tokensOf(right).join("_");
}

/**
 * A table, model, or collection reduced to a comparable name.
 *
 * `"public"."gift_cards"`, `giftCards` and `gift_card` are the same entity as far
 * as pairing a read with a write is concerned, and requiring the two sides to
 * agree is most of what keeps this rule off unrelated updates. Plurals are
 * dropped for the same reason: a model is singular and its table is not.
 */
function entityName(raw: string): string {
  const bare = raw.replace(/[`"'[\]]/g, "");
  const last = bare.split(".").pop() ?? bare;
  return tokensOf(last)
    .map((token) => token.replace(/(?:ie)?s$/, (match) => (match === "ies" ? "y" : "")))
    .join("_");
}

/** Does this column name a state a row passes through only once? */
function isSingleUseState(column: string): boolean {
  return tokensOf(column).some((token) => SINGLE_USE_STATE.has(token)) || LEDGER_COLUMN.test(column);
}

/** Every bare word in a fragment of a query, for column comparisons. */
function wordsIn(text: string): string[] {
  return text.match(/[A-Za-z_][\w$]*/g) ?? [];
}

/** The columns an UPDATE's assignment list writes to. */
function assignedColumns(setList: string): string[] {
  const names: string[] = [];
  const pattern = /([A-Za-z_][\w$]*)\s*=(?!=)/g;
  let match: RegExpExecArray | null = pattern.exec(setList);
  while (match) {
    names.push(match[1]!);
    match = pattern.exec(setList);
  }
  return names;
}

/** The columns a SELECT statement reads, or an empty list when it uses `*`. */
function selectedColumns(statement: string): string[] {
  const match = /\bselect\b([\s\S]*?)\bfrom\b/i.exec(statement);
  return match ? wordsIn(match[1]!) : [];
}

/** The property names an object literal declares, one level of nesting deep. */
function objectKeys(node: ts.Node, depth = 0): string[] {
  if (depth > 2 || !ts.isObjectLiteralExpression(node)) return [];
  const keys: string[] = [];
  for (const property of node.properties) {
    if (ts.isShorthandPropertyAssignment(property)) {
      keys.push(property.name.text);
      continue;
    }
    if (!ts.isPropertyAssignment(property)) continue;
    const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : null;
    if (!name) continue;
    // A Mongo update nests the assignments one level down under `$set`, and a
    // rule that stopped at the top level would read the operator as the column.
    if (DATA_KEY.test(name)) keys.push(...objectKeys(property.initializer, depth + 1));
    else keys.push(name);
  }
  return keys;
}

/** The initialiser of one property of an object literal, when it has one. */
function propertyOf(node: ts.Node, matches: RegExp): ts.Expression | undefined {
  if (!ts.isObjectLiteralExpression(node)) return undefined;
  for (const property of node.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : null;
    if (name && matches.test(name)) return property.initializer;
  }
  return undefined;
}

/** The receiver of a method call, as the entity it addresses. */
function receiverEntity(call: ts.CallExpression): string | null {
  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const receiver = call.expression.expression;
  if (ts.isPropertyAccessExpression(receiver)) return entityName(receiver.name.text);
  if (ts.isIdentifier(receiver)) return entityName(receiver.text);
  return null;
}

/**
 * Does this expression run a SELECT? The wrapper's name is not the evidence.
 *
 * Every project puts its own helper in front of the driver — `one`, `first`,
 * `fetchRow`, `sql` — and a rule that recognises queries by callee name sees the
 * write and misses the read, which is exactly the pairing this shape is about.
 * The statement text is the evidence, and a call handed a string containing
 * `select … from` is a query whatever it is called.
 */
function rowRead(node: ts.Node, context: RuleContext, scope: TaintScope): RowBinding | null {
  let found: RowBinding | null = null;
  walk(node, (inner) => {
    if (found || !ts.isCallExpression(inner)) return;

    const first = inner.arguments[0];
    if (first) {
      const statement = resolveExpression(first, scope).getText(context.file.source);
      const match = SELECT_SOURCE.exec(statement);
      if (match) {
        found = {
          entity: entityName(match[1]!),
          columns: selectedColumns(statement),
          described: `a \`${entityName(match[1]!)}\` row read earlier in this function`
        };
        return;
      }
    }

    // `prisma.giftCard.findUnique({ where: … })`, `cards.findOne({ … })`.
    if (!SINGLE_ROW_READ.has(calleeTail(inner))) return;
    const entity = receiverEntity(inner);
    if (!entity) return;
    const projection = first ? propertyOf(first, PROJECTION_KEY) : undefined;
    found = {
      entity,
      columns: projection ? objectKeys(projection) : [],
      described: `a \`${entity}\` record read earlier in this function`
    };
  });
  return found;
}

/**
 * The locals that hold a row this handler read, and the columns pulled off one.
 *
 * Both maps are needed because both spellings are ordinary. `const card = await
 * one(SELECT …)` names the row; `const { status } = card` names the column and
 * loses the row, and the guard is then written against the bare name. Aliasing
 * is followed one hop — `const member = held.rows[0]` — because the
 * node-postgres shape always takes that hop.
 */
function selectedRows(
  fn: ts.Node,
  context: RuleContext,
  scope: TaintScope
): { rows: Map<string, RowBinding>; columns: Map<string, { row: RowBinding; column: string }> } {
  const rows = new Map<string, RowBinding>();
  const columns = new Map<string, { row: RowBinding; column: string }>();

  // Two passes, because an alias is only sometimes declared after the binding it
  // copies has already been recognised.
  for (let pass = 0; pass < 2; pass += 1) {
    for (const declaration of collect(fn, ts.isVariableDeclaration)) {
      const initializer = declaration.initializer;
      if (!initializer) continue;

      const aliasRoot = rootOf(initializer);
      const alias = aliasRoot ? rows.get(aliasRoot) : undefined;
      const binding = rowRead(initializer, context, scope) ?? alias;
      if (!binding) continue;

      if (ts.isIdentifier(declaration.name)) {
        rows.set(declaration.name.text, binding);
        continue;
      }
      if (!ts.isObjectBindingPattern(declaration.name)) continue;
      for (const element of declaration.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        const column =
          element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
        // `const { rows } = await pool.query(SELECT …)` destructures the result
        // envelope rather than a column, so the name still holds the row.
        if (/^(rows?|records?|results?|data|items)$/i.test(column)) rows.set(element.name.text, binding);
        else columns.set(element.name.text, { row: binding, column });
      }
    }
  }

  return { rows, columns };
}

/** Does this branch leave the handler rather than fall through? */
function exitsHandler(node: ts.Node): boolean {
  let found = false;
  const visit = (inner: ts.Node) => {
    if (found) return;
    if (ts.isReturnStatement(inner) || ts.isThrowStatement(inner)) {
      found = true;
      return;
    }
    // A callback declared inside the branch returns from itself, not from the
    // handler, so its body says nothing about whether this branch exits.
    if (ts.isFunctionDeclaration(inner) || ts.isFunctionExpression(inner) || ts.isArrowFunction(inner)) return;
    inner.forEachChild(visit);
  };
  visit(node);
  return found;
}

/** Guards on a single-use column of a row, whose failing branch leaves. */
function stateGuards(
  fn: ts.Node,
  rows: Map<string, RowBinding>,
  columns: Map<string, { row: RowBinding; column: string }>
): StateGuard[] {
  const guards: StateGuard[] = [];
  for (const statement of collect(fn, ts.isIfStatement)) {
    if (!exitsHandler(statement.thenStatement)) continue;
    walk(statement.expression, (node) => {
      if (ts.isPropertyAccessExpression(node)) {
        const root = rootOf(node.expression);
        const row = root ? rows.get(root) : undefined;
        if (row && isSingleUseState(node.name.text)) guards.push({ row, column: node.name.text, node: statement });
        return;
      }
      if (!ts.isIdentifier(node)) return;
      const bound = columns.get(node.text);
      if (bound && isSingleUseState(bound.column)) {
        guards.push({ row: bound.row, column: bound.column, node: statement });
      }
    });
  }
  return guards;
}

/**
 * The write this call performs, in whichever dialect the project speaks.
 *
 * Three spellings, one meaning. A SQL string names its table, its assignments
 * and its predicate in one place. A query-builder object splits them into
 * `where` and `data` properties. A builder chain splits them across `.set()` and
 * `.where()` calls on either side of the one that names the table. Normalising
 * all three to the same triple is what lets a single discriminator — does the
 * predicate carry the checked column — decide every one of them.
 */
function stateWrite(call: ts.CallExpression, context: RuleContext, scope: TaintScope): StateWrite | null {
  const source = context.file.source;
  const first = call.arguments[0];

  if (first) {
    const statement = resolveExpression(first, scope).getText(source);
    const match = UPDATE_TARGET.exec(statement);
    if (match) {
      const after = statement.slice(match.index + match[0].length);
      const whereAt = after.search(/\bwhere\b/i);
      return {
        node: call,
        entity: entityName(match[1]!),
        assigned: assignedColumns(whereAt === -1 ? after : after.slice(0, whereAt)),
        predicate: whereAt === -1 ? "" : after.slice(whereAt),
        sql: true
      };
    }
  }

  // `db.update(giftCards).set({ status }).where(eq(giftCards.id, id))` — the
  // table is named by the call in the middle of the chain, so neither the
  // receiver of `.set` nor the receiver of `.where` identifies it on its own.
  // This is tried before the method list below, because `.set` earns its place
  // only when an enclosing `update(<table>)` gives it a table to belong to.
  const tail = calleeTail(call);
  if (tail === "set" || tail === "update") {
    const chain = builderChain(call, source);
    if (chain) return chain;
  }
  if (!ROW_WRITE.has(tail)) return null;

  const entity = receiverEntity(call);
  if (!entity) return null;

  // `prisma.card.update({ where, data })` keeps both halves in one object;
  // `cards.updateOne(filter, { $set })` keeps them in two arguments.
  const structured = first ? propertyOf(first, FILTER_KEY) : undefined;
  const data = first ? propertyOf(first, DATA_KEY) : undefined;
  if (structured || data) {
    return {
      node: call,
      entity,
      assigned: data ? objectKeys(data) : [],
      predicate: structured ? structured.getText(source) : "",
      sql: false
    };
  }
  const second = call.arguments[1];
  if (!first || !second) return null;
  return {
    node: call,
    entity,
    assigned: objectKeys(second),
    predicate: first.getText(source),
    sql: false
  };
}

/** `db.update(table).set({…}).where(…)` reduced to the same triple. */
function builderChain(call: ts.CallExpression, source: ts.SourceFile): StateWrite | null {
  // Walk down to the `update(table)` call and back up to the `where(...)` one,
  // because the chain is a nested tree and the three parts sit at three depths.
  let updateCall: ts.CallExpression | null = null;
  let current: ts.Node = call;
  for (let depth = 0; depth < 6; depth += 1) {
    if (!ts.isCallExpression(current)) break;
    if (calleeTail(current) === "update" && current.arguments.length === 1) {
      updateCall = current;
      break;
    }
    if (!ts.isPropertyAccessExpression(current.expression)) break;
    current = current.expression.expression;
  }
  if (!updateCall) return null;

  const table = updateCall.arguments[0];
  if (!table) return null;
  const entity = ts.isIdentifier(table)
    ? entityName(table.text)
    : ts.isPropertyAccessExpression(table)
      ? entityName(table.name.text)
      : null;
  if (!entity) return null;

  let assigned: string[] = [];
  let predicate = "";
  let walker: ts.Node | undefined = call;
  for (let depth = 0; walker && depth < 6; depth += 1) {
    if (ts.isCallExpression(walker)) {
      const step = calleeTail(walker);
      const argument = walker.arguments[0];
      if (step === "set" && argument) assigned = objectKeys(argument);
      if (step === "where" && argument) predicate = argument.getText(source);
    }
    walker = ts.isCallExpression(walker) && ts.isPropertyAccessExpression(walker.expression)
      ? walker.expression.expression
      : undefined;
  }
  // The predicate is written on the outside of the chain, so the call this was
  // entered on may sit below it; take it from the statement instead.
  if (!predicate) {
    for (const outer of ancestorCalls(call)) {
      if (calleeTail(outer) !== "where") continue;
      const argument = outer.arguments[0];
      if (argument) predicate = argument.getText(source);
      break;
    }
  }
  if (assigned.length === 0) return null;
  return { node: call, entity, assigned, predicate, sql: false };
}

/** The calls this expression is an argument or receiver of, innermost first. */
function ancestorCalls(node: ts.Node): ts.CallExpression[] {
  const out: ts.CallExpression[] = [];
  let current: ts.Node | undefined = node.parent;
  for (let depth = 0; current && depth < 8; depth += 1) {
    if (ts.isCallExpression(current)) out.push(current);
    current = current.parent;
  }
  return out;
}

/**
 * Is losing this race a loss?
 *
 * A duplicated transition only costs something when the row carries value. The
 * three signals are the guarded column itself, the columns the read and the
 * write name, and the entity — any one of them is enough, and none is a free
 * pass, because the shape still has to hold around it.
 */
function isSpendable(guard: StateGuard, write: StateWrite): boolean {
  if (LEDGER_COLUMN.test(guard.column)) return true;
  if (guard.row.columns.some((column) => SPENDABLE_COLUMN.test(column))) return true;
  if (write.assigned.some((column) => SPENDABLE_COLUMN.test(column))) return true;
  return SPENDABLE_ENTITY.test(write.entity);
}

/** Does anything in this handler make a replayed request resolve to the first? */
function claimsIdempotencyKey(fn: ts.Node, context: RuleContext, scope: TaintScope): boolean {
  const text = fn.getText(context.file.source);
  if (IDEMPOTENCY_ENFORCED.test(text)) return true;
  // A lookup keyed on the client's token is a replay guard: there is no other
  // reason to select by it. The mention has to be inside a statement that reads,
  // which is what separates claiming a key from merely recording one.
  for (const call of collect(fn, ts.isCallExpression)) {
    const first = call.arguments[0];
    if (!first) continue;
    const statement = resolveExpression(first, scope).getText(context.file.source);
    if (SELECT_SOURCE.test(statement) && IDEMPOTENCY_KEY.test(statement)) return true;
    if (SINGLE_ROW_READ.has(calleeTail(call)) && IDEMPOTENCY_KEY.test(first.getText(context.file.source))) return true;
  }
  return false;
}

/**
 * A single-use state checked in application code and then written by a statement
 * that does not carry the check.
 *
 * Reported as needs_review, and honestly so: the evidence settles that nothing
 * links the guard to the write, not that two requests have ever interleaved
 * there. A reader with the schema in front of them can also see a unique
 * constraint this pass cannot, which is the other reason not to claim more.
 */
function reportSingleUseStateTransition(context: RuleContext, reported: Set<ts.Node>): void {
  for (const fn of functionsIn(context.file.source)) {
    if (ts.isSourceFile(fn) || reported.has(fn)) continue;
    const scope = analyzeFunction(context.file, fn);
    if (isSerialisedOrLocked(context, fn)) continue;
    if (claimsIdempotencyKey(fn, context, scope)) continue;

    const { rows, columns } = selectedRows(fn, context, scope);
    if (rows.size === 0 && columns.size === 0) continue;
    const guards = stateGuards(fn, rows, columns);
    if (guards.length === 0) continue;

    for (const call of collect(fn, ts.isCallExpression)) {
      const write = stateWrite(call, context, scope);
      if (!write) continue;

      // The act has to follow the check and has to change the same entity. An
      // update of an unrelated table is not the transition the guard
      // authorised, and requiring the two to agree is most of the precision.
      const applicable = guards.filter(
        (guard) => guard.row.entity === write.entity && call.getStart() > guard.node.getStart()
      );
      if (applicable.length === 0) continue;

      // A predicate that repeats *any* of the states this handler checked makes
      // the whole write a compare-and-set. The write is one statement, so one
      // condition on it serialises every assignment it carries: a redemption
      // filtered on `status = 'active'` cannot run twice, and the balance it
      // also writes is therefore safe. Testing this per guard instead reported
      // the correct implementation because a second guard's column happened not
      // to appear in the predicate.
      const predicateWords = wordsIn(write.predicate);
      if (applicable.some((guard) => predicateWords.some((column) => sameColumn(column, guard.column)))) continue;
      // A version column in the predicate is the same fix written the other way
      // round, and it protects the statement just as completely.
      if (OPTIMISTIC_PREDICATE.test(write.predicate)) continue;

      // Of the states that were checked, the one this write actually transitions
      // — and only when losing the race costs something.
      const guard = applicable.find(
        (candidate) =>
          write.assigned.some((column) => sameColumn(column, candidate.column)) && isSpendable(candidate, write)
      );
      if (guard) {
        const conditional = write.sql
          ? `\`UPDATE ${write.entity} SET … WHERE id = $1 AND ${guard.column} = <the state you checked>\``
          : `a conditional update whose filter repeats \`${guard.column}\` alongside the identifier`;

        context.report({
          ruleId: "non-atomic-state-transition",
          category: "race_condition_double_spend",
          title: `\`${guard.column}\` is checked on the row this handler read and then written back with nothing making the pair atomic`,
          severity: "high",
          verification: "needs_review",
          summary: `This handler reads ${guard.row.described}, decides in application code that \`${guard.column}\` still permits the operation, and then writes the new \`${guard.column}\` with a statement that selects the row by identity alone. Nothing carries the decision into the write: no transaction, no row lock, no predicate on \`${guard.column}\`, and no enforced idempotency key. Two requests that overlap between the check and the write both read the permitting state and both perform the transition.`,
          impact:
            "The row is consumed twice while recording one use, so whatever it entitles the holder to is granted twice — a gift card, voucher, or credit pays out on both requests, or the last unit of a limited resource is handed to two callers. A client that retries on a dropped connection reaches this without an attacker trying, and it surfaces in reconciliation rather than in monitoring, because both requests returned success.",
          remediation: `Make the check part of the write: ${conditional}, and treat a row count of zero as "already consumed" rather than assuming the update applied. Where several tables change together, run the sequence in a transaction with the row locked for update, and add a unique constraint on the natural key of the consumption so a second attempt fails in the datastore rather than succeeding in the application.`,
          verificationPlan: `Send two identical requests for the same \`${write.entity}\` row concurrently, repeatedly, from a state where only one may succeed. Confirm exactly one is accepted and that the downstream effect — the credit, the entitlement, the allocation — happens once. A sequential pair will always behave correctly and proves nothing.`,
          taxonomy: ["CWE-362", "CWE-367", "OWASP-A04"],
          location: locationOf(context, call),
          ...routeOf(context, call),
          evidence: [
            sourceEvidence(
              context,
              call,
              `\`${guard.column}\` is written here, and the predicate deciding which rows change does not include the value that was checked.`
            ),
            sourceEvidence(context, guard.node, `The decision to proceed is taken from the row read earlier in this function.`),
            {
              kind: "source",
              description: `No transaction, row lock, conditional predicate on \`${guard.column}\`, or enforced idempotency key appears in this handler, so nothing serialises the check against the write.`,
              location: `${context.file.relativePath}:${locationOf(context, call).line}`
            }
          ],
          reasoning: `A guard on \`${guard.column}\` of a \`${write.entity}\` row read earlier in this function exits the handler when the state disallows the operation; a later write assigns \`${guard.column}\` on the same entity with a predicate that mentions neither it nor a version column; and the handler contains no transaction, lock, or enforced idempotency key.`
        });
        reported.add(fn);
        break;
      }
    }
  }
}

/** Is the pair serialised by a transaction or a lock in this scope or above it? */
function isSerialisedOrLocked(context: RuleContext, fn: ts.Node): boolean {
  let current: ts.Node | undefined = fn;
  while (current) {
    if (SERIALISED.test(current.getText(context.file.source))) return true;
    current = enclosingFunction(current);
  }
  return false;
}
