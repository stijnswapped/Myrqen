import ts from "typescript";
import { calleeName, calleeTail, collect, dynamicParts, isConstantString } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, taintOrigin, valueTaintOrigin } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { reportClientControlledPricing, reportNonAtomicLedgerUpdate } from "./money.js";
import { describeSink, locationOf, sourceEvidence, taintEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * Functions that take a query, filter, or predicate expression as a string.
 * Not every datastore speaks SQL: an in-house `query(table, where)`, a Mongo
 * `$where`, and a JS predicate compiled at runtime are all the same bug, and a
 * scanner that only knows SELECT statements is blind to all three.
 */
const QUERY_LIKE = /^(query|find|filter|where|search|select|lookup|fetchRows|scan|aggregate|match|evaluate)$/i;

/** Composition into a real SQL statement belongs to the sql-injection rule. */
const SQL_KEYWORDS = /\b(select|insert|update|delete|drop|union)\b/i;

/** Parameter names that carry a caller-supplied query or predicate expression. */
const PREDICATE_PARAMETER = /^(where|predicate|filter|expression|expr|condition|clause|query|criteria)$/i;

export const unsafeQueryComposition: Rule = {
  id: "unsafe-query-composition",
  category: "unsafe_query_composition",
  describes: "caller-controlled data composed into a query or predicate expression",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);

      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        if (!QUERY_LIKE.test(tail)) continue;

        for (const argument of call.arguments) {
          if (isConstantString(argument)) continue;
          // Only string composition is in scope. An object filter or a bound
          // parameter array is the safe shape and must not be reported.
          const isComposed =
            ts.isTemplateExpression(argument) ||
            (ts.isBinaryExpression(argument) && argument.operatorToken.kind === ts.SyntaxKind.PlusToken) ||
            ts.isIdentifier(argument);
          if (!isComposed) continue;

          const text = argument.getText(context.file.source);
          if (SQL_KEYWORDS.test(text)) continue;

          const origin = taintOrigin(argument, scope);
          if (!origin) continue;

          // The value must actually be an expression rather than a plain term:
          // a search string passed as data is not a predicate.
          const parts = ts.isIdentifier(argument) ? resolvedParts(context, fn, argument) : dynamicParts(argument);
          const composed = ts.isIdentifier(argument) ? resolvedText(context, fn, argument) : text;
          if (!composed || !/[.()[\]=<>!&|]/.test(composed)) continue;
          if (parts.length === 0) continue;

          context.report({
            ruleId: "unsafe-query-composition",
            category: "unsafe_query_composition",
            title: `Caller-controlled data is composed into the query expression passed to ${calleeName(call)}`,
            severity: "high",
            verification: "strong_evidence",
            summary: `A value derived from ${origin} is interpolated into an expression string that ${calleeName(call)} interprets. The caller therefore controls the structure of the query, not only the value being matched, even though no SQL statement is involved.`,
            impact:
              "Depending on how the expression is evaluated, the caller can widen the query to return records they should not see, make it always true, or — where the expression is compiled as code — run arbitrary logic in the process.",
            remediation:
              "Pass the value as data rather than as part of the expression: build the predicate from a fixed set of comparisons and supply the caller's value as a bound argument. If a free-form expression is genuinely required, parse it into an allowlisted operator tree instead of evaluating the string.",
            verificationPlan:
              "Send a value containing an expression terminator and a tautology, and confirm the result set is unchanged and no evaluation error surfaces.",
            taxonomy: ["CWE-943", "CWE-89", "OWASP-A03"],
            location: locationOf(context, call),
            ...routeOf(context, call),
            evidence: [
              sourceEvidence(context, call, "The query expression is built by interpolation rather than passed as bound data."),
              taintEvidence(origin, describeSink(call))
            ],
            reasoning: `Taint from ${origin} reaches an interpolated expression argument of ${calleeName(call)}; the argument contains operator syntax and is not a bound parameter array.`
          });
          break;
        }
      }
    }
  }
};

/**
 * A helper that compiles one of its own parameters. Whether any caller passes
 * attacker data is a question for the caller, but the helper itself hands every
 * caller a code-execution primitive, which is worth stating on its own.
 */
export const dynamicPredicateCompilation: Rule = {
  id: "dynamic-predicate-compilation",
  category: "code_injection",
  describes: "a helper that compiles a parameter into executable code",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? ts.factory.createNodeArray([]);
      const predicateNames = parameters
        .map((parameter) => (ts.isIdentifier(parameter.name) ? parameter.name.text : null))
        .filter((name): name is string => name !== null && PREDICATE_PARAMETER.test(name));
      if (predicateNames.length === 0) continue;

      for (const node of [...collect(fn, ts.isCallExpression), ...collect(fn, ts.isNewExpression)]) {
        const name = ts.isCallExpression(node) ? calleeName(node) : node.expression.getText(context.file.source);
        if (!/^(eval|Function|vm\.(runInNewContext|runInThisContext|compileFunction))$/.test(name)) continue;

        const argumentText = (node.arguments ?? []).map((argument) => argument.getText(context.file.source)).join(" ");
        const used = predicateNames.find((parameter) => new RegExp(`\\$\\{\\s*${parameter}\\s*\\}|\\b${parameter}\\b`).test(argumentText));
        if (!used) continue;

        context.report({
          ruleId: "dynamic-predicate-compilation",
          category: "code_injection",
          title: `The \`${used}\` parameter is compiled as executable code`,
          severity: "high",
          verification: "strong_evidence",
          summary: `This helper embeds its \`${used}\` parameter into source passed to ${name}, so whatever any caller supplies becomes code that runs in this process. The helper cannot make that safe on its own: every call site is now responsible for the parameter never containing caller input.`,
          impact:
            "Any route that lets user input reach this parameter is remote code execution, and a route that does so today looks identical to one that does not.",
          remediation:
            "Compile the predicate from structured input instead of a string: accept a field, an operator from a fixed set, and a value, and build the comparison in code so nothing the caller sends is ever parsed as source.",
          verificationPlan:
            "Call the helper with a parameter containing a side effect and confirm it is not executed; then confirm every call site passes only values built in code.",
          taxonomy: ["CWE-94", "CWE-95", "OWASP-A03"],
          location: locationOf(context, node),
          evidence: [sourceEvidence(context, node, `The \`${used}\` parameter is interpolated into code given to ${name}.`)],
          reasoning: `Parameter \`${used}\` of this function appears inside the source argument of ${name}.`
        });
        break;
      }
    }
  }
};

/** Names that mean the value is money, or decides how much money moves. */
const MONETARY = /\b(total|amount|price|cost|sum|charge|balance|credit|refund|discount|subtotal|payable|fee|payout)\b/i;

/** Coercions that turn caller input into a number without bounding it. */
const NUMERIC_COERCION = new Set(["Number", "parseInt", "parseFloat", "BigInt"]);

/** Guards that bound a quantity. Any of these makes the arithmetic deliberate. */
const BOUND_GUARD =
  /(<=?\s*0|>=?\s*1|>\s*0|Number\.isInteger|Number\.isSafeInteger|Math\.max|Math\.min|Math\.abs|Math\.trunc|Math\.floor|clamp|\.min\(|\.max\(|\.positive\(|\.int\(|\.gt\(|\.gte\(|safeParse|\.parse\(|assert|validate)/;

/**
 * Caller-controlled quantities multiplied into a monetary total with nothing
 * bounding them. This is the class every price-manipulation write-up describes
 * and the one a pattern scanner never reports, because the code is ordinary
 * arithmetic — the defect is the missing constraint.
 */
export const unboundedMonetaryArithmetic: Rule = {
  id: "unbounded-monetary-arithmetic",
  category: "business_logic_price_manipulation",
  describes:
    "caller-controlled money: unbounded quantities, client-set prices, non-atomic debits, and single-use things consumed without a compare-and-set",
  run(context: RuleContext) {
    // Four ways a caller ends up deciding how much money moves. They share a
    // rule registration because they share a reader: whoever owns the checkout
    // and the ledger. `reportNonAtomicLedgerUpdate` covers two of them — the
    // arithmetic read-modify-write and the single-use state transition — and
    // reports one finding per handler across both, because a handler that
    // decrements a balance *and* marks the row spent has one race, not two.
    reportClientControlledPricing(context);
    reportNonAtomicLedgerUpdate(context);

    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);
      const body = (fn as ts.FunctionLikeDeclaration).body;
      if (!body) continue;

      for (const declaration of collect(fn, ts.isVariableDeclaration)) {
        if (!ts.isIdentifier(declaration.name)) continue;
        const target = declaration.name.text;
        if (!MONETARY.test(target)) continue;

        const initializer = declaration.initializer;
        if (!initializer || !ts.isBinaryExpression(initializer)) continue;
        const operator = initializer.operatorToken.kind;
        if (
          operator !== ts.SyntaxKind.AsteriskToken &&
          operator !== ts.SyntaxKind.MinusToken &&
          operator !== ts.SyntaxKind.PlusToken
        ) {
          continue;
        }

        // One operand must be caller-controlled. A total computed from two
        // server-side values is not this bug.
        const operands = [initializer.left, initializer.right];
        const controlled = operands.find((operand) => valueTaintOrigin(operand, scope));
        if (!controlled) continue;
        const origin = valueTaintOrigin(controlled, scope)!;
        const quantity = operandName(context, controlled);

        // A guard anywhere in the handler that bounds the quantity, or a
        // coercion that already constrains it, makes this deliberate.
        if (quantity && guardedIn(context, body, quantity)) continue;
        if (!quantity && BOUND_GUARD.test(body.getText(context.file.source))) continue;

        context.report({
          ruleId: "unbounded-monetary-arithmetic",
          category: "business_logic_price_manipulation",
          title: `Caller-controlled ${quantity ? `\`${quantity}\`` : "value"} determines \`${target}\` with no bound on its range`,
          severity: "high",
          verification: "needs_review",
          summary: `\`${target}\` is computed from ${origin} with no check that the caller's value is within the range the calculation assumes. Nothing here rejects a zero, a negative number, a fractional quantity, or a value large enough to overflow — the arithmetic simply proceeds.`,
          impact:
            "A caller who sends a negative or fractional quantity changes what they are charged, and in a system that credits the difference, turns a purchase into a payout. The route behaves exactly as designed, which is why this survives testing.",
          remediation:
            "Validate the quantity against the range the product actually allows — a positive integer, at or below the stock limit — and reject anything outside it before any monetary value is derived from it. Recompute the price server-side from the product record rather than trusting any amount the client sends.",
          verificationPlan:
            "Submit the request with a quantity of -1, then 0, then 0.5, then a value beyond available stock. Each must be refused before an order is created, and no order total may ever be negative.",
          taxonomy: ["CWE-840", "CWE-20", "OWASP-A04"],
          location: locationOf(context, declaration),
          ...routeOf(context, declaration),
          evidence: [
            sourceEvidence(context, declaration, "A monetary value is derived from a caller-supplied quantity."),
            taintEvidence(origin, `arithmetic assigned to \`${target}\``)
          ],
          reasoning: `\`${target}\` is initialised from an arithmetic expression with a tainted operand${quantity ? ` (\`${quantity}\`)` : ""}, and no range guard for it appears in the handler.`
        });
      }
    }
  }
};

/** The identifier a tainted operand ultimately reads from, when there is one. */
function operandName(context: RuleContext, node: ts.Node): string | null {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isCallExpression(node) && NUMERIC_COERCION.has(calleeName(node))) {
    const first = node.arguments[0];
    return first ? operandName(context, first) : null;
  }
  return null;
}

/** Does any statement in this handler bound the named quantity? */
function guardedIn(context: RuleContext, body: ts.Node, quantity: string): boolean {
  const escaped = quantity.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `(\\b${escaped}\\b[^;\\n]{0,60}(${BOUND_GUARD.source})|(${BOUND_GUARD.source})[^;\\n]{0,60}\\b${escaped}\\b)`
  );
  return pattern.test(body.getText(context.file.source));
}

/** The interpolated parts of the expression a local identifier was built from. */
function resolvedParts(context: RuleContext, fn: ts.Node, identifier: ts.Identifier): ts.Expression[] {
  for (const declaration of collect(fn, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== identifier.text) continue;
    if (!declaration.initializer) continue;
    return dynamicParts(declaration.initializer);
  }
  void context;
  return [];
}

/** The source text of the expression a local identifier was built from. */
function resolvedText(context: RuleContext, fn: ts.Node, identifier: ts.Identifier): string | null {
  for (const declaration of collect(fn, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== identifier.text) continue;
    if (!declaration.initializer) continue;
    return declaration.initializer.getText(context.file.source);
  }
  return null;
}
