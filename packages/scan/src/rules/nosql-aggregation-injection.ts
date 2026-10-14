import ts from "typescript";
import { calleeTail, collect, expressionName } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, resolveExpression, rootOf, taintOrigin } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * Query operators smuggled into an aggregation pipeline's `$match`, or JavaScript
 * into `$where`.
 *
 * `nosql-injection` reads the filter of `find`, `findOne`, `updateOne` and their
 * family. An aggregation's `$match` stage *is* a filter by another name, and it is
 * where search and reporting endpoints put the caller's criteria — so `{ $match: {
 * status: req.query.status } }` takes `status[$ne]=x` from a query string exactly as
 * `find` would, and was read by nothing. `Model.$where(text)` and a `$where` key in a
 * stage evaluate JavaScript on the server and are worse.
 *
 * Values from the path (`params`) are not counted: a path segment is always a
 * string, so it cannot carry an operator. Values coerced with `String()`, `Number()`
 * or an `ObjectId` constructor are scalars and are not counted either.
 */
const MONGO = /["'`](?:mongoose|mongodb)["'`]|\bmongoose\b|\.aggregate\(/;
const SCALAR_CASTS = /^(?:String|Number|parseInt|parseFloat|Boolean|ObjectId|Types\.ObjectId|mongoose\.Types\.ObjectId|new ObjectId|escapeRegExp|sanitize|mongoSanitize)$/;

export const nosqlAggregationInjection: Rule = {
  id: "nosql-aggregation-injection",
  category: "nosql_injection",
  describes: "caller objects reaching an aggregation $match stage, or caller text reaching $where",
  run(context: RuleContext) {
    if (!MONGO.test(context.file.text)) return;
    if (/sanitizeFilter['"]?\s*,\s*true|mongoSanitize\(|express-mongo-sanitize/.test(context.file.text)) return;
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);
      const objectCapable = (value: ts.Expression): string | null => {
        let current = value;
        while (ts.isAwaitExpression(current) || ts.isParenthesizedExpression(current) || ts.isAsExpression(current)) current = current.expression;
        if (ts.isCallExpression(current) && SCALAR_CASTS.test(expressionName(current.expression))) return null;
        if (ts.isNewExpression(current)) return null;
        if (ts.isTemplateExpression(current) || ts.isStringLiteralLike(current) || ts.isNumericLiteral(current)) return null;
        const origin = taintOrigin(current, scope);
        if (!origin) return null;
        // Judge where the value was read, not the origin's wording: a path segment is
        // always a string, so it cannot carry an operator.
        const read = `${current.getText()} ${resolveExpression(current, scope).getText()}`;
        if (/\bparams\b|\.param\(|pathParameters|getRouterParam/.test(read)) return null;
        // A tRPC procedure's \`input\` and a GraphQL resolver's \`args\` arrive through a
        // declared schema whose scalar fields cannot hold an object.
        const root = rootOf(current);
        if (root === "input" || root === "args") return null;
        return origin;
      };

      const report = (node: ts.Node, origin: string, how: string, critical: boolean): void => {
        const location = locationOf(context, node);
        if (reported.has(location.line)) return;
        reported.add(location.line);
        context.report({
          ruleId: "nosql-aggregation-injection",
          category: "nosql_injection",
          title: critical ? "Caller-controlled text is evaluated by a $where clause" : "A caller-supplied value can carry query operators into an aggregation $match",
          severity: critical ? "critical" : "high",
          verification: "strong_evidence",
          summary: `${how} The value comes from ${origin}, and a JSON body or a bracketed query string (\`status[$ne]=\`) delivers an object, not a string, so the caller can supply operators such as \`$ne\`, \`$gt\` or \`$regex\` instead of a value.`,
          impact: critical
            ? "Server-side JavaScript runs with the caller's text inside the database, which allows reading any document the query can reach and exhausting the server."
            : "The caller widens the stage to match documents they should not see — every tenant's records, every user's rows — or matches a credential without knowing it.",
          remediation:
            "Cast each criterion to the type it should be (`String(value)`, a validated enum, an `ObjectId`) before it enters the stage, or validate the whole query with a schema that only allows scalars. Never pass a caller object as a stage, and never build `$where` from request data — use operators instead.",
          verificationPlan:
            "Request the endpoint with the parameter sent as an operator object — `?status[$ne]=__none__` or a JSON body `{\"status\": {\"$ne\": null}}` — and confirm the response is rejected or matches only what the scalar value would.",
          taxonomy: critical ? ["CWE-943", "CWE-95", "OWASP-A03"] : ["CWE-943", "OWASP-A03"],
          location,
          ...routeOf(context, node),
          evidence: [
            sourceEvidence(context, node, how),
            { kind: "source", description: `Data flow: ${origin} reaches an aggregation stage without a scalar cast.` }
          ],
          reasoning: `Taint from ${origin} reaches ${critical ? "a $where clause" : "a $match stage"}; nosql-injection reads find-style filters and not aggregation pipelines.`
        });
      };

      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        if (tail === "$where" && call.arguments[0]) {
          const origin = taintOrigin(call.arguments[0], scope);
          if (origin) report(call, origin, "`$where` evaluates its argument as JavaScript on the database server.", true);
          continue;
        }
        if (tail !== "aggregate") continue;
        const pipeline = call.arguments[0];
        if (!pipeline || !ts.isArrayLiteralExpression(pipeline)) continue;
        for (const stage of pipeline.elements) {
          if (!ts.isObjectLiteralExpression(stage)) continue;
          for (const property of stage.properties) {
            if (!ts.isPropertyAssignment(property)) continue;
            const key = property.name.getText().replace(/["']/g, "");
            if (key !== "$match") continue;
            const value = property.initializer;
            if (!ts.isObjectLiteralExpression(value)) {
              const origin = objectCapable(value);
              if (origin) report(property, origin, "The whole `$match` stage is a caller-supplied object.", false);
              continue;
            }
            for (const criterion of value.properties) {
              if (ts.isSpreadAssignment(criterion)) {
                const origin = objectCapable(criterion.expression);
                if (origin) report(criterion, origin, "A caller-supplied object is spread into the `$match` stage.", false);
                continue;
              }
              if (!ts.isPropertyAssignment(criterion) && !ts.isShorthandPropertyAssignment(criterion)) continue;
              const criterionKey = criterion.name.getText().replace(/["']/g, "");
              const criterionValue = ts.isPropertyAssignment(criterion) ? criterion.initializer : criterion.name;
              if (criterionKey === "$where") {
                const origin = taintOrigin(criterionValue, scope);
                if (origin) report(criterion, origin, "`$where` in the stage evaluates its value as JavaScript.", true);
                continue;
              }
              if (criterionKey.startsWith("$")) continue;
              const origin = objectCapable(criterionValue);
              if (origin) report(criterion, origin, `The \`${criterionKey}\` criterion of the \`$match\` stage is taken from the request without a scalar cast.`, false);
            }
          }
        }
      }
    }
  }
};
