import ts from "typescript";
import { calleeTail, collect, expressionName, isConstantString } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, rootOf, taintOrigin } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { clearedByGuard, declarationFor } from "./browser-sources.js";
import { leadingLiteral } from "./client-dom-xss.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * A server redirect written without the word `redirect` in the destination's slot.
 *
 * `perimeter-open-redirect` reads the first argument of any `redirect()` call. Three
 * ordinary spellings put the destination somewhere else, and each was invisible:
 *
 *  - the header itself — `res.setHeader("Location", next)`, `res.writeHead(302, {
 *    Location: next })`, `headers.set("location", next)`, `c.header("Location", next)`,
 *    `ctx.set("Location", next)` — which is how a plain `node:http` server, a Worker,
 *    and half of every framework's middleware redirects;
 *  - Express's `res.location(next)` followed by a status;
 *  - a status first — `res.redirect(301, next)` in Express, `reply.redirect(302, next)`
 *    in Fastify 4 — where the other rule reads the number and finds it constant;
 *  - Next's `permanentRedirect(next)`, which is not spelled `redirect`.
 *
 * Disjoint from the other rule by construction: every sink here is one whose first
 * argument it would not read as a caller-controlled destination.
 */
const HEADER_SETTERS = new Set(["setHeader", "set", "header", "append", "setHeaders"]);
const NOT_A_RESPONSE = /^(?:map|cache|store|params|searchParams|url|query|form|formData|cookies|session|localStorage|sessionStorage)$/i;

export const locationHeaderRedirect: Rule = {
  id: "location-header-redirect",
  category: "open_redirect",
  describes: "caller-supplied destinations written to a Location header or a status-first redirect",
  run(context: RuleContext) {
    if (!/location|redirect|permanentRedirect/i.test(context.file.text)) return;
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);

      const consider = (node: ts.Node, destination: ts.Expression | undefined, sink: string): void => {
        if (!destination || isConstantString(destination)) return;
        if (pinned(destination)) return;
        const origin = taintOrigin(destination, scope);
        if (!origin) return;
        if (guarded(destination, node)) return;
        const location = locationOf(context, node);
        if (reported.has(location.line)) return;
        reported.add(location.line);
        context.report({
          ruleId: "location-header-redirect",
          category: "open_redirect",
          title: `A caller-supplied destination is written as the redirect target by ${sink}`,
          severity: "medium",
          verification: "strong_evidence",
          summary: `${sink} sends the browser to a value derived from ${origin}, and nothing on the way confines it to this site. A link to this endpoint therefore forwards the visitor wherever the link's author chose, from an address that starts with this application's own.`,
          impact:
            "A phishing link borrows this site's address and reputation, then lands the victim on an attacker's page — typically a copy of this sign-in. Where the redirect follows an OAuth or magic-link step, the destination can also receive a token in its query string.",
          remediation:
            "Accept only a same-site path: require a single leading `/`, reject `//` and `/\\`, or parse the value with `new URL(value, ownOrigin)` and compare its `origin` to your own before using it. Where the destinations are known, map a short key to a fixed path instead of accepting a URL.",
          verificationPlan:
            "Request the endpoint with the destination parameter set to `//example.org/` and to `https://example.org/`, without following redirects, and confirm the `Location` header stays on this origin.",
          taxonomy: ["CWE-601", "OWASP-A01"],
          location,
          ...routeOf(context, node),
          evidence: [
            sourceEvidence(context, node, `${sink} sets the redirect target; the value comes from ${origin} with no same-site check on the path.`),
            { kind: "source", description: `Data flow: ${origin} reaches ${sink} in the same function with no prefix, origin, or allowlist check.` }
          ],
          reasoning: `Taint from ${origin} reaches a redirect target set by ${sink}, whose destination slot is not the first argument of a redirect() call, so the open-redirect rule does not read it.`
        });
      };

      for (const call of collect(fn, ts.isCallExpression)) {
        if (directScope(call) !== fn) continue;
        const tail = calleeTail(call);
        const receiver = ts.isPropertyAccessExpression(call.expression) ? call.expression.expression : null;
        const receiverName = receiver ? expressionName(receiver) : "";
        const name = expressionName(call.expression);

        if (HEADER_SETTERS.has(tail) && receiver && !NOT_A_RESPONSE.test(receiverName.split(".").pop() ?? "")) {
          const header = call.arguments[0];
          if (header && ts.isStringLiteralLike(header) && header.text.toLowerCase() === "location") {
            consider(call, call.arguments[1], `${name}("${header.text}")`);
          }
          continue;
        }
        if (tail === "writeHead") {
          for (const argument of call.arguments.slice(1)) {
            if (!ts.isObjectLiteralExpression(argument)) continue;
            const value = locationProperty(argument);
            if (value) consider(call, value, `${name}() with a Location header`);
          }
          continue;
        }
        if (tail === "location" && receiver && /^(?:res|response|reply)$/.test(receiverName)) {
          consider(call, call.arguments[0], `${name}()`);
          continue;
        }
        if (tail === "redirect" && call.arguments.length >= 2 && ts.isNumericLiteral(call.arguments[0]!)) {
          consider(call, call.arguments[1], `${name}(${call.arguments[0]!.getText(context.file.source)}, …)`);
          continue;
        }
        if (ts.isIdentifier(call.expression) && call.expression.text === "permanentRedirect") {
          consider(call, call.arguments[0], "permanentRedirect()");
        }
      }
    }
  }
};

function locationProperty(object: ts.ObjectLiteralExpression): ts.Expression | null {
  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const key = property.name.getText().replace(/["']/g, "").toLowerCase();
    if (key === "location") return property.initializer;
  }
  return null;
}

/**
 * The destination's own text fixes it to this site or to one named site: a path
 * with at least one character after its leading slash, or a full origin.
 */
function pinned(destination: ts.Expression): boolean {
  // `${url.pathname}${url.search}`: a parsed URL's path, without its origin, is a path
  // on this site whatever address it was parsed from — the shape of rebuilding the
  // request's own address with one parameter changed.
  if (ts.isPropertyAccessExpression(leadingPart(destination)) && (leadingPart(destination) as ts.PropertyAccessExpression).name.text === "pathname") {
    return true;
  }
  const prefix = leadingLiteral(destination);
  if (prefix === null) return false;
  return /^\/[^/\\]/.test(prefix) || /^https?:\/\/[^/]+\//i.test(prefix) || /^[#?]/.test(prefix);
}

/** The first operand of a concatenation or template, unwrapped. */
function leadingPart(node: ts.Expression): ts.Expression {
  if (ts.isParenthesizedExpression(node)) return leadingPart(node.expression);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return leadingPart(node.left);
  if (ts.isTemplateExpression(node) && node.head.text.length === 0 && node.templateSpans[0]) return leadingPart(node.templateSpans[0].expression);
  return node;
}

/** A stopping `if` that tests the destination's shape before it is used. */
function guarded(destination: ts.Expression, use: ts.Node): boolean {
  const root = rootOf(destination);
  if (!root) return false;
  const identifier = collect(destination, ts.isIdentifier).find((candidate) => candidate.text === root);
  if (!identifier) return false;
  const declaration = declarationFor(identifier);
  return declaration ? clearedByGuard(declaration, use) : false;
}

function directScope(node: ts.Node): ts.Node {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (
      ts.isFunctionDeclaration(current) ||
      ts.isFunctionExpression(current) ||
      ts.isArrowFunction(current) ||
      ts.isMethodDeclaration(current) ||
      ts.isSourceFile(current)
    ) {
      return current;
    }
    current = current.parent;
  }
  return node.getSourceFile();
}
