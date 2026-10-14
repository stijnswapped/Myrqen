import ts from "typescript";
import { calleeName, calleeTail, collect, walk } from "../ast/helpers.js";
import { routeOf } from "./attribution.js";
import { declarationFor } from "./browser-sources.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * Credentialed CORS that admits every origin, in the spellings `perimeter-cors` does
 * not read.
 *
 * That rule reads an *inline* options object passed to `cors(...)`. Three ordinary
 * shapes fall outside it, and each produces the same policy — any site may make
 * credentialed requests and read the responses:
 *
 *  - an `origin` callback that approves unconditionally: `(origin, cb) => cb(null,
 *    true)`, or for Hono `(origin) => origin` / `() => true`. It neither echoes a
 *    literal list nor tests anything, and it is the commonest "fix" for a CORS error;
 *  - the options held in a constant: `app.use(cors(corsOptions))`;
 *  - the configurer is not called `cors`: Fastify's `app.register(fastifyCors, {...})`,
 *    NestJS's `app.enableCors({...})` and `NestFactory.create(AppModule, { cors })`.
 *
 * Reported only with `credentials: true`. Without credentials a permissive origin
 * exposes only what an anonymous request could already read, which is a policy
 * choice rather than a defect, and reporting it is how a rule earns being ignored.
 */
const INLINE_CONFIGURERS = /^(?:cors|fastifyCors|NextCors|corsMiddleware)$/;
const VALIDATING_CALLS = new Set(["includes", "has", "test", "match", "endsWith", "startsWith", "indexOf", "some", "find", "exec"]);

export const corsCredentialedAnyOrigin: Rule = {
  id: "cors-credentialed-any-origin",
  category: "insecure_cors_configuration",
  describes: "credentialed cross-origin access granted to every origin through a callback, a shared options constant, or a framework's own CORS switch",
  run(context: RuleContext) {
    if (!/cors/i.test(context.file.text)) return;
    const reported = new Set<number>();

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const name = calleeName(call);
      const tail = calleeTail(call);
      let options: ts.ObjectLiteralExpression | null = null;
      let inlineCors = false;

      if (ts.isIdentifier(call.expression) && INLINE_CONFIGURERS.test(call.expression.text)) {
        const first = call.arguments[0];
        if (!first) continue;
        inlineCors = ts.isObjectLiteralExpression(first);
        options = objectOf(first);
      } else if (tail === "register" && call.arguments[0] && /cors/i.test(call.arguments[0].getText(context.file.source))) {
        options = objectOf(call.arguments[1]);
      } else if (tail === "enableCors") {
        options = objectOf(call.arguments[0]);
      } else if (name === "NestFactory.create" && call.arguments[1]) {
        const app = objectOf(call.arguments[1]);
        const cors = app ? property(app, "cors") : null;
        options = cors ? objectOf(cors) : null;
      }
      if (!options) continue;
      if (!isTrue(property(options, "credentials"))) continue;

      const origin = property(options, "origin");
      if (!origin) continue;
      const verdict = anyOrigin(origin, inlineCors);
      if (!verdict) continue;

      const location = locationOf(context, call);
      if (reported.has(location.line)) continue;
      reported.add(location.line);
      context.report({
        ruleId: "cors-credentialed-any-origin",
        category: "insecure_cors_configuration",
        title: `Credentialed cross-origin requests are allowed from any origin by ${name}()`,
        severity: "high",
        verification: "strong_evidence",
        summary: `${verdict} and \`credentials\` is \`true\`, so the browser lets any website send requests with this application's cookies and read the responses. The origin check is the only thing that keeps another site from acting as the signed-in visitor, and here it approves everyone.`,
        impact:
          "A page on any domain, opened by a signed-in user, can call this API as that user and read what comes back — their data, tokens in responses, anything an authenticated GET returns — and perform state changes that rely on cookies.",
        remediation:
          "Compare the request's origin against a fixed list of the origins you serve (exact strings, or a regular expression anchored at both ends and at a label boundary), and pass `false` for anything else. Keep `credentials: true` only for that list.",
        verificationPlan:
          "Send an authenticated request with `Origin: https://example.org` and confirm the response does not carry `Access-Control-Allow-Origin: https://example.org` together with `Access-Control-Allow-Credentials: true`.",
        taxonomy: ["CWE-942", "CWE-346", "OWASP-A05"],
        location,
        ...routeOf(context, call),
        evidence: [sourceEvidence(context, call, `${verdict}; credentials are allowed.`)],
        reasoning: `The CORS options passed to ${name}() set credentials to true and an origin policy that approves every origin (${verdict.toLowerCase()}).`
      });
    }
  }
};

/**
 * Does this `origin` setting approve every origin? Returns a description, or null.
 *
 * Inline `cors({ origin: true, credentials: true })` is `perimeter-cors`'s finding, as
 * is a callback that echoes its argument there; only the unconditional-`true` callback
 * is claimed here for that spelling.
 */
function anyOrigin(origin: ts.Expression, inlineCors: boolean): string | null {
  if (!inlineCors && origin.kind === ts.SyntaxKind.TrueKeyword) return "The origin option is `true`, which reflects whatever origin a request sends";
  const fn = functionOf(origin);
  if (!fn) return null;
  const body = fn.body;
  if (!body || decides(body)) return null;
  const parameters = fn.parameters.map((parameter) => (ts.isIdentifier(parameter.name) ? parameter.name.text : null));
  const [originName, callbackName] = parameters;

  // (origin, callback) => callback(null, true)
  if (callbackName) {
    let approves: "true" | "echo" | null = null;
    walk(body, (node) => {
      if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== callbackName) return;
      const decision = node.arguments[1];
      if (!decision) return;
      if (decision.kind === ts.SyntaxKind.TrueKeyword) approves = "true";
      else if (ts.isIdentifier(decision) && decision.text === originName) approves ??= "echo";
    });
    if (approves === "true") return "The origin callback approves every request unconditionally";
    if (approves === "echo" && !inlineCors) return "The origin callback hands back whatever origin the request sent, without testing it";
    return null;
  }

  // Hono: origin: (origin) => origin, or () => true
  const returned = returnedValue(body);
  if (!returned) return null;
  if (returned.kind === ts.SyntaxKind.TrueKeyword) return "The origin function returns `true` for every request";
  if (!inlineCors && ts.isIdentifier(returned) && returned.text === originName) {
    return "The origin function returns whatever origin the request sent, without testing it";
  }
  return null;
}

/** Does the body make any decision at all? A body that tests nothing approves everyone. */
function decides(body: ts.Node): boolean {
  let decision = false;
  walk(body, (node) => {
    if (decision) return;
    if (ts.isIfStatement(node) || ts.isConditionalExpression(node) || ts.isSwitchStatement(node)) decision = true;
    if (ts.isBinaryExpression(node) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.EqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken, ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken].includes(node.operatorToken.kind)) {
      decision = true;
    }
    if (ts.isCallExpression(node) && VALIDATING_CALLS.has(calleeTail(node))) decision = true;
  });
  return decision;
}

function returnedValue(body: ts.ConciseBody): ts.Expression | null {
  if (!ts.isBlock(body)) return body;
  const returns = collect(body, ts.isReturnStatement);
  if (returns.length !== 1) return null;
  return returns[0]!.expression ?? null;
}

function functionOf(node: ts.Expression): ts.FunctionLikeDeclaration | null {
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) return node;
  if (ts.isMethodDeclaration(node as ts.Node)) return node as unknown as ts.MethodDeclaration;
  if (ts.isIdentifier(node)) {
    const declaration = declarationFor(node);
    if (declaration && ts.isFunctionDeclaration(declaration)) return declaration;
    if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) {
      const init = declaration.initializer;
      if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return init;
    }
  }
  return null;
}

function objectOf(node: ts.Expression | undefined): ts.ObjectLiteralExpression | null {
  if (!node) return null;
  if (ts.isObjectLiteralExpression(node)) return node;
  if (ts.isIdentifier(node)) {
    const declaration = declarationFor(node);
    if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) {
      let init = declaration.initializer;
      while (ts.isAsExpression(init) || ts.isSatisfiesExpression(init) || ts.isParenthesizedExpression(init)) init = init.expression;
      if (ts.isObjectLiteralExpression(init)) return init;
    }
  }
  return null;
}

function property(object: ts.ObjectLiteralExpression, key: string): ts.Expression | null {
  for (const element of object.properties) {
    if (ts.isPropertyAssignment(element) && element.name.getText().replace(/["']/g, "") === key) return element.initializer;
    if (ts.isShorthandPropertyAssignment(element) && element.name.text === key) return element.name;
    if (ts.isMethodDeclaration(element) && element.name.getText() === key) return element as unknown as ts.Expression;
  }
  return null;
}

function isTrue(node: ts.Expression | null): boolean {
  return Boolean(node && node.kind === ts.SyntaxKind.TrueKeyword);
}

