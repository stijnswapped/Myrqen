import ts from "typescript";
import {
  calleeName,
  calleeTail,
  collect,
  dynamicParts,
  enclosingFunction,
  expressionName,
  isConstantString
} from "../ast/helpers.js";
import {
  analyzeFunction,
  functionsIn,
  HTML_ESCAPERS,
  isHtmlSafe,
  resolveExpression,
  taintOrigin,
  type TaintScope
} from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { describeSink, locationOf, sourceEvidence, taintEvidence, type Rule, type RuleContext } from "./context.js";

/** Calls that write a response body the browser may parse as HTML. */
const HTML_SINKS = new Set(["send", "write", "end", "html"]);

const HTML_MARKUP = /<\s*(html|body|div|span|h[1-6]|p|ul|li|table|script|a|img|form|input)\b|<\/\s*\w+\s*>/i;

export const reflectedXss: Rule = {
  id: "reflected-xss",
  category: "reflected_cross_site_scripting",
  describes: "caller-controlled data written into an HTML response without escaping",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);

      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        if (!HTML_SINKS.has(tail)) continue;

        // The markup can sit in any argument position: a project helper such as
        // `html(response, status, body)` is as common as `res.send(body)`.
        const body = call.arguments.find(
          (argument) => !isConstantString(argument) && HTML_MARKUP.test(argument.getText(context.file.source))
        );
        if (!body) continue;

        const origin = taintOrigin(body, scope);
        if (!origin) continue;

        // If every interpolated part went through an escaper, this is the safe
        // decoy shape and must not be reported.
        const parts = dynamicParts(body);
        const unescaped = parts.filter((part) => taintOrigin(part, scope) && !isHtmlSafe(part, scope));
        if (parts.length > 0 && unescaped.length === 0) continue;

        context.report({
          ruleId: "reflected-xss",
          category: "reflected_cross_site_scripting",
          title: `Caller-controlled data is interpolated into an HTML response by ${calleeName(call)}`,
          severity: "medium",
          verification: "strong_evidence",
          summary: `A value derived from ${origin} is placed into markup that is written to the response, with no escaping applied on the way. The caller therefore controls part of the document the browser parses.`,
          impact:
            "A crafted link executes script in the victim's session context, which allows session theft and any action the victim can perform.",
          remediation:
            "Escape the value before interpolation, or render through a template engine that escapes by default. A Content-Security-Policy is a useful second layer but is not the fix.",
          verificationPlan:
            "Request the page with a markup probe in the parameter and confirm the response contains only the escaped form.",
          taxonomy: ["CWE-79", "OWASP-A03"],
          location: locationOf(context, call),
          ...routeOf(context, call),
          evidence: [
            sourceEvidence(context, call, "The response body is markup built from caller input with no escaping call in the path."),
            taintEvidence(origin, describeSink(call))
          ],
          reasoning: `Taint from ${origin} reaches a markup-shaped response body; ${unescaped.length} interpolated part(s) had no escaper applied.`
        });
      }

      // A Response object is a sink too. An App Router handler that returns an
      // HTML fragment writes it through `new NextResponse(html, { headers })`,
      // never through a `send`-shaped call, so a rule keyed on method names is
      // blind to the whole framework.
      for (const constructed of collect(fn, ts.isNewExpression)) {
        const constructor = expressionName(constructed.expression);
        if (!/^(Next)?Response$/.test(constructor)) continue;
        const bodyArgument = constructed.arguments?.[0];
        if (!bodyArgument || isConstantString(bodyArgument)) continue;

        const init = constructed.arguments?.[1];
        if (!init || !/text\/html/i.test(init.getText(context.file.source))) continue;

        const document = resolveExpression(bodyArgument, scope);
        if (!HTML_MARKUP.test(document.getText(context.file.source))) continue;

        const reflected = reflectedParts(context, document, scope);
        if (reflected.length === 0) continue;

        const part = reflected[0]!;
        const origin = taintOrigin(part, scope)!;
        context.report({
          ruleId: "reflected-xss",
          category: "reflected_cross_site_scripting",
          title: `Caller-controlled data is interpolated into an HTML response returned by ${constructor}`,
          severity: "medium",
          verification: "strong_evidence",
          summary: `A value derived from ${origin} is interpolated into a document that this handler returns with an HTML content type, and nothing escapes it on the way. The caller therefore controls part of the markup the browser parses, in the application's own origin.`,
          impact:
            "A crafted link executes script in the victim's session context, which allows session theft and any action the victim can perform. A fragment endpoint is no safer than a page: whatever swaps it into the document runs it.",
          remediation:
            "Escape every interpolated value before it enters the markup, or build the fragment with a template engine that escapes by default. A Content-Security-Policy is a useful second layer but is not the fix.",
          verificationPlan:
            "Request the endpoint with a markup probe in the parameter and confirm the response body contains only the escaped form, then confirm the page that swaps the fragment in does not execute it.",
          taxonomy: ["CWE-79", "OWASP-A03"],
          location: locationOf(context, part),
          ...routeOf(context, constructed),
          evidence: [
            sourceEvidence(context, part, "This value is interpolated into the returned markup with no escaping applied."),
            taintEvidence(origin, `${constructor} with a text/html content type`)
          ],
          reasoning: `Taint from ${origin} reaches an interpolated slot of a markup document returned as text/html; no escaping call appears between the two.`
        });
        break;
      }

      // React's explicit escape hatch.
      for (const attribute of collect(fn, ts.isJsxAttribute)) {
        if (attribute.name.getText(context.file.source) !== "dangerouslySetInnerHTML") continue;
        const initializer = attribute.initializer;
        if (!initializer || !ts.isJsxExpression(initializer) || !initializer.expression) continue;
        // The attribute holds `{ __html: value }`, so the value to judge is the
        // property, not the object. Inspecting the object literal means every check
        // below is asking about the wrong node.
        const rendered = htmlProperty(context, initializer.expression) ?? initializer.expression;

        // Follow one binding: `const body = sanitizeHtml(entry.body, POLICY)` then
        // `__html: body` is the correct shape, and a rule that only inspects the
        // expression at the sink reports it as a defect.
        const resolved = resolveExpression(rendered, scope);
        if (isHtmlSafe(resolved, scope) || isHtmlSafe(rendered, scope)) continue;
        // A sanitiser call, whether written at the sink or one binding away, is the
        // documented fix for this exact escape hatch. Reporting it teaches a reader
        // that the rule cannot tell the difference, and they stop reading it.
        if (ts.isCallExpression(resolved) && isSanitiserCall(context, resolved)) continue;
        // The binding may be declared in a narrower scope than the one being
        // iterated — inside a `.map()` callback, for instance — in which case the
        // scope in hand cannot resolve it. Look the declaration up in the file.
        if (ts.isIdentifier(rendered) && sanitisedInFile(context, rendered.text)) continue;
        const origin = taintOrigin(rendered, scope);
        if (!origin && !/props|params|search|query|data|content|body/i.test(rendered.getText(context.file.source))) {
          continue;
        }
        // Severity is impact, not confidence. Where the file has no sanitiser at
        // all, the markup rendered here is whatever was stored — and stored
        // markup on a page every visitor loads runs for every visitor, which is
        // a materially worse outcome than a reflected link the attacker still
        // has to get somebody to click.
        const unsanitisedFile = !hasSanitiser(context);
        context.report({
          ruleId: "dangerous-inner-html",
          category: "stored_cross_site_scripting",
          title: "dangerouslySetInnerHTML renders a value that is not provably escaped",
          severity: unsanitisedFile ? "high" : "medium",
          verification: "needs_review",
          summary: unsanitisedFile
            ? "This element bypasses React's automatic escaping, and no HTML sanitiser appears anywhere in this file. Whatever the value holds is inserted into the document as markup, so if any of it was ever written by a user it becomes markup for everybody who loads this page."
            : "This element bypasses React's automatic escaping. Whether that is safe depends entirely on where the value comes from, and the engine could not prove it is sanitised in this file.",
          impact:
            "If any part of the value reaches this component from user-supplied content, an attacker controls markup in the rendered page and can execute script in the victim's session.",
          remediation:
            "Render the value as text so React escapes it, or sanitise it with a maintained HTML sanitiser immediately before this call and keep that call adjacent so the guarantee is visible.",
          verificationPlan:
            "Trace the value to its origin. If any path reaches it from stored or request data, insert a markup probe at that origin and confirm the rendered page shows it escaped.",
          taxonomy: ["CWE-79"],
          location: locationOf(context, attribute),
          ...routeOf(context, attribute),
          evidence: [sourceEvidence(context, attribute, "React escaping is explicitly bypassed here.")],
          reasoning: origin
            ? `Taint from ${origin} reaches dangerouslySetInnerHTML.`
            : "dangerouslySetInnerHTML receives a non-literal value whose origin could not be resolved in this file."
        });
      }
    }
  }
};

/** An error handler that returns the stack trace to the caller. */
export const verboseErrors: Rule = {
  id: "verbose-error-response",
  category: "verbose_error_response",
  describes: "error responses that disclose stack traces",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      for (const property of collect(fn, ts.isPropertyAssignment)) {
        const name = property.name.getText(context.file.source).replace(/['"]/g, "");
        if (!ERROR_DETAIL_FIELD.test(name)) continue;
        const value = property.initializer.getText(context.file.source);
        if (!/\.stack\b/.test(value)) continue;

        // Only report when the object is on its way into a response.
        if (!leavesInAResponse(context, property)) continue;

        context.report({
          ruleId: "verbose-error-response",
          category: "verbose_error_response",
          title: "Error responses include the stack trace",
          severity: "low",
          verification: "strong_evidence",
          summary:
            "The error handler serialises the stack trace into the response body, so every unhandled failure tells the caller where the code lives and how it is structured.",
          impact:
            "Stack traces disclose file paths, dependency versions, and internal structure, which shortens the work of finding a more serious issue.",
          remediation:
            "Return a generic message with a correlation identifier, and log the detail server-side where only operators can read it.",
          verificationPlan: "Trigger a handled failure and confirm the response body contains no stack or file paths.",
          taxonomy: ["CWE-209"],
          location: locationOf(context, property),
          ...routeOf(context, property),
          evidence: [sourceEvidence(context, property, "The response payload carries error.stack.")],
          reasoning: "A property named `stack` initialised from an error's stack is serialised into a response call."
        });
      }
    }
  }
};


/**
 * Interpolated slots that carry caller-controlled *text* into markup.
 *
 * Two kinds of slot are deliberately excluded, because including either turns
 * the correctly written version of this handler into a finding:
 *
 *  - a `.length` read, which is a number and cannot carry markup, and
 *  - a slot holding a fragment this file built itself, which is markup by
 *    intention and is judged where it is assembled rather than where it lands.
 */
function reflectedParts(context: RuleContext, document: ts.Node, scope: TaintScope): ts.Expression[] {
  const slots: ts.Expression[] = [];

  const consider = (part: ts.Expression): void => {
    // `a || b` and `a ?? b` each yield one of their operands whole.
    if (
      ts.isBinaryExpression(part) &&
      (part.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
        part.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
    ) {
      consider(part.left);
      consider(part.right);
      return;
    }
    if (isConstantString(part)) return;
    if (ts.isPropertyAccessExpression(part) && part.name.text === "length") return;
    if (!taintOrigin(part, scope)) return;
    if (isHtmlSafe(part, scope)) return;
    const resolved = resolveExpression(part, scope);
    if (isHtmlSafe(resolved, scope)) return;
    if (HTML_MARKUP.test(resolved.getText(context.file.source))) return;
    slots.push(part);
  };

  for (const part of dynamicParts(document)) consider(part);
  return slots;
}

/** Property names that carry an exception's internals. */
const ERROR_DETAIL_FIELD = /^(stack|stacktrace|stackTrace|trace|errorStack|stack_trace)$/i;

/**
 * Functions whose return value *is* the error body.
 *
 * Apollo's `formatError` and its equivalents never touch a response object:
 * whatever they return is serialised straight to the client. A rule that only
 * looks for a `send`-shaped call therefore sees nothing at all in the one place
 * a GraphQL server decides what to disclose.
 */
const ERROR_FORMATTER =
  /^(formatError|formatErrorResponse|formatResponse|errorFormatter|customFormatErrorFn|onError|errorHandler|toResponse|serializeError)$/;

/** Response objects a handler assigns its body to. */
const RESPONSE_BODY = /^(ctx|context|c|res|reply|response|event)\.(body|payload)$/;

/** The value of the `__html` property inside a dangerouslySetInnerHTML object. */
function htmlProperty(context: RuleContext, expression: ts.Expression): ts.Expression | null {
  if (!ts.isObjectLiteralExpression(expression)) return null;
  for (const property of expression.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    if (property.name.getText(context.file.source).replace(/["']/g, "") !== "__html") continue;
    return property.initializer;
  }
  return null;
}

/** Does this file bring an HTML sanitiser into scope at all? */
function hasSanitiser(context: RuleContext): boolean {
  return /sanitize-html|sanitizeHtml|DOMPurify|dompurify|isomorphic-dompurify|\bxss\b|escapeHtml|escapeHTML/.test(
    context.file.text
  );
}

/** Is every declaration of this name in the file a sanitiser call? */
function sanitisedInFile(context: RuleContext, name: string): boolean {
  let seen = false;
  for (const declaration of collect(context.file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
    const initializer = declaration.initializer;
    if (!initializer || !ts.isCallExpression(initializer) || !isSanitiserCall(context, initializer)) return false;
    seen = true;
  }
  return seen;
}

/** Is this call an HTML sanitiser? */
function isSanitiserCall(context: RuleContext, call: ts.CallExpression): boolean {
  const name = calleeName(call);
  const tail = calleeTail(call);
  if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail)) return true;
  // A project may wrap its sanitiser; the import tells us what it is.
  return /sanitiz|purif|\bxss\b|escape/i.test(name) && /sanitize-html|dompurify|xss|isomorphic-dompurify/i.test(context.file.text);
}

/**
 * Does this object reach the caller?
 *
 * Three ways, all of them common: it is an argument to a response-writing call,
 * it is assigned to the framework's response body, or it is returned from the
 * function the framework calls to shape an error. The last one is the reason
 * this is not a single `res.json` check.
 */
function leavesInAResponse(context: RuleContext, node: ts.Node): boolean {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isCallExpression(current)) {
      const tail = calleeTail(current);
      if (tail === "json" || tail === "send" || tail === "end" || tail === "write" || tail === "respond") return true;
      const name = calleeName(current);
      if (name === "Response.json" || name === "NextResponse.json") return true;
    }
    if (
      ts.isBinaryExpression(current) &&
      current.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      RESPONSE_BODY.test(expressionName(current.left))
    ) {
      return true;
    }
    if (ts.isReturnStatement(current)) {
      const holder = enclosingFunction(current)?.parent;
      if (holder && ts.isPropertyAssignment(holder)) {
        const key = holder.name.getText(context.file.source).replace(/["']/g, "");
        if (ERROR_FORMATTER.test(key)) return true;
      }
      if (holder && ts.isVariableDeclaration(holder) && ts.isIdentifier(holder.name)) {
        if (ERROR_FORMATTER.test(holder.name.text)) return true;
      }
    }
    current = current.parent;
  }
  return false;
}

