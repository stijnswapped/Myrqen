import ts from "typescript";
import {
  calleeName,
  calleeTail,
  collect,
  dynamicParts,
  enclosingFunction,
  expressionName,
  isConstantString,
  walk
} from "../ast/helpers.js";
import {
  analyzeFunction,
  functionsIn,
  HTML_ESCAPERS,
  htmlEscapersIn,
  isHtmlSafe,
  resolveExpression,
  taintOrigin,
  type TaintScope
} from "../ast/taint.js";
import { entryPointForFunction } from "../ast/entrypoints.js";
import { routeOf } from "./attribution.js";
import { describeSink, locationOf, sourceEvidence, taintEvidence, type Rule, type RuleContext } from "./context.js";

/** Calls that write a response body the browser may parse as HTML. */
const HTML_SINKS = new Set(["send", "write", "end", "html"]);

const HTML_MARKUP = /<\s*(html|body|div|span|h[1-6]|p|ul|li|table|script|a|img|form|input)\b|<\/\s*\w+\s*>/i;

/**
 * Receivers whose `write`, `end` or `send` is not a response to a caller.
 *
 * `write` is the same word for a file handle, a socket, a log and a response,
 * and a page written to any of the first three is not reflected in anybody's
 * browser. Naming that XSS names the wrong defect at the wrong severity, and a
 * report a reader can dismiss on sight costs more than the finding was worth.
 * The list is of receivers rather than of methods because the method name cannot
 * tell them apart.
 */
const NOT_A_RESPONSE =
  /^(fs|fh|file|stream|writer|out|output|mail|mailer|transport|transporter|smtp|ses|socket|ws|channel|publisher|queue|log|logger|stdout|stderr|archive|zip|csv)$/i;

/**
 * `element.innerHTML = caller` and its family.
 *
 * The gap this closes, stated precisely. `dangerous-inner-html` below already covered
 * the **JSX** form, `dangerouslySetInnerHTML` — so the engine was not blind to this
 * defect in React-shaped code. What appeared **nowhere** in the engine was the
 * *imperative* form: `innerHTML`, `outerHTML`, `insertAdjacentHTML` and
 * `document.write`. That is how the defect is written in a content script, in vanilla
 * DOM code, in a web component, and in anything jQuery-shaped — none of which any
 * corpus in this repository contains, which is why the hole survived.
 *
 * It is deliberately a separate rule from `reflected-xss`: that one is about a value
 * reaching a *response body*, which is a server concern, and this is about a value
 * reaching the *live document*, which is a client one. They share the escaper model
 * and nothing else — the impact, the remediation and the verification differ.
 *
 * The sink list is written from the DOM specification rather than from any case, so
 * it carries no corpus dependence. `textContent` is deliberately absent: assigning
 * to it is the fix, not the defect.
 */
const DOM_HTML_PROPERTIES = new Set(["innerHTML", "outerHTML"]);
const DOM_HTML_CALLS = new Set(["insertAdjacentHTML", "setHTMLUnsafe", "write", "writeln"]);

/** Which argument of the call carries markup. `insertAdjacentHTML(position, html)`. */
function domMarkupArgument(call: ts.CallExpression): ts.Expression | undefined {
  const tail = calleeTail(call);
  if (tail === "insertAdjacentHTML") return call.arguments[1];
  if (tail === "setHTMLUnsafe") return call.arguments[0];
  // `document.write` is only this sink on `document`; a project's own `write` is not.
  if (tail === "write" || tail === "writeln") {
    const receiver = ts.isPropertyAccessExpression(call.expression) ? call.expression.expression : null;
    const name = receiver ? receiver.getText() : "";
    return /^(?:document|doc|win\.document|window\.document|globalThis\.document)$/.test(name)
      ? call.arguments[0]
      : undefined;
  }
  return undefined;
}

export const domHtmlInjection: Rule = {
  id: "dom-html-injection",
  category: "dom_html_injection",
  describes: "caller-controlled data assigned to a DOM property the browser parses as HTML",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);
      const reported = new Set<number>();

      const consider = (node: ts.Node, written: ts.Expression, sink: string): void => {
        if (isConstantString(written)) return;
        const origin = taintOrigin(written, scope);
        if (!origin) return;
        // The escaped form is the fix, and after `htmlEscapersIn` it is recognised
        // by what the escaper does rather than by what it is called.
        if (isHtmlSafe(written, scope)) return;
        const parts = dynamicParts(written);
        const unescaped = parts.filter((part) => taintOrigin(part, scope) && !isHtmlSafe(part, scope));
        if (parts.length > 0 && unescaped.length === 0) return;

        const line = locationOf(context, node).line;
        if (reported.has(line)) return;
        reported.add(line);

        context.report({
          ruleId: "dom-html-injection",
          category: "dom_html_injection",
          title: `Caller-controlled data is written to the document through ${sink}`,
          severity: "high",
          verification: "strong_evidence",
          summary: `A value derived from ${origin} is assigned to ${sink}, which the browser parses as HTML. Nothing on the path escapes it, so the caller controls markup in the live document.`,
          impact:
            "Markup the caller supplies is parsed in the page's origin. An injected element with an event handler runs script with the victim's session, which allows acting as them and reading anything the page can read.",
          remediation: `Assign the value to \`textContent\` instead, which cannot introduce markup. Where markup genuinely has to be built, escape the interpolated values or construct the nodes with \`createElement\` and set their text.`,
          verificationPlan: `Supply a markup probe through ${origin} and confirm the document contains the escaped text rather than a new element.`,
          taxonomy: ["CWE-79", "CWE-79.1", "OWASP-A03"],
          location: locationOf(context, node),
          ...routeOf(context, node),
          evidence: [
            sourceEvidence(context, node, `${sink} parses whatever it is given as HTML; the assigned value carries caller input with no escaping call in the path.`),
            taintEvidence(origin, sink)
          ],
          reasoning: `Taint from ${origin} reaches ${sink}; ${unescaped.length} interpolated part(s) had no escaper applied.`
        });
      };

      for (const assignment of collect(fn, ts.isBinaryExpression)) {
        const operator = assignment.operatorToken.kind;
        if (operator !== ts.SyntaxKind.EqualsToken && operator !== ts.SyntaxKind.PlusEqualsToken) continue;
        if (!ts.isPropertyAccessExpression(assignment.left)) continue;
        const property = assignment.left.name.text;
        if (!DOM_HTML_PROPERTIES.has(property)) continue;
        consider(assignment, assignment.right, property);
      }

      for (const call of collect(fn, ts.isCallExpression)) {
        if (!DOM_HTML_CALLS.has(calleeTail(call))) continue;
        const written = domMarkupArgument(call);
        if (written) consider(call, written, `${calleeName(call)}()`);
      }
    }
  }
};

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

      // The markup is not always written where the response is. A team's own
      // portal assembles a fragment in one local, embeds that fragment in a page
      // in the next, and hands the page to a layout helper — `html(layout(title,
      // body))` — so the argument text at the sink holds no angle bracket at all
      // and the pass above never looks at the document. Without this, every
      // hand-rolled server that has a layout function is examined only for the
      // markup it happens to write inline at the sink, which is none of it.
      //
      // This pass is deliberately stricter than the one above about what counts
      // as unescaped, because it is reasoning through layers rather than reading
      // one expression in front of it. See `unescapedSlot`.
      for (const call of collect(fn, ts.isCallExpression)) {
        if (!HTML_SINKS.has(calleeTail(call))) continue;
        if (writesSomewhereOtherThanTheResponse(call)) continue;
        // Where the markup is written at the sink, the pass above has already
        // judged it. Judging a resolved copy of the same expression here would
        // report the same slot a second time.
        const writtenInline = call.arguments.some(
          (argument) => !isConstantString(argument) && HTML_MARKUP.test(argument.getText(context.file.source))
        );
        if (writtenInline) continue;

        for (const document of documentsBehind(call, scope)) {
          if (!HTML_MARKUP.test(document.getText(context.file.source))) continue;
          const reflected = unescapedSlot(document, scope);
          if (!reflected) continue;

          context.report({
            ruleId: "reflected-xss",
            category: "reflected_cross_site_scripting",
            title: `Caller-controlled data is interpolated into the HTML page written by ${calleeName(call)}`,
            severity: "medium",
            verification: "strong_evidence",
            summary: `A value derived from ${reflected.origin} is interpolated into the markup this handler writes to the response, and nothing escapes it between the two. The rest of the page may well be encoded correctly; this slot is not, so the caller controls part of the document the browser parses.`,
            impact:
              "A crafted link executes script in the victim's session context on this application's own origin, which allows session theft and any action the victim can perform.",
            remediation:
              "Pass this value through the same encoder the rest of the page uses before interpolating it, or render the page with a template engine that escapes by default. A Content-Security-Policy is a useful second layer but is not the fix.",
            verificationPlan:
              "Request the page with a markup probe in the parameter and confirm the response body contains only the escaped form of it.",
            taxonomy: ["CWE-79", "OWASP-A03"],
            location: locationOf(context, reflected.slot),
            ...routeOf(context, reflected.slot),
            evidence: [
              sourceEvidence(
                context,
                reflected.slot,
                "This interpolation puts caller-controlled text into the page with no encoder applied to it."
              ),
              taintEvidence(reflected.origin, describeSink(call))
            ],
            reasoning: `Taint from ${reflected.origin} reaches an interpolated slot of the document ${calleeName(call)}() writes. The value arrived at that slot through reads and string operations only, so nothing on the path could have escaped it.`
          });
          break;
        }
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
        // `note.bodyHtml`, where `bodyHtml` is built by a sanitiser in this file's
        // loader. See propertySanitisedInFile for why this is allowed to be loose.
        if (ts.isPropertyAccessExpression(rendered) && propertySanitisedInFile(context, rendered.name.text)) continue;
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

/**
 * An error handler that hands the caught exception to the caller.
 *
 * The defect is one sentence long — something the handler caught leaves the
 * process inside the response — and that sentence is framework-independent
 * while the syntax for it is not. Express writes `res.status(500).json(body)`,
 * h3 and Nitro throw `createError({ statusCode, data })`, a Worker returns
 * `new Response(JSON.stringify(body))`, a SvelteKit endpoint returns
 * `json(body)`, and a NestJS controller throws an exception whose payload the
 * framework serialises on its behalf. A rule that knows one of those spellings
 * finds one framework's disclosures and pronounces every other framework clean,
 * which is worse than saying nothing.
 *
 * Two things keep it quiet on correct code, and both matter more than the
 * detections. A payload handed to anything other than a response — a logger,
 * `next(err)`, a promise's `reject`, or a project helper that may itself be the
 * redaction step — is that function's business and is not reported. And a
 * payload that carries a fixed sentence, an application error code or a
 * correlation identifier never mentions the caught binding at all, so it never
 * reaches the check in the first place.
 */
export const verboseErrors: Rule = {
  id: "verbose-error-response",
  category: "verbose_error_response",
  describes: "error responses that disclose the caught exception",
  run(context: RuleContext) {
    /**
     * One finding per place a payload leaves the handler.
     *
     * The two passes below overlap on purpose — a handler that returns a stack
     * trace inside a larger error object is seen by both — and reporting the
     * same escape twice tells a reader there are two defects where there is one.
     */
    const reported = new Set<ts.Node>();

    for (const handler of errorHandlersIn(context)) {
      for (const payload of candidatePayloads(handler)) {
        const disclosures = disclosuresIn(payload, handler.bindings);
        if (disclosures.length === 0) continue;

        const escape = escapeSite(context, payload);
        if (!escape || reported.has(escape.node)) continue;

        /**
         * A 4xx tells the caller their own request was wrong, and explaining
         * what was wrong with it is the handler doing its job. A stack trace, a
         * SQL statement, a driver detail line or the exception object itself is
         * never an explanation of the request, so those are reported whatever
         * the status code says.
         */
        const internal = disclosures.some((disclosure) => disclosure.internal);
        const status = statusOf(escape.node);
        if (!internal && status !== null && status < 500) continue;

        reported.add(escape.node);
        const anchor = disclosures[0]!;
        const listed = describeDisclosures(disclosures);
        context.report({
          ruleId: "verbose-error-response",
          category: "verbose_error_response",
          title: `The error response carries ${listed} to the caller`,
          severity: internal ? "medium" : "low",
          verification: "strong_evidence",
          summary: `The handler catches the failure and then puts ${listed} into the payload that ${escape.description} sends back, so every failure this path can be pushed into answers the caller with the server's own account of it rather than with a message written for them.`,
          impact: internal
            ? "Exception internals disclose file paths, dependency versions, schema and query shapes, and the values the failing statement was bound to. Each of those shortens the work of finding a more serious issue, and a query echoed back with its parameters can disclose another tenant's identifiers outright."
            : "An exception message is written for an operator, not for a caller, and it routinely names the table, the constraint or the upstream service that failed. Repeated against a handler an attacker can steer, it maps out internals a caller was never meant to see.",
          remediation:
            "Log the exception server-side where only operators can read it, and answer the caller with a fixed message plus a correlation identifier they can quote to support. Where a 4xx genuinely has to explain the caller's own mistake, build that sentence from validated fields rather than from the exception.",
          verificationPlan: `Force this path to fail — an unreachable dependency or a deliberately invalid identifier will do — and confirm the response body contains no ${anchor.internal ? "stack, file path, query text or driver detail" : "exception message"}, only the generic message and the correlation identifier.`,
          taxonomy: ["CWE-209", "OWASP-A05"],
          location: locationOf(context, anchor.node),
          ...routeOf(context, anchor.node),
          evidence: [
            sourceEvidence(context, anchor.node, "This field of the error payload is read off the caught exception."),
            sourceEvidence(context, escape.node, `The payload leaves the handler here, through ${escape.description}.`)
          ],
          reasoning: `A binding introduced by the error handler reaches ${escape.description} inside the response payload; the disclosed field(s) are ${listed}${status === null ? "" : ` and the response status is ${status}`}.`
        });
      }
    }

    /**
     * The stack trace keeps a pass of its own.
     *
     * It can be attached to a value this rule cannot tie back to an error
     * handler — the error a GraphQL `formatError` shapes arrives as an ordinary
     * parameter, not as a caught binding — and a stack trace in a response body
     * needs no argument about intent to be wrong.
     */
    for (const fn of functionsIn(context.file.source)) {
      for (const property of collect(fn, ts.isPropertyAssignment)) {
        const name = property.name.getText(context.file.source).replace(/['"]/g, "");
        if (!ERROR_DETAIL_FIELD.test(name)) continue;
        const value = property.initializer.getText(context.file.source);
        if (!/\.stack\b/.test(value)) continue;

        // Only report when the object is on its way into a response.
        const escape = escapeSite(context, property);
        if (!escape || reported.has(escape.node)) continue;
        reported.add(escape.node);

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

/** Operators that hand one of their operands through to the markup whole. */
const MARKUP_JOINING_OPERATOR = new Set([
  ts.SyntaxKind.PlusToken,
  ts.SyntaxKind.BarBarToken,
  ts.SyntaxKind.QuestionQuestionToken
]);

/**
 * Calls that reshape a string without removing anything it says.
 *
 * Trimming, slicing, casing and splitting a value change how much of the
 * caller's text arrives, never whether it is still markup: `"<img src=x
 * onerror=1>".slice(0, 120)` is the whole payload. A length cap reads like a
 * defence and is not one, and treating one as a defence is how a page that caps
 * its search term at 120 characters gets called safe.
 */
const TEXT_PRESERVING = new Set([
  "String",
  "decodeURI",
  "decodeURIComponent",
  "trim",
  "trimStart",
  "trimEnd",
  "toString",
  "valueOf",
  "toLowerCase",
  "toUpperCase",
  "normalize",
  "slice",
  "substring",
  "substr",
  "split",
  "join",
  "concat",
  "at",
  "padStart",
  "padEnd",
  "replace",
  "replaceAll"
]);

/**
 * Encoders that make a value safe for markup by percent-escaping it.
 *
 * `encodeURIComponent` is a pass-through for taint — the value is still the
 * caller's — and it is not a pass-through for markup: every character that could
 * open a tag, close an attribute or introduce whitespace comes back as a percent
 * escape. A URL built for an `href` this way is the correct shape, and reporting
 * it teaches a reader that the rule cannot tell encoding from no encoding.
 */
const PERCENT_ENCODERS = new Set(["encodeURI", "encodeURIComponent"]);

/** Is this response-shaped call actually writing to a file, a socket or a log? */
function writesSomewhereOtherThanTheResponse(call: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const receiver = expressionName(call.expression.expression);
  const tail = receiver.split(".").pop() ?? receiver;
  return NOT_A_RESPONSE.test(tail);
}

/** An interpolated slot that carries the caller's own text into a document. */
interface ReflectedSlot {
  slot: ts.Node;
  origin: string;
}

/**
 * The documents a response-writing call could be handing to the caller.
 *
 * A sink argument is rarely the page. It is a local that holds the page, or a
 * call to the project's layout function that takes the page as an argument, and
 * in both shapes the markup is somewhere else in the same function. Resolving
 * each argument through its local binding, and looking inside the arguments of a
 * wrapping call, is what puts the document in front of the check. The two levels
 * of unwrapping cover `send(page)` and `html(layout(title, page))` and stop
 * there, because a chain longer than that is a call graph and this engine does
 * not follow one.
 */
function documentsBehind(call: ts.CallExpression, scope: TaintScope, depth = 0): ts.Node[] {
  const documents: ts.Node[] = [];
  for (const argument of call.arguments) {
    if (isConstantString(argument)) continue;
    const resolved = resolveExpression(argument, scope);
    documents.push(resolved);
    if (depth < 2 && ts.isCallExpression(resolved)) {
      documents.push(...documentsBehind(resolved, scope, depth + 1));
    }
  }
  return documents;
}

/**
 * The first slot in this document that still holds the caller's own text.
 *
 * A page is assembled in layers: a fragment in one local, a page that embeds the
 * fragment in the next, a layout around that. The decision to encode a value or
 * not is made in the innermost layer, so a check that only inspects the slots of
 * the outermost template is inspecting the layer where the decision was never
 * taken. This walks down through the locals a slot names and through the
 * conditionals that choose between fragments, and reports the slot it was
 * standing in when it found raw caller text — which is the line the author has
 * to change, not the line the page is written on.
 */
function unescapedSlot(node: ts.Node, scope: TaintScope, depth = 0): ReflectedSlot | null {
  if (depth > 8) return null;
  if (isHtmlSafe(node, scope)) return null;

  const consider = (part: ts.Expression): ReflectedSlot | null => {
    // Deeper first: the slot worth naming is the innermost one, and the outer
    // slot that merely embeds a fragment is not where anything is missing.
    const deeper = unescapedSlot(part, scope, depth + 1);
    if (deeper) return deeper;
    const origin = rawCallerText(part, scope);
    return origin ? { slot: part, origin } : null;
  };

  if (ts.isTemplateExpression(node)) {
    for (const span of node.templateSpans) {
      const found = consider(span.expression);
      if (found) return found;
    }
    return null;
  }
  // `hits.length > 0 ? renderHits() : renderEmptyMessage(term)` — the branch that
  // is taken depends on what the caller asked for, so both branches ship.
  if (ts.isConditionalExpression(node)) return consider(node.whenTrue) ?? consider(node.whenFalse);
  if (ts.isBinaryExpression(node) && MARKUP_JOINING_OPERATOR.has(node.operatorToken.kind)) {
    return consider(node.left) ?? consider(node.right);
  }
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAwaitExpression(node) ||
    (ts.isYieldExpression(node) && node.expression !== undefined) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node)
  ) {
    return node.expression ? unescapedSlot(node.expression, scope, depth + 1) : null;
  }
  if (ts.isIdentifier(node)) {
    // Descend into a local only while there is still markup underneath it. A
    // local that holds another layer of the page is worth following; a local
    // that holds a *value* is where the descent has to stop, because the slot a
    // reader has to fix is the interpolation that named this local and not the
    // line the value was read on three statements earlier.
    const initializer = scope.initializers.get(node.text);
    if (!initializer || !isMarkupShaped(initializer)) return null;
    return unescapedSlot(initializer, scope, depth + 1);
  }
  return null;
}

/** Does this expression contain markup, so that it is a layer of a page? */
function isMarkupShaped(node: ts.Node): boolean {
  return HTML_MARKUP.test(node.getText(node.getSourceFile()));
}

/**
 * Caller-controlled text that provably nothing has escaped, or null.
 *
 * This is the distinction the whole layered check rests on, and taint alone
 * cannot make it. A project's encoder is an ordinary call taking an ordinary
 * argument: `entities(term)` is exactly as tainted as `term`, and the file that
 * declares `entities` is usually not the file being read. What separates them is
 * the direction the value travels. An encoder is *handed* the value, so any call
 * that was handed it and cannot be identified is treated as having possibly
 * encoded it and the slot stays silent. A read is handed a key and gives the
 * caller's value back, and string reshaping keeps whatever it was given. Text
 * that arrived through nothing but reads and reshaping is text nobody encoded —
 * which is exactly the slot whose author forgot the encoder every neighbouring
 * slot uses.
 *
 * Erring this way costs recall on flows through helpers this engine cannot see
 * into. Erring the other way reports every correctly encoded page in every
 * project that named its encoder something other than `escapeHtml`, and one of
 * those is worth more than a hundred of the other.
 */
function rawCallerText(node: ts.Node, scope: TaintScope, depth = 0): string | null {
  if (depth > 6) return null;
  if (isConstantString(node)) return null;
  if (isHtmlSafe(node, scope)) return null;

  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAwaitExpression(node) ||
    (ts.isYieldExpression(node) && node.expression !== undefined) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node)
  ) {
    return node.expression ? rawCallerText(node.expression, scope, depth + 1) : null;
  }

  if (ts.isBinaryExpression(node) && MARKUP_JOINING_OPERATOR.has(node.operatorToken.kind)) {
    return rawCallerText(node.left, scope, depth + 1) ?? rawCallerText(node.right, scope, depth + 1);
  }

  if (ts.isIdentifier(node)) {
    if (scope.htmlSafe.has(node.text)) return null;
    // A local says nothing about itself; what it was initialised from says
    // everything. `const term = (query.get("q") ?? "").trim()` is raw caller
    // text, and `const term = entities(query.get("q"))` is not, and the two are
    // the same identifier at the slot.
    const initializer = scope.initializers.get(node.text);
    if (initializer) return rawCallerText(initializer, scope, depth + 1);
    // No initialiser in this function: a parameter or a binding the entry point
    // seeded, holding whatever arrived in the request.
    return taintOrigin(node, scope);
  }

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    // A `.length` is a number and cannot carry markup. Reporting one turns the
    // correctly written version of a paginated page into a finding.
    if (ts.isPropertyAccessExpression(node) && node.name.text === "length") return null;
    return taintOrigin(node, scope);
  }

  if (ts.isCallExpression(node)) {
    const name = calleeName(node);
    const tail = calleeTail(node);
    if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail)) return null;
    if (scope.htmlEscapers.has(name) || scope.htmlEscapers.has(tail)) return null;
    if (PERCENT_ENCODERS.has(name) || PERCENT_ENCODERS.has(tail)) return null;

    if (TEXT_PRESERVING.has(name) || TEXT_PRESERVING.has(tail)) {
      const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : null;
      const fromReceiver = receiver ? rawCallerText(receiver, scope, depth + 1) : null;
      if (fromReceiver) return fromReceiver;
      for (const argument of node.arguments) {
        const origin = rawCallerText(argument, scope, depth + 1);
        if (origin) return origin;
      }
      return null;
    }

    // A read: the call names what it wants — `query.get("q")`, `params.get("id")`,
    // `req.header("x-forwarded-for")` — and gets the caller's own value back.
    // Nothing was handed over that could have been encoded on the way, which is
    // what separates this shape from a call to an encoder.
    const readsFrom = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : null;
    const namesAKey = node.arguments.every((argument) => isConstantString(argument) || ts.isNumericLiteral(argument));
    if (readsFrom && namesAKey) return rawCallerText(readsFrom, scope, depth + 1);

    // Any other call was handed the value and may have encoded it. Silence here
    // is the whole reason this check can be trusted on a codebase whose encoders
    // it has never heard of.
    return null;
  }

  return null;
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

/**
 * Is every place this file builds a property of this name a sanitiser call?
 *
 * The shape this closes is the one most real applications are written in: the value
 * is sanitised where it is loaded and rendered somewhere else.
 *
 *     export const useNotes = routeLoader$(async () => rows.map((row) => ({
 *       bodyHtml: sanitizeHtml(row.body_html, OPTIONS)   // <- the guard
 *     })));
 *     …
 *     <li dangerouslySetInnerHTML={note.bodyHtml} />     // <- the sink, two functions away
 *
 * `sanitisedInFile` above handles the same idea for a bare local. It could not see
 * this one, because the value at the sink is a *property access* and there is no
 * variable of that name to look up — so the rule reported a page whose markup had
 * been through `sanitize-html` with `allowedAttributes: {}`.
 *
 * Matching on the property name across function boundaries is looser than anything
 * else in this engine, and it is only ever used to **silence**. Its failure mode is a
 * false negative, which is the direction this rule is documented to err: reporting
 * every correctly sanitised page teaches a reader that the rule cannot tell the
 * difference, and then they stop reading it.
 *
 * It stays honest by requiring *every* assignment of that property in the file to be
 * a sanitiser call. One raw assignment anywhere and the rule reports, which is what
 * makes the unsanitised sibling of this exact shape still fire.
 */
function propertySanitisedInFile(context: RuleContext, property: string): boolean {
  const assignments = propertyAssignmentsIn(context.file).get(property);
  if (!assignments || assignments.length === 0) return false;
  return assignments.every((value) => ts.isCallExpression(value) && isSanitiserCall(context, value));
}

/**
 * Every property assignment in the file, indexed by key, computed once.
 *
 * The first version collected every `PropertyAssignment` in the file on each
 * `dangerouslySetInnerHTML` it judged — the same quadratic shape that made
 * `ast/route-index.ts` take 82 seconds on a large module, reintroduced within hours of
 * that being fixed. `pnpm benchmark:performance` caught it at 2.5x on a 69 KB file,
 * which is exactly what that gate is for.
 */
const PROPERTY_INDEX = new WeakMap<ts.SourceFile, Map<string, ts.Expression[]>>();

function propertyAssignmentsIn(file: RuleContext["file"]): Map<string, ts.Expression[]> {
  const cached = PROPERTY_INDEX.get(file.source);
  if (cached) return cached;
  const index = new Map<string, ts.Expression[]>();
  for (const assignment of collect(file.source, ts.isPropertyAssignment)) {
    const key = ts.isIdentifier(assignment.name) || ts.isStringLiteral(assignment.name) ? assignment.name.text : null;
    if (key === null) continue;
    const bucket = index.get(key);
    if (bucket) bucket.push(assignment.initializer);
    else index.set(key, [assignment.initializer]);
  }
  PROPERTY_INDEX.set(file.source, index);
  return index;
}

/** Is this call an HTML sanitiser? */
function isSanitiserCall(context: RuleContext, call: ts.CallExpression): boolean {
  const name = calleeName(call);
  const tail = calleeTail(call);
  if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail)) return true;
  if (htmlEscapersIn(context.file).has(name) || htmlEscapersIn(context.file).has(tail)) return true;
  // A project may wrap its sanitiser; the import tells us what it is.
  return /sanitiz|purif|\bxss\b|escape/i.test(name) && /sanitize-html|dompurify|xss|isomorphic-dompurify/i.test(context.file.text);
}

/* ------------------------------------------------------------------ *
 * verbose_error_response: what leaves, and where it leaves through
 * ------------------------------------------------------------------ */

/** Something of the caught exception that a payload carries. */
interface Disclosure {
  /** How to name it in the report, for example `failure.stack`. */
  what: string;
  /**
   * True when the value describes the server rather than the caller's request.
   * A stack trace, a SQL statement or the exception object itself is wrong to
   * disclose at any status code; an exception *message* is only wrong when the
   * handler is admitting its own failure, which is what a 5xx says.
   */
  internal: boolean;
}

/** A place where the exception is in hand and the response is still to be written. */
interface ErrorHandler {
  /** The body that runs with the exception in hand. */
  body: ts.Node;
  /** Local names holding the exception or a piece of it, and what each holds. */
  bindings: Map<string, Disclosure>;
}

/** How a payload reaches the caller. */
interface Escape {
  /** The expression that hands the payload over. */
  node: ts.Node;
  /** How it does it, for the evidence line. */
  description: string;
}

/**
 * Exception properties that describe the server.
 *
 * The list is deliberately driver-shaped rather than Error-shaped: `detail`,
 * `hint`, `constraint`, `where` and `routine` are Postgres, `sqlMessage` and
 * `sqlState` are MySQL, `response` and `config` are an HTTP client's record of
 * the upstream call. Those are the fields that turn a 500 into a description of
 * the schema, and a rule that only knows `stack` misses every one of them.
 */
const INTERNAL_ERROR_FIELD = new Set([
  "stack",
  "stacktrace",
  "sql",
  "sqlmessage",
  "sqlstate",
  "query",
  "internalquery",
  "internalposition",
  "detail",
  "details",
  "hint",
  "where",
  "routine",
  "position",
  "constraint",
  "column",
  "table",
  "schema",
  "cause",
  "config",
  "request",
  "response",
  "originalerror",
  "innererror",
  "command",
  "stderr",
  "stdout",
  "syscall",
  "path",
  "file",
  "filename",
  "driver"
]);

/**
 * Exception properties that a 4xx may legitimately quote back.
 *
 * A validation failure's message *is* the explanation the caller asked for, so
 * these are reported only when the handler is admitting a server-side failure.
 * `errors` and `issues` are absent on purpose: a schema validator puts the
 * caller's own field errors there, and returning them is the correct design.
 */
const CALLER_FACING_ERROR_FIELD = new Set(["message", "code", "errno", "reason"]);

/** Calls that hand their argument to the caller as the response body. */
const RESPONSE_WRITER = new Set(["json", "send", "end", "write", "respond", "reply"]);

/**
 * Helpers that build the HTTP error the framework sends back.
 *
 * The object argument is what separates h3's `createError({ statusCode, data })`
 * from a project's own `createError("could not parse")`, which only builds an
 * Error for internal use and never reaches a caller by itself.
 */
const HTTP_ERROR_FACTORY = /^(createError|createHttpError|createHttpException|createApiError|httpError)$/;

/**
 * Bare functions that produce a response and are always handed straight back.
 *
 * SvelteKit's `error(500, body)` and `fail(400, body)` are called by name, which
 * makes them indistinguishable from a `debug`-style logger until you notice that
 * a response factory's result is always returned or thrown and a logger's never
 * is. Requiring that is what keeps `error({ err }, "failed")` out of the rule.
 */
const THROWN_RESPONSE_FACTORY = /^(error|fail)$/;

const RESPONSE_CONSTRUCTOR = /^(Next)?Response$/;

/** NestJS serialises the payload an HTTP exception was constructed with. */
const HTTP_EXCEPTION = /^[A-Z][A-Za-z0-9]*Exception$/;

/** Entry points whose return value is the answer somebody outside receives. */
const CALLER_FACING_ENTRY = new Set(["http", "rpc", "ipc", "action"]);

/** Wrappers that hand their argument onward unchanged. */
const PASS_THROUGH_WRAPPER = /^(JSON\.stringify|String|Object\.assign|structuredClone|util\.inspect|inspect|util\.format)$/;

/** Calls that render a value as text: the exception's name and its message. */
const TEXT_STRINGIFIER = new Set(["String"]);

/** Calls that serialise every own property, `detail` and `query` included. */
const DEEP_STRINGIFIER = new Set(["JSON.stringify", "util.inspect", "inspect", "util.format"]);

/** String methods that trim or reshape a value without removing what it says. */
const STRING_PASS_THROUGH = new Set([
  "toString",
  "slice",
  "substring",
  "substr",
  "trim",
  "split",
  "join",
  "replace",
  "replaceAll",
  "tolowercase",
  "touppercase",
  "concat",
  "normalize",
  "valueOf"
]);

/** Calls that set the status a response will carry. */
const STATUS_SETTER = new Set(["status", "code", "statusCode"]);

/** Property names that hold a numeric HTTP status. */
const STATUS_FIELD = /^(status|statusCode|httpStatus|code)$/;

/**
 * Every place in this file where an exception is in hand.
 *
 * Three shapes, because a verbose error response is written in all three and a
 * rule that only reads `catch` blocks is silent on two of them: the catch
 * clause, the rejection callback of `.catch(err => …)`, and Express's
 * four-argument error middleware, which is the single function in a typical
 * Express application whose whole purpose is deciding what a 500 says.
 */
function errorHandlersIn(context: RuleContext): ErrorHandler[] {
  const handlers: ErrorHandler[] = [];
  const source = context.file.source;

  const add = (body: ts.Node | undefined, names: string[], describe: (name: string) => string): void => {
    if (!body || names.length === 0) return;
    const bindings = new Map<string, Disclosure>();
    for (const name of names) bindings.set(name, { what: describe(name), internal: true });
    const handler: ErrorHandler = { body, bindings };
    resolveAliases(handler);
    handlers.push(handler);
  };

  for (const clause of collect(source, ts.isCatchClause)) {
    const declaration = clause.variableDeclaration;
    if (!declaration) continue;
    add(clause.block, boundNames(declaration.name), (name) => `the caught exception \`${name}\``);
  }

  for (const call of collect(source, ts.isCallExpression)) {
    if (calleeTail(call) !== "catch") continue;
    const callback = call.arguments[0];
    if (!callback || (!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback))) continue;
    const parameter = callback.parameters[0];
    if (!parameter) continue;
    add(callback.body, boundNames(parameter.name), (name) => `the rejection reason \`${name}\``);
  }

  for (const fn of functionsIn(source)) {
    if (!isErrorMiddleware(fn)) continue;
    const parameter = (fn as ts.FunctionLikeDeclaration).parameters[0]!;
    add((fn as ts.FunctionLikeDeclaration).body, boundNames(parameter.name), (name) => `the failure \`${name}\` handed to this middleware`);
  }

  return handlers;
}

/** Every name a binding pattern introduces, so `catch ({ message })` is followed too. */
function boundNames(pattern: ts.BindingName): string[] {
  if (ts.isIdentifier(pattern)) return [pattern.text];
  const names: string[] = [];
  for (const element of pattern.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

/**
 * Express's error middleware is identified by its shape, not by its name.
 *
 * Four parameters with the error first is the signature the framework dispatches
 * on, and it is the only thing in the file that says this function receives an
 * exception rather than a request.
 */
function isErrorMiddleware(fn: ts.Node): boolean {
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters;
  if (!parameters || parameters.length !== 4) return false;
  const names = parameters.map((parameter) => (ts.isIdentifier(parameter.name) ? parameter.name.text : ""));
  return (
    /^_?(err|error|e|exception)$/i.test(names[0] ?? "") &&
    /^_?(req|request)$/i.test(names[1] ?? "") &&
    /^_?(res|response|reply)$/i.test(names[2] ?? "") &&
    /^_?next$/i.test(names[3] ?? "")
  );
}

/**
 * Follow the exception into the locals the handler copies it into.
 *
 * `const failure = err as Error & { detail?: string }` and
 * `const message = err.message` are how an error handler is actually written in
 * TypeScript, and without this the payload one line later mentions no binding
 * the rule has ever heard of. Two passes, so an alias of an alias is followed.
 */
function resolveAliases(handler: ErrorHandler): void {
  for (let pass = 0; pass < 2; pass += 1) {
    walk(handler.body, (node) => {
      if (!ts.isVariableDeclaration(node) || !node.initializer || !ts.isIdentifier(node.name)) return;
      if (handler.bindings.has(node.name.text)) return;
      const disclosure = errorDisclosure(node.initializer, handler.bindings);
      if (disclosure) handler.bindings.set(node.name.text, disclosure);
    });
  }
}

/**
 * Expressions inside an error handler that could be a response payload.
 *
 * Object literals and template strings cover almost everything. A bare binding
 * or a single field of it — `res.status(500).send(err.message)` is as common as
 * the object form — counts only where it is handed straight to a call or
 * returned, because `err` and `err.code` appear in every condition and every log
 * line in the block, and judging those as payloads would report the handler for
 * reading its own exception.
 */
function candidatePayloads(handler: ErrorHandler): ts.Node[] {
  const payloads: ts.Node[] = [];
  walk(handler.body, (node) => {
    if (ts.isObjectLiteralExpression(node) || ts.isTemplateExpression(node)) {
      payloads.push(node);
      return;
    }
    if (ts.isCallExpression(node) && stringifierKind(node) !== null) {
      payloads.push(node);
      return;
    }
    const readsTheError =
      (ts.isIdentifier(node) && handler.bindings.has(node.text)) ||
      ((ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) &&
        fieldDisclosure(node, handler.bindings) !== null);
    if (readsTheError && isHandedOver(node)) payloads.push(node);
  });
  return payloads;
}

/** Is this expression handed straight to a call, or returned, rather than read? */
function isHandedOver(node: ts.Node): boolean {
  const parent = node.parent;
  if (!parent) return false;
  if (ts.isReturnStatement(parent)) return true;
  if (!ts.isCallExpression(parent) && !ts.isNewExpression(parent)) return false;
  return (parent.arguments ?? []).some((argument) => argument === node);
}

/** What of the exception this payload carries, one entry per disclosing field. */
function disclosuresIn(payload: ts.Node, bindings: Map<string, Disclosure>): Array<Disclosure & { node: ts.Node }> {
  if (ts.isObjectLiteralExpression(payload)) return disclosingProperties(payload, bindings);
  const single = errorDisclosure(payload, bindings);
  return single ? [{ ...single, node: payload }] : [];
}

/**
 * The properties of a payload object that carry the exception.
 *
 * Nested objects are descended into rather than reported whole, so the finding
 * points at `data.stack` rather than at the `data:` key three lines above it —
 * the reader has to see the field to agree with the finding.
 */
function disclosingProperties(
  object: ts.ObjectLiteralExpression,
  bindings: Map<string, Disclosure>,
  depth = 0
): Array<Disclosure & { node: ts.Node }> {
  if (depth > 4) return [];
  const found: Array<Disclosure & { node: ts.Node }> = [];
  for (const property of object.properties) {
    if (ts.isPropertyAssignment(property)) {
      if (ts.isObjectLiteralExpression(property.initializer)) {
        found.push(...disclosingProperties(property.initializer, bindings, depth + 1));
        continue;
      }
      const disclosure = errorDisclosure(property.initializer, bindings);
      if (disclosure) found.push({ ...disclosure, node: property });
      continue;
    }
    if (ts.isShorthandPropertyAssignment(property)) {
      const disclosure = bindings.get(property.name.text);
      if (disclosure) found.push({ ...disclosure, node: property });
      continue;
    }
    if (ts.isSpreadAssignment(property)) {
      const disclosure = errorDisclosure(property.expression, bindings);
      if (disclosure) found.push({ ...disclosure, node: property });
    }
  }
  return found;
}

/**
 * What this expression discloses of the exception, or null when it discloses
 * nothing.
 *
 * The recursion follows the operators that pass a value through and stops at any
 * call it does not recognise. Stopping there is the point: `{ error: redact(err) }`
 * and `{ error: toClientMessage(err) }` are what a fixed handler looks like, and
 * a rule that assumed every helper leaks would report the fix as the defect.
 */
function errorDisclosure(node: ts.Node, bindings: Map<string, Disclosure>, depth = 0): Disclosure | null {
  if (depth > 6) return null;
  const next = (inner: ts.Node): Disclosure | null => errorDisclosure(inner, bindings, depth + 1);

  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAwaitExpression(node) ||
    (ts.isYieldExpression(node) && node.expression !== undefined) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node)
  ) {
    return node.expression ? next(node.expression) : null;
  }
  if (isConstantString(node)) return null;
  if (ts.isIdentifier(node)) return bindings.get(node.text) ?? null;

  // Only the branches, never the condition: `err.code === "P2002" ? "duplicate"
  // : "failed"` tests the exception and discloses none of it.
  if (ts.isConditionalExpression(node)) return next(node.whenTrue) ?? next(node.whenFalse);

  if (ts.isBinaryExpression(node)) {
    const kind = node.operatorToken.kind;
    const passesThrough =
      kind === ts.SyntaxKind.BarBarToken ||
      kind === ts.SyntaxKind.QuestionQuestionToken ||
      kind === ts.SyntaxKind.AmpersandAmpersandToken ||
      kind === ts.SyntaxKind.PlusToken;
    return passesThrough ? (next(node.left) ?? next(node.right)) : null;
  }

  if (ts.isTemplateExpression(node)) {
    for (const span of node.templateSpans) {
      const disclosure = next(span.expression);
      // Interpolating an exception into a sentence yields its name and message,
      // which is the tier a 4xx may quote — unless what was interpolated was
      // itself an internal field.
      if (disclosure) return { what: disclosure.what, internal: disclosure.internal && !isWholeError(disclosure) };
    }
    return null;
  }

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return fieldDisclosure(node, bindings);
  }

  if (ts.isCallExpression(node)) {
    const kind = stringifierKind(node);
    if (kind !== null) {
      for (const argument of node.arguments) {
        const disclosure = next(argument);
        if (!disclosure) continue;
        return { what: `${calleeName(node)}(${disclosure.what})`, internal: kind === "deep" ? true : !isWholeError(disclosure) && disclosure.internal };
      }
      return null;
    }
    const tail = calleeTail(node).toLowerCase();
    if (STRING_PASS_THROUGH.has(tail) && ts.isPropertyAccessExpression(node.expression)) {
      return next(node.expression.expression);
    }
    return null;
  }

  if (ts.isArrayLiteralExpression(node)) {
    for (const element of node.elements) {
      const disclosure = next(element);
      if (disclosure) return disclosure;
    }
    return null;
  }

  if (ts.isObjectLiteralExpression(node)) {
    const nested = disclosingProperties(node, bindings, depth + 1);
    return nested[0] ? { what: nested[0].what, internal: nested[0].internal } : null;
  }

  return null;
}

/** Does this disclosure name the exception object rather than one field of it? */
function isWholeError(disclosure: Disclosure): boolean {
  return !disclosure.what.includes(".");
}

/**
 * A property read off a binding the error handler introduced.
 *
 * Only the first segment is judged. `err.errors[0].path` is a validator's report
 * on the caller's own input and belongs in the response; `err.response.body` is
 * the upstream service's answer and does not.
 */
/**
 * Classes this file declares, by name.
 *
 * Memoised per source file. An application's own error types are the point: nothing
 * about a class declared here is the runtime's, a driver's, or an upstream service's,
 * so a message carried by one is text this codebase wrote.
 */
const LOCAL_CLASSES = new WeakMap<ts.SourceFile, Set<string>>();

function locallyDeclaredClasses(source: ts.SourceFile): Set<string> {
  const cached = LOCAL_CLASSES.get(source);
  if (cached) return cached;
  const names = new Set<string>();
  walk(source, (node) => {
    if (ts.isClassDeclaration(node) && node.name) names.add(node.name.text);
    if (ts.isClassExpression(node) && node.name) names.add(node.name.text);
  });
  LOCAL_CLASSES.set(source, names);
  return names;
}

/**
 * Has this read been narrowed, by `instanceof`, to an error class this file declares?
 *
 *     class TargetRejected extends Error {}
 *     …
 *     catch (rejection) {
 *       const reason = rejection instanceof TargetRejected ? rejection.message : "callbackUrl rejected";
 *       return { status: 400, jsonBody: { error: reason } };
 *     }
 *
 * `.message` is on `INTERNAL_ERROR_FIELD` because on a caught exception it is usually the
 * runtime's or the driver's, and that default is right. It is wrong here, and confidently
 * wrong: the narrowing is the author stating which type this is, the type is one they
 * declared, and every `throw` of it in the file carries a sentence they wrote for the
 * caller to read. There is also a literal fallback for every other error, so nothing
 * unrecognised escapes either.
 *
 * Refusing this shape reported the *correct* way to surface a validation failure, which
 * is worse than a missed finding: it teaches a reader that the rule does not understand
 * error handling, and the next real disclosure it reports gets dismissed with the rest.
 *
 * Both branch shapes count — the ternary above and the `if (e instanceof T) { … }` form —
 * because they are the same statement and which one an author picks is style. The
 * negated forms are followed so `!(e instanceof T)` selects the other branch correctly.
 */
function containsNode(container: ts.Node, node: ts.Node): boolean {
  let current: ts.Node | undefined = node;
  while (current) {
    if (current === container) return true;
    current = current.parent;
  }
  return false;
}

function narrowedToLocalError(node: ts.Node, binding: string): boolean {
  const local = locallyDeclaredClasses(node.getSourceFile());
  if (local.size === 0) return false;

  const narrows = (condition: ts.Expression): { negated: boolean } | null => {
    let inner: ts.Node = condition;
    let negated = false;
    while (
      (ts.isPrefixUnaryExpression(inner) && inner.operator === ts.SyntaxKind.ExclamationToken) ||
      ts.isParenthesizedExpression(inner)
    ) {
      if (ts.isPrefixUnaryExpression(inner)) negated = !negated;
      inner = ts.isPrefixUnaryExpression(inner) ? inner.operand : inner.expression;
    }
    if (!ts.isBinaryExpression(inner)) return null;
    if (inner.operatorToken.kind !== ts.SyntaxKind.InstanceOfKeyword) return null;
    if (!ts.isIdentifier(inner.left) || inner.left.text !== binding) return null;
    if (!ts.isIdentifier(inner.right) || !local.has(inner.right.text)) return null;
    return { negated };
  };

  let child: ts.Node = node;
  let parent: ts.Node | undefined = node.parent;
  while (parent) {
    if (ts.isConditionalExpression(parent)) {
      const found = narrows(parent.condition);
      if (found) {
        const selected = found.negated ? parent.whenFalse : parent.whenTrue;
        if (selected === child || containsNode(selected, child)) return true;
      }
    }
    if (ts.isIfStatement(parent)) {
      const found = narrows(parent.expression);
      if (found) {
        const selected = found.negated ? parent.elseStatement : parent.thenStatement;
        if (selected && (selected === child || containsNode(selected, child))) return true;
      }
    }
    child = parent;
    parent = parent.parent;
  }
  return false;
}

function fieldDisclosure(node: ts.Node, bindings: Map<string, Disclosure>): Disclosure | null {
  const segments: string[] = [];
  let current: ts.Node = node;
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
    if (ts.isPropertyAccessExpression(current)) segments.unshift(current.name.text);
    else if (ts.isStringLiteralLike(current.argumentExpression)) segments.unshift(current.argumentExpression.text);
    else segments.unshift("*");
    current = current.expression;
  }
  if (!ts.isIdentifier(current) || !bindings.has(current.text)) return null;
  const field = segments[0];
  if (!field) return null;
  const lowered = field.toLowerCase();
  if (INTERNAL_ERROR_FIELD.has(lowered)) {
    return { what: `${current.text}.${field}`, internal: !narrowedToLocalError(node, current.text) };
  }
  if (CALLER_FACING_ERROR_FIELD.has(lowered)) return { what: `${current.text}.${field}`, internal: false };
  return null;
}

/** Is this call a stringifier, and does it render text or serialise the object? */
function stringifierKind(call: ts.CallExpression): "text" | "deep" | null {
  const name = calleeName(call);
  const tail = calleeTail(call);
  if (DEEP_STRINGIFIER.has(name) || DEEP_STRINGIFIER.has(tail)) return "deep";
  if (TEXT_STRINGIFIER.has(name)) return "text";
  return null;
}

/** The first few disclosures, named the way the payload names them. */
function describeDisclosures(disclosures: Array<Disclosure & { node: ts.Node }>): string {
  const names = [...new Set(disclosures.map((disclosure) => disclosure.what))];
  if (names.length === 1) return names[0]!;
  if (names.length <= 3) return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  const rest = names.length - 3;
  return `${names.slice(0, 3).join(", ")} and ${rest} other field${rest === 1 ? "" : "s"}`;
}

/**
 * Where this payload leaves the handler, or null when it does not.
 *
 * The walk climbs to the enclosing function and stops at the first call that is
 * not a response. That stop is the rule's precision: a payload passed to
 * `logger.error`, to `next(err)`, to a promise's `reject`, or to a project's own
 * `toClientError(err)` has been handed to somebody else, and what that somebody
 * does with it is not visible here. Assuming the worst there would report every
 * correctly written handler in the repository, which is the failure mode that
 * gets a scanner uninstalled.
 */
function escapeSite(context: RuleContext, node: ts.Node, depth = 0): Escape | null {
  let child: ts.Node = node;
  let current: ts.Node | undefined = node.parent;

  while (current) {
    if (ts.isCallExpression(current) || ts.isNewExpression(current)) {
      const escape = responseFrom(context, current);
      if (escape) return escape;
      const args = current.arguments ?? ts.factory.createNodeArray<ts.Expression>([]);
      if (args.some((argument) => argument === child) && !PASS_THROUGH_WRAPPER.test(expressionName(current.expression))) {
        return null;
      }
    }

    if (
      ts.isBinaryExpression(current) &&
      current.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      RESPONSE_BODY.test(expressionName(current.left))
    ) {
      return { node: current, description: `an assignment to ${expressionName(current.left)}` };
    }

    if (ts.isReturnStatement(current)) {
      const holder = enclosingFunction(current);
      const formatter = errorFormatterName(context, holder);
      if (formatter) return { node: current, description: `the value \`${formatter}\` returns` };
      // A Nitro route, a SvelteKit endpoint, a tRPC procedure and an Electron
      // IPC handler all answer their caller with whatever they return, so the
      // return statement itself is the response and there is no `res` in the
      // file to key on.
      const entry = holder ? entryPointForFunction(context.file, holder) : undefined;
      if (entry && CALLER_FACING_ENTRY.has(entry.kind)) {
        return { node: current, description: `the value this ${entry.framework} handler returns` };
      }
      return null;
    }

    // `const body = { … }; res.status(500).json(body);` is the same flow written
    // over two statements, and stopping at the declaration loses it.
    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) {
      return depth < 2 ? escapeOfBinding(context, current, depth) : null;
    }

    if (isFunctionLike(current)) return null;

    child = current;
    current = current.parent;
  }
  return null;
}

/** Does the value this declaration binds reach the caller somewhere below? */
function escapeOfBinding(context: RuleContext, declaration: ts.VariableDeclaration, depth: number): Escape | null {
  const name = declaration.name as ts.Identifier;
  const holder = enclosingFunction(declaration) ?? context.file.source;
  for (const use of collect(holder, ts.isIdentifier)) {
    if (use === name || use.text !== name.text) continue;
    if (ts.isPropertyAccessExpression(use.parent) && use.parent.name === use) continue;
    const onward = escapeSite(context, use, depth + 1);
    if (onward) return onward;
  }
  return null;
}

/** Does this call or construction hand its argument to the caller? */
function responseFrom(context: RuleContext, node: ts.CallExpression | ts.NewExpression): Escape | null {
  if (ts.isNewExpression(node)) {
    const constructor = expressionName(node.expression);
    if (RESPONSE_CONSTRUCTOR.test(constructor)) return { node, description: `new ${constructor}()` };
    if (HTTP_EXCEPTION.test(constructor) && handedBack(node)) {
      return { node, description: `the ${constructor} the handler throws` };
    }
    return null;
  }

  const name = calleeName(node);
  if (name === "Response.json" || name === "NextResponse.json") return { node, description: `${name}()` };
  if (RESPONSE_WRITER.has(calleeTail(node)) && !isDiagnosticStream(name)) {
    return { node, description: `${name}()` };
  }
  if (!ts.isIdentifier(node.expression)) return null;

  const bare = node.expression.text;
  if (HTTP_ERROR_FACTORY.test(bare) && node.arguments.some((argument) => ts.isObjectLiteralExpression(argument))) {
    return { node, description: `${bare}()` };
  }
  if (THROWN_RESPONSE_FACTORY.test(bare) && handedBack(node)) return { node, description: `${bare}()` };
  return null;
}

/**
 * Is this `write` going to an operator, not to the caller?
 *
 * `write` has to be in the response-writer list — it is how a raw `node:http`
 * handler answers — and it is also how every program in Node writes a log line.
 * A handler that logs `error.message` to stderr and returns a fixed string to
 * the caller is the textbook correct shape, and reporting it is the single most
 * insulting false positive this rule can produce.
 */
function isDiagnosticStream(name: string): boolean {
  return /(^|\.)(process\.)?(stderr|stdout)\.\w+$/.test(name) || /^console\./.test(name);
}

/** Is this expression returned or thrown out of the function it sits in? */
function handedBack(node: ts.Node): boolean {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isReturnStatement(current) || ts.isThrowStatement(current)) return true;
    if (isFunctionLike(current)) return false;
    current = current.parent;
  }
  return false;
}

function isFunctionLike(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

/** The name under which this function is registered as the error shaper, if it is. */
function errorFormatterName(context: RuleContext, holder: ts.Node | undefined): string | null {
  const parent = holder?.parent;
  if (!parent) return null;
  if (ts.isPropertyAssignment(parent)) {
    const key = parent.name.getText(context.file.source).replace(/["']/g, "");
    return ERROR_FORMATTER.test(key) ? key : null;
  }
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name) && ERROR_FORMATTER.test(parent.name.text)) {
    return parent.name.text;
  }
  return null;
}

/**
 * The HTTP status this response carries, when the handler states one.
 *
 * It is read from wherever the framework puts it — the `status(500)` in the
 * chain, a numeric argument, a `statusCode` in the options object, or the
 * `ctx.status = 502` written beside the body. Null means the handler does not
 * say, and an unstated status is treated as a server failure rather than as a
 * client one, because that is the direction that does not lose real findings.
 */
function statusOf(node: ts.Node): number | null {
  /*
   * `return { status: 400, jsonBody: { error: reason } }`.
   *
   * The status is a property of the returned object, not an argument to a call. That is
   * how Azure Functions, Nitro, Hono's `c.json(body, init)` and every framework whose
   * handler *returns* its response rather than writing to a stream spells it — and this
   * function only read arguments, so the status came back null and the "a 4xx is the
   * handler explaining the caller's own mistake" exemption never applied to any of them.
   *
   * The consequence was a confident finding on the correct way to surface a validation
   * failure: a 400 carrying the application's own message read as an undeclared
   * disclosure. Two of Run 7's four false positives, and both of its *asserted* ones,
   * were this.
   */
  /*
   * The escape site is often the `return` statement rather than the expression, so the
   * status has to be looked for *inside* it. Walking up from the value found the block
   * and never the object literal it sat in.
   */
  if (ts.isReturnStatement(node)) return node.expression ? statusOf(node.expression) : null;
  if (ts.isObjectLiteralExpression(node)) {
    const declared = statusInObject(node);
    if (declared !== null) return declared;
  }
  if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const receiver = node.expression.expression;
      if (ts.isCallExpression(receiver) && STATUS_SETTER.has(calleeTail(receiver))) {
        const chained = numericValue(receiver.arguments[0]);
        if (chained !== null) return chained;
      }
    }
    for (const argument of node.arguments ?? []) {
      const direct = numericValue(argument);
      if (direct !== null && direct >= 100 && direct <= 599) return direct;
      if (ts.isObjectLiteralExpression(argument)) {
        const declared = statusInObject(argument);
        if (declared !== null) return declared;
      }
    }
    return null;
  }
  return statusNearby(node);
}

/** A `status`, `statusCode` or `httpStatus` property holding a number. */
function statusInObject(object: ts.ObjectLiteralExpression): number | null {
  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const key = property.name.getText().replace(/["']/g, "");
    if (!STATUS_FIELD.test(key)) continue;
    const value = numericValue(property.initializer);
    if (value !== null && value >= 100 && value <= 599) return value;
  }
  return null;
}

/** `ctx.status = 502` written beside the body assignment it belongs to. */
function statusNearby(node: ts.Node): number | null {
  /*
   * The object this value is being returned inside.
   *
   * Walked before the block scan below, because a handler that returns its response
   * carries the status in the same literal as the body — `{ status: 400, jsonBody: … }`
   * — and the block scan is looking for `res.status = 400`, an assignment that shape
   * never performs. Bounded by the nearest enclosing return so a status belonging to a
   * different branch of the same block cannot be borrowed.
   */
  for (let current: ts.Node | undefined = node.parent; current; current = current.parent) {
    if (ts.isObjectLiteralExpression(current)) {
      const declared = statusInObject(current);
      if (declared !== null) return declared;
    }
    if (ts.isReturnStatement(current) || ts.isFunctionLike(current)) break;
  }

  let block: ts.Node | undefined = node.parent;
  while (block && !ts.isBlock(block)) block = block.parent;
  if (!block) return null;
  let found: number | null = null;
  walk(block, (inner) => {
    if (found !== null) return;
    if (!ts.isBinaryExpression(inner) || inner.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
    if (!/\.(status|statusCode)$/.test(expressionName(inner.left))) return;
    const value = numericValue(inner.right);
    if (value !== null && value >= 100 && value <= 599) found = value;
  });
  return found;
}

function numericValue(node: ts.Node | undefined): number | null {
  if (!node) return null;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (ts.isParenthesizedExpression(node)) return numericValue(node.expression);
  return null;
}
