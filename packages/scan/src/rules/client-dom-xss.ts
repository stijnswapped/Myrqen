import ts from "typescript";
import { calleeName, calleeTail, collect, expressionName, isConstantString } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, taintOrigin } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { browserTaint } from "./browser-sources.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * DOM-based cross-site scripting: input the *browser* supplies reaching a sink the
 * browser parses as HTML.
 *
 * `dom-html-injection` already owns these sinks for values that came through an
 * entry point — an extension message, a worker event. What it cannot see is the
 * commonest source in page code: the address bar. `location.hash` is not a
 * parameter of anything, so the request-shaped taint model never marks it, and a
 * page that writes its own fragment into the document was invisible. This rule is
 * the same sinks with the browser's sources (`./browser-sources.ts`), and it
 * declines any sink the request model already tainted, so one defect is one finding.
 *
 * Sinks, from the DOM and jQuery documentation rather than from any case:
 *  - `innerHTML`, `outerHTML`, `srcdoc` assignment, and `setAttribute("srcdoc", …)`;
 *  - `insertAdjacentHTML`, `document.write` / `writeln`, `createContextualFragment`,
 *    `setHTMLUnsafe`;
 *  - jQuery's `.html`, `.append`, `.prepend`, `.before`, `.after`, `.replaceWith`
 *    and the `$(markup)` constructor;
 *  - React's `dangerouslySetInnerHTML`, where the other rule's heuristics did not
 *    already claim it.
 */
const ASSIGNED_SINKS = new Set(["innerHTML", "outerHTML", "srcdoc"]);
const CALL_SINKS = new Set(["insertAdjacentHTML", "createContextualFragment", "setHTMLUnsafe", "write", "writeln"]);
const JQUERY_SINKS = new Set(["html", "append", "prepend", "before", "after", "replaceWith", "wrap", "wrapAll"]);
const DOCUMENT_RECEIVER = /^(?:document|window\.document|globalThis\.document|doc)$/;
/** The text the other JSX rule already reads as caller data; see `dangerous-inner-html`. */
const ALREADY_GUESSED = /props|params|search|query|data|content|body/i;

export const clientDomXss: Rule = {
  id: "client-dom-xss",
  category: "dom_html_injection",
  describes: "input from the page address, referrer, window name, or an unchecked message reaching an HTML sink",
  run(context: RuleContext) {
    const taint = browserTaint(context.file);
    // Most files read nothing from the browser at all; skip them before any walk.
    if (!/location|referrer|document\.URL|documentURI|window\.name|onmessage|"message"|'message'|useSearchParams|useParams|useLocation|useRouter|useRoute|\$route|searchParams/.test(context.file.text)) {
      return;
    }
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);

      const consider = (node: ts.Node, written: ts.Expression | undefined, sink: string): void => {
        if (!written || isConstantString(written)) return;
        // The request model owns anything it can already see; reporting it here too
        // would make one defect two findings.
        if (taintOrigin(written, scope)) return;
        const origin = taint.originOf(written);
        if (!origin) return;
        const location = locationOf(context, node);
        if (reported.has(location.line)) return;
        reported.add(location.line);
        context.report({
          ruleId: "client-dom-xss",
          category: "dom_html_injection",
          title: `Input from the browser is written to the document through ${sink}`,
          severity: "high",
          verification: "strong_evidence",
          summary: `A value read from ${origin} reaches ${sink}, which parses it as HTML, and nothing on the way escapes or sanitises it. Whoever composes the link — or, for a message, whichever window posts it — controls markup in this page.`,
          impact:
            "A crafted link runs script in this application's origin with the victim's session when they open it: reading what the page can read, and acting as them. No server request is involved, so server-side filtering and logging see nothing.",
          remediation: `Write the value with \`textContent\` (or as a React child) so it is treated as text. Where markup is genuinely required, pass it through a maintained sanitiser such as DOMPurify immediately before ${sink}. For a message listener, check \`event.origin\` against the exact origins this page expects before reading \`event.data\`.`,
          verificationPlan: `Open the page with a markup probe in the source — for example \`#<img src=x onerror=alert(document.domain)>\` for the fragment, or a crafted query parameter — and confirm in a browser that the probe renders as text and no element is created. For a message source, post the probe from another origin with \`window.postMessage\`.`,
          taxonomy: ["CWE-79", "OWASP-A03"],
          location,
          ...routeOf(context, node),
          evidence: [
            sourceEvidence(context, node, `${sink} parses its input as HTML; the value is read from ${origin} with no escaping or sanitising call between them.`),
            { kind: "source", description: `Data flow: ${origin} reaches ${sink} in page code, with no escaper, sanitiser, or shape guard on the path.` }
          ],
          reasoning: `Browser-supplied input (${origin}) reaches ${sink}. The request-shaped taint model does not mark this source, so no other rule reports this line.`
        });
      };

      for (const assignment of collect(fn, ts.isBinaryExpression)) {
        if (enclosingScope(assignment) !== fn) continue;
        const operator = assignment.operatorToken.kind;
        if (operator !== ts.SyntaxKind.EqualsToken && operator !== ts.SyntaxKind.PlusEqualsToken) continue;
        if (!ts.isPropertyAccessExpression(assignment.left)) continue;
        const property = assignment.left.name.text;
        if (!ASSIGNED_SINKS.has(property)) continue;
        consider(assignment, assignment.right, property);
      }

      for (const call of collect(fn, ts.isCallExpression)) {
        if (enclosingScope(call) !== fn) continue;
        const tail = calleeTail(call);
        if (tail === "setAttribute") {
          const attribute = call.arguments[0];
          if (attribute && ts.isStringLiteralLike(attribute) && attribute.text.toLowerCase() === "srcdoc") {
            consider(call, call.arguments[1], "the srcdoc attribute");
          }
          continue;
        }
        if (CALL_SINKS.has(tail)) {
          consider(call, markupArgument(call), `${calleeName(call)}()`);
          continue;
        }
        if (JQUERY_SINKS.has(tail) && isJQueryChain(call)) {
          consider(call, call.arguments[0], `jQuery .${tail}()`);
          continue;
        }
        if (ts.isIdentifier(call.expression) && (call.expression.text === "$" || call.expression.text === "jQuery")) {
          // `$(location.hash)` builds elements when the string looks like markup. A
          // fixed prefix that is not `<` — `$("#" + id)` — makes it a selector since
          // jQuery 1.9, which is a different (and much smaller) problem.
          const argument = call.arguments[0];
          if (argument && leadingLiteral(argument) !== null && !leadingLiteral(argument)!.trimStart().startsWith("<")) continue;
          consider(call, argument, `${call.expression.text}()`);
        }
      }

      for (const attribute of collect(fn, ts.isJsxAttribute)) {
        if (enclosingScope(attribute) !== fn) continue;
        if (attribute.name.getText(context.file.source) !== "dangerouslySetInnerHTML") continue;
        const initializer = attribute.initializer;
        if (!initializer || !ts.isJsxExpression(initializer) || !initializer.expression) continue;
        const rendered = htmlProperty(initializer.expression);
        if (!rendered) continue;
        if (ALREADY_GUESSED.test(rendered.getText(context.file.source))) continue;
        consider(attribute, rendered, "dangerouslySetInnerHTML");
      }
    }
  }
};

/** Which argument carries markup, or undefined when this call is not the sink. */
function markupArgument(call: ts.CallExpression): ts.Expression | undefined {
  const tail = calleeTail(call);
  if (tail === "insertAdjacentHTML") return call.arguments[1];
  if (tail === "write" || tail === "writeln") {
    const receiver = ts.isPropertyAccessExpression(call.expression) ? expressionName(call.expression.expression) : "";
    return DOCUMENT_RECEIVER.test(receiver) ? call.arguments[0] : undefined;
  }
  return call.arguments[0];
}

/** `$(selector).html(x)`, `jQuery("#a").append(x)`, or a `$panel.html(x)` held in a `$`-named binding. */
function isJQueryChain(call: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  let receiver: ts.Expression = call.expression.expression;
  while (ts.isCallExpression(receiver) && ts.isPropertyAccessExpression(receiver.expression)) {
    receiver = receiver.expression.expression;
  }
  if (ts.isCallExpression(receiver) && ts.isIdentifier(receiver.expression)) {
    return receiver.expression.text === "$" || receiver.expression.text === "jQuery";
  }
  return ts.isIdentifier(receiver) && /^\$[A-Za-z_]/.test(receiver.text);
}

/** The fixed text an expression starts with, or null when it starts with a variable part. */
export function leadingLiteral(node: ts.Expression): string | null {
  if (ts.isStringLiteralLike(node)) return node.text;
  if (ts.isTemplateExpression(node)) return node.head.text.length > 0 ? node.head.text : null;
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) return leadingLiteral(node.left);
  if (ts.isParenthesizedExpression(node)) return leadingLiteral(node.expression);
  return null;
}

function htmlProperty(expression: ts.Expression): ts.Expression | null {
  if (!ts.isObjectLiteralExpression(expression)) return null;
  for (const property of expression.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const key = property.name.getText().replace(/["']/g, "");
    if (key === "__html") return property.initializer;
  }
  return null;
}

/**
 * The function (or file) a node is directly inside, so each sink is judged once,
 * by the scope that owns it, rather than once per enclosing function.
 */
function enclosingScope(node: ts.Node): ts.Node {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (
      ts.isFunctionDeclaration(current) ||
      ts.isFunctionExpression(current) ||
      ts.isArrowFunction(current) ||
      ts.isMethodDeclaration(current)
    ) {
      return current;
    }
    if (ts.isSourceFile(current)) return current;
    current = current.parent;
  }
  return node.getSourceFile();
}
