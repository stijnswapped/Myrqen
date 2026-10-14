import ts from "typescript";
import { calleeTail, collect, expressionName, isConstantString, walk } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, isHtmlSafe, resolveExpression, rootOf, taintOrigin } from "../ast/taint.js";
import { declarationFor } from "./browser-sources.js";
import { routeOf } from "./attribution.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * A raw caller value sent as the body of a response declared to be HTML.
 *
 * `reflected-xss` judges a response body by whether it *looks* like markup: an
 * angle bracket in the text at the sink, or one binding away. That is the right
 * test when the content type is implicit, and it is silent by design on
 * `c.html(q)`, `res.type("html").send(name)`, or a `Content-Type: text/html` header
 * followed by `res.end(message)` — the body holds no markup until the caller sends
 * some, and the handler has already told the browser to parse it as a document.
 *
 * So this rule keys on the declaration instead of the shape, and covers exactly the
 * complement: a tainted body that is *not* markup-shaped, in a response the code
 * itself declared HTML. One defect, one rule, one finding.
 */
const HTML_MARKUP = /<\s*(html|body|div|span|h[1-6]|p|ul|li|table|script|a|img|form|input)\b|<\/\s*\w+\s*>/i;
const BODY_WRITERS = new Set(["send", "end", "write"]);

export const htmlContentTypeReflection: Rule = {
  id: "html-content-type-reflection",
  category: "reflected_cross_site_scripting",
  describes: "a raw caller value written as the body of a response declared text/html",
  run(context: RuleContext) {
    if (!/html/i.test(context.file.text)) return;
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      if (ts.isSourceFile(fn)) continue;
      const scope = analyzeFunction(context.file, fn);
      const declaresHtmlHeader = setsHtmlContentType(fn);

      const consider = (node: ts.Node, body: ts.Expression | undefined, sink: string): void => {
        if (!body || isConstantString(body)) return;
        // Markup-shaped bodies belong to reflected-xss.
        if (HTML_MARKUP.test(body.getText(context.file.source))) return;
        if (HTML_MARKUP.test(resolveExpression(body, scope).getText(context.file.source))) return;
        if (isHtmlSafe(body, scope)) return;
        if (helperParameter(body, fn)) return;
        const origin = taintOrigin(body, scope);
        if (!origin) return;
        const location = locationOf(context, node);
        if (reported.has(location.line)) return;
        reported.add(location.line);
        context.report({
          ruleId: "html-content-type-reflection",
          category: "reflected_cross_site_scripting",
          title: `A caller-controlled value is sent as an HTML document by ${sink}`,
          severity: "medium",
          verification: "strong_evidence",
          summary: `This response is declared \`text/html\`, and its body is a value derived from ${origin} with nothing escaping it. The handler writes no markup of its own, so the caller supplies the entire document the browser parses.`,
          impact:
            "A crafted link returns a page whose content the attacker wrote, in this application's origin: script in it runs with the victim's session and can act as them.",
          remediation:
            "Send the value as `text/plain` or as JSON if it is data, or escape it before it enters an HTML body. Declaring a response HTML is a promise that everything in it was meant to be markup.",
          verificationPlan:
            "Request the endpoint with a markup probe such as `<img src=x onerror=alert(1)>` in the parameter and confirm the response is either not `text/html` or contains only the escaped form.",
          taxonomy: ["CWE-79", "OWASP-A03"],
          location,
          ...routeOf(context, node),
          evidence: [
            sourceEvidence(context, node, `The body is caller-controlled text and the response is declared text/html.`),
            { kind: "source", description: `Data flow: ${origin} reaches ${sink} in the same function with no escaping call on the path.` }
          ],
          reasoning: `Taint from ${origin} is the body of a response the handler declared HTML; the body is not markup-shaped, so reflected-xss does not read it.`
        });
      };

      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        const name = expressionName(call.expression);
        // Hono: c.html(value).
        if (tail === "html" && /^(?:c|ctx|context)$/.test(name.split(".")[0] ?? "") && name.split(".").length === 2) {
          consider(call, call.arguments[0], `${name}()`);
          continue;
        }
        if (!BODY_WRITERS.has(tail)) continue;
        if (!ts.isPropertyAccessExpression(call.expression)) continue;
        const receiver = call.expression.expression;
        // res.type("html").send(x), reply.type("text/html").send(x),
        // reply.header("content-type", "text/html").send(x)
        if (ts.isCallExpression(receiver) && chainDeclaresHtml(receiver)) {
          consider(call, call.arguments[0], `${name}()`);
          continue;
        }
        // res.setHeader("Content-Type", "text/html"); … res.end(x)
        if (declaresHtmlHeader && ts.isIdentifier(receiver) && /^(?:res|response|reply)$/.test(receiver.text)) {
          consider(call, call.arguments[0], `${name}()`);
        }
      }

      // new Response(value, { headers: { "Content-Type": "text/html" } }) with a non-markup value.
      for (const constructed of collect(fn, ts.isNewExpression)) {
        if (!/^(?:Next)?Response$/.test(expressionName(constructed.expression))) continue;
        const init = constructed.arguments?.[1];
        if (!init || !/text\/html/i.test(init.getText(context.file.source))) continue;
        consider(constructed, constructed.arguments?.[0], `new ${expressionName(constructed.expression)}()`);
      }
    }
  }
};

/**
 * Is the body a parameter of a helper rather than something read off a request?
 *
 * `function html(response, status, body) { …; response.end(body) }` is a writer: the
 * taint model marks a parameter called `body` as request data by name, but what this
 * function sends is whatever its caller passed, and the caller is where a missing
 * escape would be. `reflected-xss` already follows layout helpers back to that call
 * site, so judging the helper's own parameter here would report the writer instead
 * of the defect.
 */
function helperParameter(body: ts.Expression, fn: ts.Node): boolean {
  const root = rootOf(body);
  if (!root || REQUEST_OBJECT.test(root)) return false;
  const identifier = collect(body, ts.isIdentifier).find((candidate) => candidate.text === root);
  if (!identifier) return false;
  const declaration = declarationFor(identifier);
  return Boolean(declaration && ts.isParameter(declaration) && declaration.parent === fn);
}

const REQUEST_OBJECT = /^(?:req|request|ctx|c|context|event)$/;

/** Does this chain set an HTML content type before the body is written? */
function chainDeclaresHtml(call: ts.CallExpression): boolean {
  let current: ts.Expression = call;
  for (let depth = 0; depth < 6 && ts.isCallExpression(current); depth += 1) {
    const tail = calleeTail(current);
    const args = current.arguments;
    if ((tail === "type" || tail === "contentType") && args[0] && ts.isStringLiteralLike(args[0]) && /^(?:html|\.html|text\/html)/i.test(args[0].text)) {
      return true;
    }
    if (["header", "set", "setHeader"].includes(tail) && args[0] && args[1] && ts.isStringLiteralLike(args[0]) && ts.isStringLiteralLike(args[1])) {
      if (args[0].text.toLowerCase() === "content-type" && /text\/html/i.test(args[1].text)) return true;
    }
    if (!ts.isPropertyAccessExpression(current.expression)) return false;
    current = current.expression.expression;
  }
  return false;
}

/** Does this handler set `Content-Type: text/html` on its response as a statement? */
function setsHtmlContentType(fn: ts.Node): boolean {
  let declared = false;
  walk(fn, (node) => {
    if (declared || !ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    const [first, second] = node.arguments;
    if (["setHeader", "set", "header"].includes(tail) && first && second && ts.isStringLiteralLike(first) && ts.isStringLiteralLike(second)) {
      if (first.text.toLowerCase() === "content-type" && /text\/html/i.test(second.text)) declared = true;
    }
    if ((tail === "type" || tail === "contentType") && first && ts.isStringLiteralLike(first) && /^(?:html|\.html|text\/html)/i.test(first.text)) {
      declared = true;
    }
    if (tail === "writeHead" && node.arguments.some((argument) => ts.isObjectLiteralExpression(argument) && /content-type["']?\s*:\s*["']text\/html/i.test(argument.getText()))) {
      declared = true;
    }
  });
  return declared;
}
