import ts from "typescript";
import { calleeTail, collect, expressionName, isConstantString } from "../ast/helpers.js";
import { functionsIn } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { browserTaint, FULL_ADDRESS } from "./browser-sources.js";
import { leadingLiteral } from "./client-dom-xss.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * A page that navigates to a destination taken from its own address.
 *
 * `perimeter-open-redirect` owns the server's redirect: a `redirect()` call with a
 * request value. The browser has its own, and it is written with assignment rather
 * than a call — `location.href = params.get("next")` — so a rule keyed on a method
 * name cannot see it, and its source is the address bar, which the request model
 * does not mark. The usual shape is a sign-in page that honours `?next=` after
 * authenticating, which is exactly where a convincing phishing link wants to land.
 *
 * Worse than the server form in one respect, which is why the remediation says so:
 * assigning a `javascript:` URL to `location` executes it, so an unvalidated
 * destination here is script execution as well as a redirect.
 */
const LOCATION_TARGET = /^(?:window\.|self\.|globalThis\.|document\.|top\.|parent\.)?location(?:\.href)?$/;
const LOCATION_CALL = /^(?:window\.|self\.|globalThis\.|document\.|top\.|parent\.)?location\.(?:assign|replace)$/;

export const clientOpenRedirect: Rule = {
  id: "client-open-redirect",
  category: "open_redirect",
  describes: "page code navigating to a destination read from its own address or an unchecked message",
  run(context: RuleContext) {
    if (!/location|window\.open/.test(context.file.text)) return;
    const taint = browserTaint(context.file);
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      const consider = (node: ts.Node, destination: ts.Expression | undefined, sink: string): void => {
        if (!destination || isConstantString(destination)) return;
        if (pinnedDestination(destination)) return;
        const origin = taint.originOf(destination);
        // The whole current address is on this origin by construction; navigating to
        // a rearrangement of it (dropping the fragment, say) cannot leave the site.
        if (!origin || origin.includes(FULL_ADDRESS)) return;
        const location = locationOf(context, node);
        if (reported.has(location.line)) return;
        reported.add(location.line);
        context.report({
          ruleId: "client-open-redirect",
          category: "open_redirect",
          title: `The page navigates to a destination taken from ${originNoun(origin)}`,
          severity: "medium",
          verification: "strong_evidence",
          summary: `${sink} receives a value read from ${origin}, and nothing between the two constrains it to this site. A link to this page can send the visitor anywhere, from a URL that starts with this application's own address.`,
          impact:
            "A phishing link borrows this site's address and reputation and then lands the victim on an attacker's page, typically a convincing copy of this sign-in. Because the browser executes a `javascript:` URL assigned to `location`, an unvalidated destination here can also run script in this origin.",
          remediation:
            "Accept only a same-site path: require a single leading `/`, reject `//` and `/\\`, and resolve it with `new URL(value, location.origin)` and compare the result's `origin` to `location.origin` before navigating. Where the set of destinations is known, map a short key to a fixed path instead of accepting a URL at all.",
          verificationPlan:
            "Open the page with the destination parameter set to `//example.org/` and to `javascript:alert(document.domain)`, complete whatever step triggers the navigation, and confirm in a browser that neither leaves this origin nor executes.",
          taxonomy: ["CWE-601", "OWASP-A01"],
          location,
          ...routeOf(context, node),
          evidence: [
            sourceEvidence(context, node, `${sink} navigates to whatever it is given; the value comes from ${origin} without a same-site check.`),
            { kind: "source", description: `Data flow: ${origin} reaches ${sink} in page code with no prefix, origin, or allowlist check on the path.` }
          ],
          reasoning: `Browser-supplied input (${origin}) reaches a navigation sink (${sink}). No guard constrains the destination, and its leading text is not a fixed same-site path.`
        });
      };

      for (const assignment of collect(fn, ts.isBinaryExpression)) {
        if (directScope(assignment) !== fn) continue;
        if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
        const target = expressionName(assignment.left as ts.Expression);
        if (!LOCATION_TARGET.test(target)) continue;
        consider(assignment, assignment.right, target);
      }

      for (const call of collect(fn, ts.isCallExpression)) {
        if (directScope(call) !== fn) continue;
        const name = expressionName(call.expression);
        if (LOCATION_CALL.test(name)) {
          consider(call, call.arguments[0], `${name}()`);
          continue;
        }
        if (calleeTail(call) === "open" && /^(?:window|self|globalThis)\.open$/.test(name)) {
          consider(call, call.arguments[0], `${name}()`);
        }
      }
    }
  }
};

/**
 * Is the destination fixed to this site, or to one named site, by its own text?
 *
 * `/account/${id}` cannot leave the origin; `/${next}` can (`next = "/evil.example"`
 * makes `//evil.example`), so a bare `/` is not enough and the literal has to carry
 * at least one path character after it. A fixed `https://host/` prefix pins the host.
 * A leading `#` or `?` stays on the current page.
 */
function pinnedDestination(destination: ts.Expression): boolean {
  const prefix = leadingLiteral(destination);
  if (prefix === null) return false;
  if (/^\/[^/\\]/.test(prefix)) return true;
  if (/^https?:\/\/[^/]+\//i.test(prefix)) return true;
  if (/^[#?]/.test(prefix)) return true;
  return false;
}

function originNoun(origin: string): string {
  if (/message/.test(origin)) return "a posted message";
  if (/referrer/.test(origin)) return "the referring page";
  if (/window\.name/.test(origin)) return "the window name";
  return "the page address";
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
