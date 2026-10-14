import ts from "typescript";
import { calleeName, calleeTail, collect, expressionName, walk } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, rootOf, taintOrigin } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { parameterIndex, taintThroughCallers } from "./caller-taint.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * Prototype pollution written as a *path*, not as a merge.
 *
 * `prototype-pollution-deep-merge` owns the recursive merge and the named merge
 * helpers (`_.merge`, `_.set`, `deepmerge`, …). Three shapes of the same defect are
 * outside it:
 *
 *  1. **Two computed keys in one assignment** — `settings[section][key] = value` with
 *     `section` from the request. `section = "__proto__"` makes the second index the
 *     shared prototype, and `key` names the property every object in the process now
 *     inherits.
 *  2. **An iterative path setter** — `path.split(".")` walked with `cursor =
 *     cursor[part]` and a final `cursor[last] = value`. The recursive form is the other
 *     rule's; the loop form, which is how most hand-written `setPath` helpers are
 *     actually written, has no recursion for it to recognise.
 *  3. **Library sinks it does not list** — `_.zipObjectDeep(paths, values)`,
 *     `flat.unflatten(input)`, jQuery's deep `$.extend(true, …)`, dot-prop's
 *     `setProperty(obj, path, …)`, `dottie.set`.
 *
 * Guards: any mention of `__proto__`, `constructor`, or `prototype` in the writing
 * function, an own-property check, a `Map`, or a target built with
 * `Object.create(null)`. A guard that is merely present is accepted, because judging
 * whether a hand-written key filter is complete is a question for the agent.
 */
const GUARD = /__proto__|["'`]constructor["'`]|["'`]prototype["'`]|\bprototype\b|hasOwnProperty|Object\.hasOwn|Object\.create\(\s*null\s*\)|new Map\b|Object\.freeze|isSafeKey|isPrototypePolluted|FORBIDDEN_KEYS|forbiddenKeys|blockedKeys/;

export const prototypePollutionPath: Rule = {
  id: "prototype-pollution-path",
  category: "prototype_pollution",
  describes: "caller-chosen property paths written through two computed keys, a loop, or a path-setting library call",
  run(context: RuleContext) {
    const reported = new Set<number>();
    const report = (node: ts.Node, origin: string, shape: string, sink: string, caller?: ts.CallExpression): void => {
      const location = locationOf(context, node);
      if (reported.has(location.line)) return;
      reported.add(location.line);
      context.report({
        ruleId: "prototype-pollution-path",
        category: "prototype_pollution",
        title: `A caller-chosen property path is written into an object by ${sink}`,
        severity: "high",
        verification: "strong_evidence",
        summary: `${shape} The path comes from ${origin}, and nothing refuses \`__proto__\`, \`constructor\`, or \`prototype\` as a segment, so a request can write a property onto \`Object.prototype\` that every object in the process then inherits.`,
        impact:
          "A polluted prototype changes behaviour everywhere at once: an `isAdmin` or `role` check that reads a missing property now finds the attacker's value, option objects gain settings nobody passed, and in some template and child-process paths this escalates to code execution. The process stays polluted until it restarts.",
        remediation:
          "Reject `__proto__`, `constructor`, and `prototype` as path segments before writing, and check `Object.hasOwn(target, segment)` when walking. Better, write into a `Map` or an object created with `Object.create(null)`, or validate the path against the fixed set of settings this endpoint is allowed to change.",
        verificationPlan:
          "In a local instance, send a request whose path or key is `__proto__.myrqenProbe` (or a section of `__proto__` and a key of `myrqenProbe`) with a harmless value, then confirm a fresh object such as `({}).myrqenProbe` is still undefined in the process — for example through an endpoint that echoes a default option. Restart the instance afterwards.",
        taxonomy: ["CWE-1321", "CWE-915", "OWASP-A08"],
        location,
        ...routeOf(context, caller ?? node),
        evidence: [
          sourceEvidence(context, node, `${sink} writes through a property path the caller chose.`),
          ...(caller ? [sourceEvidence(context, caller, `The path is supplied here, from ${origin}.`)] : []),
          { kind: "source", description: `Data flow: ${origin} chooses the property path written by ${sink}, with no reserved-key guard.` }
        ],
        reasoning: `${origin} reaches the key position of a property write (${sink}) and the writing function contains no __proto__/constructor/prototype guard, own-property check, null-prototype target, or Map.`
      });
    };

    for (const fn of functionsIn(context.file.source)) {
      if (ts.isSourceFile(fn)) continue;
      const fnText = fn.getText(context.file.source);
      const guarded = GUARD.test(fnText);
      const scope = analyzeFunction(context.file, fn);

      /** Where does this key come from: the function's own taint, or a caller one hop away. */
      const keyOrigin = (key: ts.Expression): { origin: string; caller?: ts.CallExpression } | null => {
        const own = taintOrigin(key, scope);
        if (own) return { origin: own };
        const root = rootOf(key);
        if (!root) return null;
        const index = parameterIndex(fn, root);
        if (index < 0) return null;
        const through = taintThroughCallers(context, fn, index);
        return through ? { origin: through.origin, caller: through.call } : null;
      };

      // 1. target[a][b] = value, with `a` caller-chosen.
      if (!guarded) {
        for (const assignment of collect(fn, ts.isBinaryExpression)) {
          if (innermost(assignment) !== fn) continue;
          if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
          const left = assignment.left;
          if (!ts.isElementAccessExpression(left) || !ts.isElementAccessExpression(left.expression)) continue;
          const outerKey = left.expression.argumentExpression;
          if (!outerKey || ts.isStringLiteralLike(outerKey) || ts.isNumericLiteral(outerKey)) continue;
          if (ts.isStringLiteralLike(left.argumentExpression)) {
            // `target[section]["name"] = v` still pollutes `name`; keep it.
          }
          const found = keyOrigin(outerKey);
          if (!found) continue;
          report(
            assignment,
            found.origin,
            `\`${left.getText(context.file.source)}\` indexes twice with a caller-chosen first key.`,
            `the assignment to ${expressionName(left.expression.expression) || "an object"}[…][…]`,
            found.caller
          );
        }
      }

      // 2. An iterative path setter: for (const part of path.split(".")) cursor = cursor[part] …
      if (!guarded) {
        const walker = iterativePathWalk(fn);
        if (walker) {
          const found = keyOrigin(walker.path);
          if (found) {
            report(
              walker.write,
              found.origin,
              `This function splits a dotted path and walks it segment by segment, creating and descending into objects, then writes the final segment.`,
              `the path walk in ${nameOf(fn) ?? "this function"}`,
              found.caller
            );
          }
        }
      }

      // 3. Library path setters the merge rule does not list.
      for (const call of collect(fn, ts.isCallExpression)) {
        if (innermost(call) !== fn) continue;
        const sink = librarySink(call);
        if (!sink) continue;
        const found = keyOrigin(sink.argument);
        if (!found) continue;
        report(call, found.origin, sink.shape, `${calleeName(call)}()`, found.caller);
      }
    }
  }
};

function librarySink(call: ts.CallExpression): { argument: ts.Expression; shape: string } | null {
  const name = calleeName(call);
  const tail = calleeTail(call);
  const args = call.arguments;
  if (tail === "zipObjectDeep" && args[0]) {
    return { argument: args[0], shape: "`zipObjectDeep` builds nested objects from the property paths it is given." };
  }
  if (tail === "unflatten" && args[0]) {
    return { argument: args[0], shape: "`unflatten` turns dotted keys into nested objects, segment by segment." };
  }
  if (/^(?:\$|jQuery)\.extend$/.test(name) && args[0] && args[0].kind === ts.SyntaxKind.TrueKeyword) {
    const source = args.slice(2).find(Boolean) ?? args[args.length - 1];
    return source ? { argument: source, shape: "A deep `$.extend(true, …)` copies nested keys recursively, including `__proto__`." } : null;
  }
  if ((name === "setProperty" || /^(?:dotProp|dottie|dot)\.(?:set|setProperty|str)$/.test(name)) && args[1]) {
    return { argument: args[1], shape: "A dotted-path setter creates and descends into objects for each segment of the path it is given." };
  }
  return null;
}

/**
 * The loop form of a path setter: segments from `.split(...)` of some value,
 * walked with `cursor = cursor[segment]`, and a computed write at the end.
 */
function iterativePathWalk(fn: ts.Node): { path: ts.Expression; write: ts.Node } | null {
  const body = (fn as ts.FunctionLikeDeclaration).body;
  if (!body) return null;
  let pathSource: ts.Expression | null = null;
  walk(body, (node) => {
    if (pathSource) return;
    if (ts.isCallExpression(node) && calleeTail(node) === "split" && ts.isPropertyAccessExpression(node.expression)) {
      pathSource = node.expression.expression;
    }
  });
  if (!pathSource) return null;

  let descends = false;
  let write: ts.Node | null = null;
  walk(body, (node) => {
    if (!ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
    // cursor = cursor[part]  /  cursor = cursor[part] ??= {}
    if (ts.isIdentifier(node.left) && ts.isElementAccessExpression(node.right) && ts.isIdentifier(node.right.expression) && node.right.expression.text === node.left.text) {
      descends = true;
    }
    if (ts.isElementAccessExpression(node.left) && ts.isIdentifier(node.left.expression) && !ts.isStringLiteralLike(node.left.argumentExpression)) {
      write ??= node;
    }
  });
  if (!descends || !write) return null;
  return { path: pathSource, write };
}

function nameOf(fn: ts.Node): string | null {
  if (ts.isFunctionDeclaration(fn) && fn.name) return `${fn.name.text}()`;
  const parent = fn.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return `${parent.name.text}()`;
  return null;
}

function innermost(node: ts.Node): ts.Node {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) || ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
      return current;
    }
    if (ts.isSourceFile(current)) return current;
    current = current.parent;
  }
  return node.getSourceFile();
}
