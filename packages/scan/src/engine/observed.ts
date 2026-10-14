/**
 * Is this value the caller's because the engine *read* it, or only because it assumed so?
 *
 * The taint model in `ast/taint.ts` assumes that an unknown function handed caller data
 * returns caller data. Inside one function that assumption is what keeps ordinary
 * handlers visible — `const body = await readBody(req)` would otherwise end every flow.
 * Across a call boundary it is the assumption that invents flows: stacked on a hop, a
 * validating helper's return becomes "caller data handed to a second function", and the
 * second function's sink is reported for a value the first one constrained. An earlier
 * widening of this engine did exactly that to a validated executable path in this
 * project's own source, and was closed by requiring *observed* taint rather than
 * *inferred* taint across a boundary. `rules/injection.ts` encodes the rule for its own
 * one-hop bridge; this is the same rule, for every boundary the engine crosses.
 *
 * Observed means every step from the value back to its origin is one the engine can read:
 * a parameter or request object, a property of one, a local initialised from one, a
 * transparent string transformation, a method on an observed value, an accessor the entry
 * point declared — or a call into **a project function whose own body was read** and
 * found to hand that argument back (`ReturnSummary.observed`).
 */
import ts from "typescript";
import { calleeName, calleeTail, dynamicParts } from "../ast/helpers.js";
import { taintOrigin, type TaintScope } from "../ast/taint.js";
import { schemaParse } from "./validation.js";

/** Standard transformations that hand back the value they were given. */
const TRANSPARENT_CALLS = new Set([
  "String",
  "decodeURI",
  "decodeURIComponent",
  "encodeURI",
  "encodeURIComponent",
  "JSON.parse",
  "JSON.stringify",
  "trim",
  "trimStart",
  "trimEnd",
  "toString",
  "toLowerCase",
  "toUpperCase",
  "normalize",
  "slice",
  "substring",
  "substr",
  "replace",
  "replaceAll",
  "split",
  "join",
  "at",
  "concat",
  "padStart",
  "padEnd",
  "Object.fromEntries",
  "Object.assign",
  "Object.values",
  "Object.entries",
  "Array.from",
  "structuredClone"
]);

function unwrap(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAwaitExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isTypeAssertionExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/** The initialiser of a destructuring declaration that binds `name`, in this scope. */
function destructuringSource(name: string, scope: TaintScope): ts.Expression | undefined {
  const body = (scope.fn as ts.FunctionLikeDeclaration).body ?? (ts.isSourceFile(scope.fn) ? scope.fn : undefined);
  if (!body) return undefined;
  let found: ts.Expression | undefined;
  const visit = (node: ts.Node): void => {
    if (found) return;
    if (ts.isVariableDeclaration(node) && node.initializer && !ts.isIdentifier(node.name) && bindsName(node.name, name)) {
      found = node.initializer;
      return;
    }
    node.forEachChild(visit);
  };
  visit(body);
  return found;
}

function bindsName(pattern: ts.BindingName, name: string): boolean {
  if (ts.isIdentifier(pattern)) return pattern.text === name;
  return pattern.elements.some((element) => !ts.isOmittedExpression(element) && bindsName(element.name, name));
}

/**
 * Does the engine *read* this value as the caller's, rather than infer it?
 *
 * `scope.file.returnSummary`, when the scan installed one, answers for calls into project
 * functions: a call is observed when its callee's body hands the argument back.
 */
export function observedCallerValue(node: ts.Node, scope: TaintScope, depth = 0): boolean {
  if (depth > 8) return false;
  const bare = unwrap(node);

  if (ts.isIdentifier(bare)) {
    if (scope.cleared.has(bare.text) || scope.validated?.has(bare.text)) return false;
    const initializer = scope.initializers.get(bare.text);
    if (initializer) return observedCallerValue(initializer, scope, depth + 1);
    const destructured = destructuringSource(bare.text, scope);
    if (destructured) return observedCallerValue(destructured, scope, depth + 1);
    return scope.roots.has(bare.text) || scope.taintedCollections.has(bare.text);
  }
  if (ts.isPropertyAccessExpression(bare) || ts.isElementAccessExpression(bare)) {
    if (taintOrigin(bare, scope) === null) return false;
    // A field of something observed is observed; a field of an inferred value is not.
    const base = unwrap(bare.expression);
    if (ts.isIdentifier(base) || ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base) || ts.isCallExpression(base)) {
      return observedCallerValue(base, scope, depth + 1) || pathSeeded(bare, scope);
    }
    return true;
  }
  if (ts.isTemplateExpression(bare) || ts.isBinaryExpression(bare)) {
    return dynamicParts(bare).some((part) => observedCallerValue(part, scope, depth + 1));
  }
  if (ts.isConditionalExpression(bare)) {
    return observedCallerValue(bare.whenTrue, scope, depth + 1) || observedCallerValue(bare.whenFalse, scope, depth + 1);
  }
  if (ts.isObjectLiteralExpression(bare)) {
    return bare.properties.some((property) => {
      if (ts.isPropertyAssignment(property)) return observedCallerValue(property.initializer, scope, depth + 1);
      if (ts.isShorthandPropertyAssignment(property)) return observedCallerValue(property.name, scope, depth + 1);
      if (ts.isSpreadAssignment(property)) return observedCallerValue(property.expression, scope, depth + 1);
      return false;
    });
  }
  if (ts.isArrayLiteralExpression(bare)) {
    return bare.elements.some((element) =>
      observedCallerValue(ts.isSpreadElement(element) ? element.expression : element, scope, depth + 1)
    );
  }
  if (ts.isNewExpression(bare)) {
    // `new URL(request.url)` parses the caller's string and hands back its parts.
    if (ts.isIdentifier(bare.expression) && /^URL(SearchParams)?$/.test(bare.expression.text)) {
      return (bare.arguments ?? []).some((argument) => observedCallerValue(argument, scope, depth + 1));
    }
    return false;
  }
  if (ts.isCallExpression(bare)) {
    if (taintOrigin(bare, scope) === null) return false;
    const receiver = ts.isPropertyAccessExpression(bare.expression) ? bare.expression.expression : undefined;
    // `body.trim()`, `req.header("x")`, `searchParams.get("q")`.
    if (receiver && observedCallerValue(receiver, scope, depth + 1)) return true;
    // `Body.parse(req.body)`: a schema this scan can read hands back the value it was given,
    // minus what it constrains — and a constrained field never reaches here, because the
    // taint model already reads it as clean.
    const facts = scope.schemaFacts;
    const parsed = facts ? schemaParse(bare, facts.resolve) : null;
    if (parsed) return observedCallerValue(parsed.input, scope, depth + 1);
    // A free accessor the entry point declared, such as h3's `readBody(event)`.
    if (ts.isIdentifier(bare.expression) && scope.accessors.has(bare.expression.text)) {
      return bare.arguments.some((argument) => observedCallerValue(argument, scope, depth + 1));
    }
    if (TRANSPARENT_CALLS.has(calleeName(bare)) || TRANSPARENT_CALLS.has(calleeTail(bare))) {
      return bare.arguments.some((argument) => observedCallerValue(argument, scope, depth + 1));
    }
    // A project function whose body was read: observed when it hands this argument back.
    const summarise = scope.file?.returnSummary;
    if (summarise) {
      return bare.arguments.some((argument, index) => {
        if (!observedCallerValue(argument, scope, depth + 1)) return false;
        return summarise(bare, index)?.observed === true;
      });
    }
    return false;
  }
  return false;
}

function pathSeeded(node: ts.Node, scope: TaintScope): boolean {
  if (!scope.taintedPaths || scope.taintedPaths.size === 0) return false;
  const text = dotted(node);
  if (!text) return false;
  for (const prefix of scope.taintedPaths.keys()) if (text === prefix || text.startsWith(`${prefix}.`)) return true;
  return false;
}

function dotted(node: ts.Node): string | null {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) {
    const base = dotted(node.expression);
    return base ? `${base}.${node.name.text}` : null;
  }
  return null;
}

/** `taintOrigin`, but only when the value is observed rather than inferred. */
export function observedOrigin(node: ts.Node, scope: TaintScope): string | null {
  const origin = taintOrigin(node, scope);
  if (!origin) return null;
  return observedCallerValue(node, scope) ? origin : null;
}
