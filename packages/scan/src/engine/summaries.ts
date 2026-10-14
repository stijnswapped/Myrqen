/**
 * Function summaries: does a project function hand an argument back to its caller?
 *
 * The taint model's default for a call it cannot see into is that the result carries the
 * caller data handed to it. That keeps flows through body parsers and helpers alive, and
 * it is wrong for exactly the functions a careful developer writes: a validator that
 * returns a vetted constant, a parser that returns a number, a resolver that refuses
 * anything outside an allowlist. Reporting the sink after such a helper is a confident
 * finding on code doing the right thing.
 *
 * When the callee is a function this project declares, the engine no longer has to
 * assume — it can read the body. Each summary is computed once per function and argument
 * position, by analysing the callee with that one parameter seeded and asking what its
 * `return` statements carry:
 *
 *  - `tainted` — does any return carry the argument's taint, by the same over-approximating
 *    model every rule uses? `false` lets the taint model *clear* the call's result.
 *  - `observed` — does any return hand the argument back by steps the engine reads rather
 *    than infers? Only then may the result cross a further call boundary (see
 *    `observed.ts`).
 *
 * The summary only ever replaces the default for a resolved project function. A library
 * call, an unresolvable call and a recursive call keep the default exactly.
 */
import ts from "typescript";
import type { ParsedFile } from "../ast/parse.js";
import { analyzeFunction, isAllowlistedTernary, isSanitizingCall, isSchemaConstrained, taintOrigin, type TaintScope } from "../ast/taint.js";
import { resolveCall } from "./callgraph.js";
import type { ModuleGraph } from "./modules.js";
import { observedCallerValue } from "./observed.js";

export interface ReturnSummary {
  /** A return statement carries the argument's taint (the model's usual sense). */
  tainted: boolean;
  /** A return statement hands the argument back by steps the engine reads. */
  observed: boolean;
}

const SUMMARY_SEED = "the argument a caller passed";

function unwrap(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAwaitExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/** Return expressions of this function, not of functions nested inside it. */
export function returnExpressions(fn: ts.FunctionLikeDeclaration): ts.Expression[] {
  const body = fn.body;
  if (!body) return [];
  if (!ts.isBlock(body)) return [body];
  const found: ts.Expression[] = [];
  const visit = (node: ts.Node): void => {
    if (node !== body && ts.isFunctionLike(node)) return;
    if (ts.isClassLike(node)) return;
    if (ts.isReturnStatement(node) && node.expression) found.push(node.expression);
    node.forEachChild(visit);
  };
  visit(body);
  return found;
}

/**
 * Every local binding whose value is, syntactically, derived from the seeded parameter —
 * through any construct at all, including ones the taint model does not understand.
 *
 * This is the half of the summary that refuses to clear what it cannot read. `return new
 * Promise((resolve) => { ... resolve(JSON.parse(body)) })` is how a body reader is written,
 * and the taint model has no rule for a `new Promise`, so it reports no taint in the
 * return; without this the summary would call the reader clean and every handler built
 * on it would go silent.
 */
function derivedNames(fn: ts.FunctionLikeDeclaration, seed: string): Set<string> {
  const derived = new Set<string>([seed]);
  const body = fn.body;
  if (!body) return derived;
  const declarations: Array<{ names: string[]; value: ts.Node }> = [];
  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      declarations.push({ names: bindingNames(node.name), value: node.initializer });
    } else if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
      declarations.push({ names: [node.left.text], value: node.right });
    }
    node.forEachChild(visit);
  };
  visit(body);
  for (let round = 0; round < 4; round += 1) {
    let grew = false;
    for (const declaration of declarations) {
      if (declaration.names.every((name) => derived.has(name))) continue;
      if (!mentions(declaration.value, derived)) continue;
      for (const name of declaration.names) {
        if (!derived.has(name)) {
          derived.add(name);
          grew = true;
        }
      }
    }
    if (!grew) break;
  }
  return derived;
}

function bindingNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const out: string[] = [];
  for (const element of name.elements) if (!ts.isOmittedExpression(element)) out.push(...bindingNames(element.name));
  return out;
}

function mentions(node: ts.Node, names: Set<string>): boolean {
  let found = false;
  const visit = (current: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(current) && names.has(current.text)) {
      // `obj.name` mentions `obj`, not a binding called `name`.
      const parent = current.parent;
      if (!(parent && ts.isPropertyAccessExpression(parent) && parent.name === current)) {
        found = true;
        return;
      }
    }
    current.forEachChild(visit);
  };
  visit(node);
  return found;
}

const BOOLEAN_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.LessThanToken,
  ts.SyntaxKind.LessThanEqualsToken,
  ts.SyntaxKind.GreaterThanToken,
  ts.SyntaxKind.GreaterThanEqualsToken,
  ts.SyntaxKind.InstanceOfKeyword,
  ts.SyntaxKind.InKeyword
]);

/**
 * Is this returned value provably free of the seeded argument?
 *
 * Clean only when the model finds no taint in it *and* either it does not mention the
 * argument at all, or it mentions it only through a shape the model is known to sanitise:
 * a coercion, an escaper, a constant-table read, an allowlist ternary, a comparison, a
 * length. Anything else that mentions the argument is assumed to carry it.
 */
function returnsClean(node: ts.Node, scope: TaintScope, derived: Set<string>, depth = 0): boolean {
  if (depth > 8) return false;
  const bare = unwrap(node);
  // Shapes that sanitise whatever they are handed, checked before the model's verdict,
  // which does not read an allowlist ternary as a guard outside a declaration.
  if (ts.isConditionalExpression(bare) && isAllowlistedTernary(bare)) return true;
  if (ts.isCallExpression(bare) && isSanitizingCall(bare, scope)) return true;
  // `Body.parse(raw).id` where the schema constrains `id`.
  if (isSchemaConstrained(bare, scope)) return true;
  if (taintOrigin(bare, scope) !== null) return false;
  if (!mentions(bare, derived)) return true;
  if (ts.isIdentifier(bare)) return scope.cleared.has(bare.text);
  if (ts.isCallExpression(bare)) {
    if (isSanitizingCall(bare, scope)) return true;
    const summarise = scope.file?.returnSummary;
    if (!summarise) return false;
    return bare.arguments.every((argument, index) => !mentions(argument, derived) || summarise(bare, index)?.tainted === false);
  }
  if (ts.isPrefixUnaryExpression(bare) && bare.operator === ts.SyntaxKind.ExclamationToken) return true;
  if (ts.isTypeOfExpression(bare)) return true;
  if (ts.isBinaryExpression(bare)) {
    if (BOOLEAN_OPERATORS.has(bare.operatorToken.kind)) return true;
    return returnsClean(bare.left, scope, derived, depth + 1) && returnsClean(bare.right, scope, derived, depth + 1);
  }
  if (ts.isConditionalExpression(bare)) {
    if (isAllowlistedTernary(bare)) return true;
    return returnsClean(bare.whenTrue, scope, derived, depth + 1) && returnsClean(bare.whenFalse, scope, derived, depth + 1);
  }
  if (ts.isTemplateExpression(bare)) {
    return bare.templateSpans.every((span) => returnsClean(span.expression, scope, derived, depth + 1));
  }
  if (ts.isPropertyAccessExpression(bare) && (bare.name.text === "length" || bare.name.text === "size")) return true;
  if (ts.isObjectLiteralExpression(bare)) {
    return bare.properties.every((property) => {
      if (ts.isPropertyAssignment(property)) return returnsClean(property.initializer, scope, derived, depth + 1);
      if (ts.isShorthandPropertyAssignment(property)) return returnsClean(property.name, scope, derived, depth + 1);
      return !mentions(property, derived);
    });
  }
  if (ts.isArrayLiteralExpression(bare)) {
    return bare.elements.every((element) => !ts.isSpreadElement(element) && returnsClean(element, scope, derived, depth + 1));
  }
  return false;
}

/** Does the body read the implicit `arguments` object, which no parameter analysis sees? */
function readsArguments(fn: ts.FunctionLikeDeclaration): boolean {
  let found = false;
  const visit = (node: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(node) && node.text === "arguments") found = true;
    else node.forEachChild(visit);
  };
  if (fn.body) visit(fn.body);
  return found;
}

export type ReturnSummariser = (file: ParsedFile, call: ts.CallExpression, index: number) => ReturnSummary | null;

export function createReturnSummariser(graph: ModuleGraph): ReturnSummariser {
  const cache = new Map<ts.Node, Map<number, ReturnSummary | null>>();
  const inProgress = new Set<ts.Node>();

  return (file, call, index) => {
    const target = resolveCall(graph, file, call);
    if (!target || ts.isConstructorDeclaration(target.fn)) return null;
    const fn = target.fn;
    const cached = cache.get(fn)?.get(index);
    if (cached !== undefined) return cached;
    // Recursion: the default answer, not a guess.
    if (inProgress.has(fn)) return null;

    let summary: ReturnSummary | null;
    const parameters = fn.parameters;
    const rest = parameters.findIndex((parameter) => parameter.dotDotDotToken !== undefined);
    if ((rest !== -1 && index >= rest) || readsArguments(fn)) {
      summary = null;
    } else if (index >= parameters.length) {
      // An argument no parameter receives cannot come back out.
      summary = { tainted: false, observed: false };
    } else {
      inProgress.add(fn);
      try {
        const scope = analyzeFunction(target.file, fn, { isolate: true, seeds: new Map([[index, SUMMARY_SEED]]) });
        const returns = returnExpressions(fn);
        const parameter = parameters[index]!;
        const derived = derivedNames(fn, ts.isIdentifier(parameter.name) ? parameter.name.text : "");
        if (!ts.isIdentifier(parameter.name)) for (const name of bindingNames(parameter.name)) derived.add(name);
        summary = {
          tainted: returns.some((expression) => !returnsClean(expression, scope, derived)),
          observed: returns.some((expression) => observedCallerValue(expression, scope))
        };
      } catch {
        summary = null;
      } finally {
        inProgress.delete(fn);
      }
    }
    const forFn = cache.get(fn) ?? new Map<number, ReturnSummary | null>();
    forFn.set(index, summary);
    cache.set(fn, forFn);
    return summary;
  };
}
