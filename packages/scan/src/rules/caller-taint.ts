import ts from "typescript";
import { collect } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, taintOrigin, type TaintScope } from "../ast/taint.js";
import type { RuleContext } from "./context.js";

/**
 * Taint for a value read off a helper's parameter, one call away, in the same file.
 *
 * The engine follows data within a function. A handler that hands its input to a
 * small named helper leaves the helper holding a parameter with no origin, and the
 * sink inside the helper is then judged as if it held the application's own data.
 * This looks one call outwards: the helper must be called by name in this file, and
 * the argument in that parameter's position must already be caller-controlled where
 * the call is written. One hop and no more, so a chain of helpers ends rather than
 * being guessed at — the engine's cross-function pass is the place for anything
 * deeper, and this function is the seam it will replace.
 *
 * Returns the origin and the call that supplied it, or null.
 */
export function taintThroughCallers(
  context: RuleContext,
  fn: ts.Node,
  parameterIndex: number
): { origin: string; call: ts.CallExpression } | null {
  const name = nameOf(fn);
  if (!name) return null;
  for (const caller of functionsIn(context.file.source)) {
    if (caller === fn) continue;
    let scope: TaintScope | null = null;
    for (const call of collect(caller, ts.isCallExpression)) {
      if (!ts.isIdentifier(call.expression) || call.expression.text !== name) continue;
      if (innermostFunction(call) !== caller) continue;
      const argument = call.arguments[parameterIndex];
      if (!argument) continue;
      scope ??= analyzeFunction(context.file, caller);
      const origin = taintOrigin(argument, scope);
      if (origin) return { origin, call };
    }
  }
  return null;
}

/** The index of the parameter a name is bound to in this function, or -1. */
export function parameterIndex(fn: ts.Node, name: string): number {
  if (!ts.isFunctionLike(fn)) return -1;
  return fn.parameters.findIndex((parameter) => ts.isIdentifier(parameter.name) && parameter.name.text === name);
}

function nameOf(fn: ts.Node): string | null {
  if (ts.isFunctionDeclaration(fn) && fn.name) return fn.name.text;
  const parent = fn.parent;
  if ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  return null;
}

function innermostFunction(node: ts.Node): ts.Node {
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
