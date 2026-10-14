import ts from "typescript";
import type { ParsedFile } from "./parse.js";

/** Dotted call name, for example `path.join` or `child_process.execSync`. */
export function calleeName(node: ts.CallExpression): string {
  return expressionName(node.expression);
}

export function expressionName(expression: ts.Expression | ts.LeftHandSideExpression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) {
    return `${expressionName(expression.expression)}.${expression.name.text}`;
  }
  if (ts.isElementAccessExpression(expression) && ts.isStringLiteralLike(expression.argumentExpression)) {
    return `${expressionName(expression.expression)}.${expression.argumentExpression.text}`;
  }
  if (ts.isCallExpression(expression)) return `${expressionName(expression.expression)}()`;
  if (ts.isNonNullExpression(expression) || ts.isParenthesizedExpression(expression)) {
    return expressionName(expression.expression);
  }
  /*
   * A type assertion names whatever it wraps.
   *
   * `(request.query as { sort?: string }).sort` is how Fastify's own documentation
   * reads a query parameter, because `request.query` is `unknown` until you say what
   * it is. This helper returned "" for the assertion, so the property's parent name
   * was empty, nothing matched `.query`, and the value was not caller data — in a
   * TypeScript codebase, which is the language this engine is for.
   */
  if (ts.isAsExpression(expression) || ts.isSatisfiesExpression(expression) || ts.isTypeAssertionExpression(expression)) {
    return expressionName(expression.expression);
  }
  if (ts.isAwaitExpression(expression)) return expressionName(expression.expression as ts.Expression);
  return "";
}

/** The last segment of a dotted name, for matching `join` in `path.join`. */
export function calleeTail(node: ts.CallExpression): string {
  const name = calleeName(node);
  const index = name.lastIndexOf(".");
  return index === -1 ? name : name.slice(index + 1);
}

export function isStringLike(node: ts.Node): boolean {
  return ts.isStringLiteralLike(node) || ts.isTemplateExpression(node) || ts.isNoSubstitutionTemplateLiteral(node);
}

/** True when the expression is built from a literal and nothing else. */
export function isConstantString(node: ts.Node): boolean {
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return true;
  if (ts.isTemplateExpression(node)) return node.templateSpans.length === 0;
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return isConstantString(node.left) && isConstantString(node.right);
  }
  if (ts.isParenthesizedExpression(node)) return isConstantString(node.expression);
  return false;
}

export function literalTextOf(node: ts.Node): string | null {
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

/** Operators that pass a value through rather than transforming it. */
const PASS_THROUGH_OPERATORS = new Set([
  ts.SyntaxKind.QuestionQuestionToken,
  ts.SyntaxKind.BarBarToken,
  ts.SyntaxKind.AmpersandAmpersandToken
]);

/**
 * Every interpolated expression in a template, both sides of a `+` chain, and
 * both sides of a defaulting operator. `req.query.q ?? ""` is still attacker
 * controlled, so missing that shape loses most real-world taint flows.
 */
export function dynamicParts(node: ts.Node): ts.Expression[] {
  if (ts.isTemplateExpression(node)) return node.templateSpans.map((span) => span.expression);
  if (ts.isBinaryExpression(node) && PASS_THROUGH_OPERATORS.has(node.operatorToken.kind)) {
    return [node.left, node.right];
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return [...dynamicParts(node.left), ...dynamicParts(node.right)].concat(
      isConstantString(node.left) ? [] : [node.left as ts.Expression],
      isConstantString(node.right) ? [] : [node.right as ts.Expression]
    );
  }
  if (ts.isParenthesizedExpression(node)) return dynamicParts(node.expression);
  return [];
}

/** Nearest enclosing function-ish node, used to name the container in evidence. */
export function enclosingFunction(node: ts.Node): ts.Node | undefined {
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
    current = current.parent;
  }
  return undefined;
}

export function functionName(node: ts.Node | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isFunctionDeclaration(node) && node.name) return node.name.text;
  if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) return node.name.text;
  const parent = node.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  if (parent && ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  return undefined;
}

export function walk(node: ts.Node, visitor: (node: ts.Node) => void): void {
  visitor(node);
  node.forEachChild((child) => walk(child, visitor));
}

export function collect<T extends ts.Node>(root: ts.Node, predicate: (node: ts.Node) => node is T): T[] {
  const out: T[] = [];
  walk(root, (node) => {
    if (predicate(node)) out.push(node);
  });
  return out;
}

export function findAll(root: ts.Node, predicate: (node: ts.Node) => boolean): ts.Node[] {
  const out: ts.Node[] = [];
  walk(root, (node) => {
    if (predicate(node)) out.push(node);
  });
  return out;
}

/** Does any ancestor of `node` guard on the given identifier-ish expression? */
export function hasAncestor(node: ts.Node, predicate: (node: ts.Node) => boolean): boolean {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (predicate(current)) return true;
    current = current.parent;
  }
  return false;
}

export function textOf(file: ParsedFile, node: ts.Node): string {
  return node.getText(file.source);
}

/**
 * Names that end a request by being called rather than by `throw` or `return`.
 *
 * Koa aborts with `ctx.throw(400, …)`, Next with `notFound()` and `redirect()`,
 * SvelteKit and Hono with helpers of the same shape. A guard model that only
 * recognises the `throw` and `return` *statements* reads every one of these as
 * fall-through, and then reports the guarded code.
 *
 * This existed twice already — in `perimeter.ts` and `records-origin.ts` — and not
 * in the three other copies of the same predicate, which is how holdout-5 came to
 * report a Mongo lookup guarded by `if (!isValidObjectId(id)) ctx.throw(400)`. One
 * definition, so the next framework idiom is added once.
 */
const ABORTING_CALL = new Set([
  "throw",
  "abort",
  "notfound",
  "not_found",
  "unauthorized",
  "unauthorised",
  "forbidden",
  "redirect"
]);

/*
 * Read the callee's last segment directly rather than building its dotted name.
 *
 * This runs for every call inside every guarded branch, and the first version went
 * through `expressionName`, which allocates a string per property access and then
 * matched a regex against it. That alone doubled the cost of scanning a 72KB file.
 * Only the final segment can ever match, so only the final segment is looked at.
 */
export function isAbortCall(node: ts.Node): boolean {
  if (!ts.isCallExpression(node)) return false;
  const callee = node.expression;
  const tail = ts.isIdentifier(callee)
    ? callee.text
    : ts.isPropertyAccessExpression(callee)
      ? callee.name.text
      : null;
  return tail !== null && ABORTING_CALL.has(tail.toLowerCase());
}
