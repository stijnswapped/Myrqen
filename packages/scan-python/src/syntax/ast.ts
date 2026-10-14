/**
 * A deliberately small Python syntax tree.
 *
 * The parser (`@lezer/python`) produces a concrete syntax tree: every keyword,
 * comma and parenthesis is a node, and a decorator's dotted name arrives as a
 * flat run of tokens. Rules written against that shape spend most of their
 * length skipping punctuation, and every rule skips it slightly differently.
 *
 * So the concrete tree is converted once, here, into the subset of Python's own
 * abstract grammar the analysis needs. Anything the converter does not model
 * becomes `other` with its sub-expressions preserved, which keeps data flow
 * conservative: an unknown construct still carries the taint of what is inside it.
 */

export interface Span {
  /** 1-based line of the first character. */
  line: number;
  endLine: number;
  from: number;
  to: number;
}

export type Expr =
  | { k: "name"; id: string; span: Span }
  | { k: "attr"; value: Expr; attr: string; span: Span }
  | { k: "call"; func: Expr; args: Expr[]; kwargs: Keyword[]; span: Span }
  | { k: "str"; value: string; bytes: boolean; span: Span }
  | { k: "fstr"; parts: Array<string | Expr>; span: Span }
  | { k: "num"; value: number; span: Span }
  | { k: "const"; value: true | false | null; span: Span }
  | { k: "binop"; op: string; left: Expr; right: Expr; span: Span }
  | { k: "boolop"; op: "and" | "or"; left: Expr; right: Expr; span: Span }
  | { k: "compare"; op: string; left: Expr; right: Expr; span: Span }
  | { k: "not"; operand: Expr; span: Span }
  | { k: "unary"; op: string; operand: Expr; span: Span }
  | { k: "subscript"; value: Expr; index: Expr | null; span: Span }
  | { k: "list" | "tuple" | "set"; elts: Expr[]; span: Span }
  | { k: "dict"; entries: Array<{ key: Expr | null; value: Expr }>; span: Span }
  | { k: "lambda"; params: Param[]; body: Expr; span: Span }
  | { k: "ifexp"; test: Expr; body: Expr; orelse: Expr; span: Span }
  | { k: "comp"; elt: Expr; key: Expr | null; targets: Expr[]; iters: Expr[]; conds: Expr[]; span: Span }
  | { k: "await"; value: Expr; span: Span }
  | { k: "starred"; value: Expr; double: boolean; span: Span }
  | { k: "named"; target: string; value: Expr; span: Span }
  | { k: "yield"; value: Expr | null; span: Span }
  | { k: "other"; children: Expr[]; span: Span };

export interface Keyword {
  /** `null` for `**mapping`. */
  name: string | null;
  value: Expr;
}

export interface Param {
  name: string;
  annotation: Expr | null;
  default: Expr | null;
  kind: "normal" | "vararg" | "kwarg";
  span: Span;
}

export interface Decorator {
  expr: Expr;
  span: Span;
}

export interface FunctionDef {
  k: "funcdef";
  name: string;
  params: Param[];
  decorators: Decorator[];
  body: Stmt[];
  isAsync: boolean;
  returns: Expr | null;
  /** From the first decorator (or `def`) to the end of the body. */
  span: Span;
  /** The `def` line itself. */
  defLine: number;
}

export interface ClassDef {
  k: "classdef";
  name: string;
  bases: Expr[];
  keywords: Keyword[];
  decorators: Decorator[];
  body: Stmt[];
  span: Span;
}

export type Stmt =
  | FunctionDef
  | ClassDef
  | { k: "assign"; targets: Expr[]; value: Expr | null; annotation: Expr | null; span: Span }
  | { k: "augassign"; target: Expr; op: string; value: Expr; span: Span }
  | { k: "expr"; value: Expr; span: Span }
  | { k: "return"; value: Expr | null; span: Span }
  | { k: "if"; branches: Array<{ test: Expr | null; body: Stmt[] }>; span: Span }
  | { k: "for"; target: Expr; iter: Expr; body: Stmt[]; orelse: Stmt[]; isAsync: boolean; span: Span }
  | { k: "while"; test: Expr; body: Stmt[]; orelse: Stmt[]; span: Span }
  | { k: "with"; items: Array<{ expr: Expr; as: Expr | null }>; body: Stmt[]; span: Span }
  | {
      k: "try";
      body: Stmt[];
      handlers: Array<{ type: Expr | null; name: string | null; body: Stmt[] }>;
      orelse: Stmt[];
      finalbody: Stmt[];
      span: Span;
    }
  | { k: "raise"; exc: Expr | null; span: Span }
  | { k: "import"; names: Array<{ module: string; asname: string | null }>; span: Span }
  | { k: "importfrom"; module: string; level: number; names: Array<{ name: string; asname: string | null }>; span: Span }
  | { k: "match"; subject: Expr; cases: Stmt[][]; span: Span }
  | { k: "delete"; targets: Expr[]; span: Span }
  | { k: "assert"; test: Expr; span: Span }
  | { k: "simple"; keyword: "pass" | "break" | "continue" | "global" | "nonlocal"; span: Span };

export interface Module {
  body: Stmt[];
}

/** Visit every expression under `root`, depth first, including nested lambdas. */
export function walkExpr(root: Expr, visit: (expr: Expr) => void): void {
  visit(root);
  for (const child of childExprs(root)) walkExpr(child, visit);
}

export function childExprs(expr: Expr): Expr[] {
  switch (expr.k) {
    case "attr":
      return [expr.value];
    case "call":
      return [expr.func, ...expr.args, ...expr.kwargs.map((keyword) => keyword.value)];
    case "fstr":
      return expr.parts.filter((part): part is Expr => typeof part !== "string");
    case "binop":
    case "boolop":
    case "compare":
      return [expr.left, expr.right];
    case "not":
    case "unary":
      return [expr.operand];
    case "subscript":
      return expr.index ? [expr.value, expr.index] : [expr.value];
    case "list":
    case "tuple":
    case "set":
      return expr.elts;
    case "dict":
      return expr.entries.flatMap((entry) => (entry.key ? [entry.key, entry.value] : [entry.value]));
    case "lambda":
      return [expr.body];
    case "ifexp":
      return [expr.test, expr.body, expr.orelse];
    case "comp":
      return [expr.elt, ...(expr.key ? [expr.key] : []), ...expr.iters, ...expr.conds];
    case "await":
    case "starred":
    case "named":
      return [expr.value];
    case "yield":
      return expr.value ? [expr.value] : [];
    case "other":
      return expr.children;
    default:
      return [];
  }
}

/** The expressions a statement evaluates directly (not those of nested blocks). */
export function stmtExprs(stmt: Stmt): Expr[] {
  switch (stmt.k) {
    case "funcdef":
      return [
        ...stmt.decorators.map((decorator) => decorator.expr),
        ...stmt.params.flatMap((param) => [param.annotation, param.default].filter((e): e is Expr => e !== null))
      ];
    case "classdef":
      return [...stmt.decorators.map((decorator) => decorator.expr), ...stmt.bases, ...stmt.keywords.map((k) => k.value)];
    case "assign":
      return [...stmt.targets, ...(stmt.value ? [stmt.value] : []), ...(stmt.annotation ? [stmt.annotation] : [])];
    case "augassign":
      return [stmt.target, stmt.value];
    case "expr":
      return [stmt.value];
    case "return":
      return stmt.value ? [stmt.value] : [];
    case "if":
      return stmt.branches.flatMap((branch) => (branch.test ? [branch.test] : []));
    case "for":
      return [stmt.target, stmt.iter];
    case "while":
      return [stmt.test];
    case "with":
      return stmt.items.flatMap((item) => (item.as ? [item.expr, item.as] : [item.expr]));
    case "try":
      return stmt.handlers.flatMap((handler) => (handler.type ? [handler.type] : []));
    case "raise":
      return stmt.exc ? [stmt.exc] : [];
    case "match":
      return [stmt.subject];
    case "delete":
      return stmt.targets;
    case "assert":
      return [stmt.test];
    default:
      return [];
  }
}

/** Nested statement blocks of a statement, in source order. */
export function stmtBlocks(stmt: Stmt): Stmt[][] {
  switch (stmt.k) {
    case "funcdef":
    case "classdef":
      return [stmt.body];
    case "if":
      return stmt.branches.map((branch) => branch.body);
    case "for":
    case "while":
      return [stmt.body, stmt.orelse];
    case "with":
      return [stmt.body];
    case "try":
      return [stmt.body, ...stmt.handlers.map((handler) => handler.body), stmt.orelse, stmt.finalbody];
    case "match":
      return stmt.cases;
    default:
      return [];
  }
}

/**
 * Every statement in a block, recursively, without descending into nested
 * function or class bodies unless asked: a nested `def` is its own scope.
 */
export function walkStmts(body: Stmt[], visit: (stmt: Stmt) => void, intoDefinitions = false): void {
  for (const stmt of body) {
    visit(stmt);
    if (!intoDefinitions && (stmt.k === "funcdef" || stmt.k === "classdef")) continue;
    for (const block of stmtBlocks(stmt)) walkStmts(block, visit, intoDefinitions);
  }
}

/** Every expression evaluated in a block (not inside nested definitions). */
export function exprsIn(body: Stmt[]): Expr[] {
  const out: Expr[] = [];
  walkStmts(body, (stmt) => {
    for (const expr of stmtExprs(stmt)) walkExpr(expr, (e) => out.push(e));
  });
  return out;
}

/**
 * `a.b.c` as a dotted string, or null when the chain is not names and attributes.
 * Calls in the chain are spelled `()`, so `Path(x).open` becomes `Path().open`.
 */
export function dotted(expr: Expr): string | null {
  if (expr.k === "name") return expr.id;
  if (expr.k === "attr") {
    const base = dotted(expr.value);
    return base === null ? null : `${base}.${expr.attr}`;
  }
  if (expr.k === "call") {
    const base = dotted(expr.func);
    return base === null ? null : `${base}()`;
  }
  return null;
}

/** The final identifier a call is made through: `a.b.execute(...)` is `execute`. */
export function calleeTail(call: Extract<Expr, { k: "call" }>): string | null {
  if (call.func.k === "name") return call.func.id;
  if (call.func.k === "attr") return call.func.attr;
  return null;
}

export function keyword(call: Extract<Expr, { k: "call" }>, name: string): Expr | undefined {
  return call.kwargs.find((keyword) => keyword.name === name)?.value;
}

/** The literal text of a constant string expression, or null. */
export function constString(expr: Expr | undefined | null): string | null {
  if (!expr) return null;
  if (expr.k === "str") return expr.value;
  return null;
}

export function isTrue(expr: Expr | undefined | null): boolean {
  return Boolean(expr && expr.k === "const" && expr.value === true);
}
