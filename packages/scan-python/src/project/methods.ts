import type { Expr, FunctionDef, Stmt } from "../syntax/ast.js";
import { calleeTail, constString, dotted, stmtBlocks } from "../syntax/ast.js";
import type { RouteInfo } from "./frameworks.js";

/**
 * Which HTTP method reaches a line of a multi-method handler.
 *
 * `@bp.route("/login", methods=["GET", "POST"])` declares two operations in one
 * function, and they are rarely the same code: the GET half renders a form, the
 * POST half signs the user in. A finding in the POST half reported as `GET /login`
 * names an operation that never reaches it. So the methods are narrowed by what
 * dominates the line:
 *
 *  - an early exit guarded by the method (`if request.method == "GET": return …`);
 *  - an early exit guarded by Flask-WTF's `validate_on_submit()`, which is only
 *    true for a submission (`if not form.validate_on_submit(): return …`);
 *  - an enclosing branch on the method (`if request.method == "POST": …`).
 *
 * Nothing else narrows. When the guards say nothing, the declared methods stand.
 */

const ALL: ReadonlySet<string> = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);
const SUBMISSIONS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

interface MethodFacts {
  whenTrue: ReadonlySet<string>;
  whenFalse: ReadonlySet<string>;
}

const UNKNOWN: MethodFacts = { whenTrue: ALL, whenFalse: ALL };

function intersect(a: ReadonlySet<string>, b: ReadonlySet<string>): Set<string> {
  return new Set([...a].filter((item) => b.has(item)));
}

function union(a: ReadonlySet<string>, b: ReadonlySet<string>): Set<string> {
  return new Set([...a, ...b]);
}

function complement(a: ReadonlySet<string>): Set<string> {
  return new Set([...ALL].filter((item) => !a.has(item)));
}

function isMethodRead(expr: Expr): boolean {
  return /(^|\.)request\.method$/.test(dotted(expr) ?? "");
}

function literalMethods(expr: Expr): Set<string> | null {
  const single = constString(expr);
  if (single !== null) return new Set([single.toUpperCase()]);
  if (expr.k === "tuple" || expr.k === "list" || expr.k === "set") {
    const values = expr.elts.map((element) => constString(element));
    if (values.some((value) => value === null)) return null;
    return new Set(values.map((value) => value!.toUpperCase()));
  }
  return null;
}

function methodFacts(test: Expr): MethodFacts {
  switch (test.k) {
    case "not": {
      const inner = methodFacts(test.operand);
      return { whenTrue: inner.whenFalse, whenFalse: inner.whenTrue };
    }
    case "boolop": {
      const left = methodFacts(test.left);
      const right = methodFacts(test.right);
      return test.op === "and"
        ? { whenTrue: intersect(left.whenTrue, right.whenTrue), whenFalse: union(left.whenFalse, right.whenFalse) }
        : { whenTrue: union(left.whenTrue, right.whenTrue), whenFalse: intersect(left.whenFalse, right.whenFalse) };
    }
    case "compare": {
      const [read, other] = isMethodRead(test.left) ? [test.left, test.right] : isMethodRead(test.right) ? [test.right, test.left] : [null, null];
      if (!read || !other) return UNKNOWN;
      const methods = literalMethods(other);
      if (!methods) return UNKNOWN;
      if (test.op === "==" || test.op === "in") return { whenTrue: methods, whenFalse: complement(methods) };
      if (test.op === "!=" || test.op === "not in") return { whenTrue: complement(methods), whenFalse: methods };
      return UNKNOWN;
    }
    case "call": {
      // Flask-WTF: true only for a submitted form that validates.
      if (calleeTail(test) === "validate_on_submit" || calleeTail(test) === "is_submitted") return { whenTrue: SUBMISSIONS, whenFalse: ALL };
      return UNKNOWN;
    }
    default:
      return UNKNOWN;
  }
}

function exits(body: Stmt[]): boolean {
  const last = body[body.length - 1];
  if (!last) return false;
  if (last.k === "return" || last.k === "raise") return true;
  return last.k === "expr" && last.value.k === "call" && /(^|\.)(abort|exit|fail|deny|forbid|unauthorized|forbidden)$/.test(dotted(last.value.func) ?? "");
}

function contains(stmt: Stmt, line: number): boolean {
  return stmt.span.line <= line && line <= stmt.span.endLine;
}

function narrow(body: Stmt[], line: number, allowed: ReadonlySet<string>): ReadonlySet<string> {
  let current = allowed;
  for (const stmt of body) {
    if (contains(stmt, line)) {
      if (stmt.k === "if") {
        let reaching = current;
        for (const branch of stmt.branches) {
          const facts = branch.test ? methodFacts(branch.test) : { whenTrue: ALL, whenFalse: ALL };
          const inBranch = intersect(reaching, facts.whenTrue);
          if (branch.body.some((inner) => contains(inner, line))) return narrow(branch.body, line, inBranch);
          reaching = intersect(reaching, facts.whenFalse);
        }
        return current;
      }
      for (const block of stmtBlocks(stmt)) {
        if (stmt.k === "funcdef" || stmt.k === "classdef") continue;
        if (block.some((inner) => contains(inner, line))) return narrow(block, line, current);
      }
      return current;
    }
    if (stmt.span.line > line) break;
    // An `if` that leaves the handler: what follows runs only when its tests were false.
    if (stmt.k === "if" && stmt.branches.every((branch) => branch.test !== null) && stmt.branches.every((branch) => exits(branch.body))) {
      for (const branch of stmt.branches) current = intersect(current, methodFacts(branch.test!).whenFalse);
    }
  }
  return current;
}

/**
 * The methods that can reach `line` of a handler declared for `declared` methods, in
 * declaration order. A multi-method decorator yields one route per method, so the
 * caller passes the methods of every route the function serves.
 */
export function methodsAt(fn: FunctionDef, declared: readonly string[], line: number | undefined): string[] {
  if (declared.length < 2 || line === undefined || line < fn.span.line || line > fn.span.endLine) return [...declared];
  const reaching = narrow(fn.body, line, new Set(declared));
  const ordered = declared.filter((method) => reaching.has(method));
  return ordered.length > 0 ? ordered : [...declared];
}

/** The routes one handler serves at one path, one per method. */
export function siblingRoutes(routes: readonly RouteInfo[], route: RouteInfo): RouteInfo[] {
  return routes.filter((candidate) => candidate.fn === route.fn && candidate.path === route.path);
}

/**
 * The route, among those one handler serves, whose method reaches `line`. With
 * `preferSubmission`, a submission method wins over a read when both reach it.
 */
export function routeAt(siblings: readonly RouteInfo[], line: number | undefined, preferSubmission = false): RouteInfo | undefined {
  const first = siblings[0];
  if (!first) return undefined;
  const declared = siblings.flatMap((route) => route.methods);
  let methods = methodsAt(first.fn, declared, line);
  if (preferSubmission && methods.length > 1) {
    const submitted = methods.filter((method) => SUBMISSIONS.has(method));
    if (submitted.length > 0) methods = submitted;
  }
  const method = methods[0];
  return siblings.find((route) => route.methods.includes(method!)) ?? first;
}

/** `POST /session/new`: the operation, among a handler's routes, that reaches `line`. */
export function routeLabelAt(siblings: readonly RouteInfo[], line?: number, preferSubmission = false): string | undefined {
  const route = routeAt(siblings, line, preferSubmission);
  return route ? `${route.methods[0]} ${route.path}` : undefined;
}
