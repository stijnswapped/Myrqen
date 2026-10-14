import type { SyntaxNode } from "@lezer/common";
import { parser } from "@lezer/python";
import type { ClassDef, Decorator, Expr, FunctionDef, Module, Span, Stmt } from "./ast.js";
import { ExpressionConverter, childrenOf, isExpr } from "./expressions.js";

/**
 * Parse Python source into the small tree in `ast.ts`.
 *
 * `@lezer/python` is an error-tolerant LR parser: malformed input produces error
 * nodes rather than an exception, so a half-edited file still yields every
 * statement around the damage. The count of error nodes is returned so the scan
 * can say, per file, that its reading was partial.
 */
export function parsePython(text: string): { module: Module; errors: number } {
  const tree = parser.parse(text);
  const converter = new Converter(text);
  let errors = 0;
  const cursor = tree.cursor();
  do {
    if (cursor.type.isError) errors += 1;
  } while (cursor.next());
  return { module: { body: converter.block(tree.topNode) }, errors };
}

class Converter extends ExpressionConverter {
  /* ------------------------------------------------------------ statements */

  block(node: SyntaxNode): Stmt[] {
    const out: Stmt[] = [];
    for (const child of childrenOf(node)) out.push(...this.statement(child));
    return out;
  }

  private statement(node: SyntaxNode): Stmt[] {
    const span = this.span(node);
    const parts = childrenOf(node);
    switch (node.name) {
      case "StatementGroup":
        return this.block(node);
      case "ExpressionStatement": {
        const expr = parts.find(isExpr);
        return expr ? [{ k: "expr", value: this.expr(expr), span }] : [];
      }
      case "YieldStatement":
        return [{ k: "expr", value: { k: "yield", value: this.firstExpr(parts), span }, span }];
      case "AssignStatement":
        return [this.assignment(parts, span)];
      case "UpdateStatement": {
        const exprs = parts.filter(isExpr);
        const op = parts.find((part) => part.name === "UpdateOp");
        if (exprs.length < 2) return [];
        return [
          {
            k: "augassign",
            target: this.expr(exprs[0]!),
            op: op ? this.source(op) : "+=",
            value: this.expr(exprs[exprs.length - 1]!),
            span
          }
        ];
      }
      case "ReturnStatement":
        return [{ k: "return", value: this.sequence(parts), span }];
      case "RaiseStatement": {
        const exprs = parts.filter(isExpr);
        return [{ k: "raise", exc: exprs[0] ? this.expr(exprs[0]) : null, span }];
      }
      case "PassStatement":
        return [{ k: "simple", keyword: "pass", span }];
      case "BreakStatement":
        return [{ k: "simple", keyword: "break", span }];
      case "ContinueStatement":
        return [{ k: "simple", keyword: "continue", span }];
      case "ScopeStatement":
        return [{ k: "simple", keyword: this.source(node).startsWith("nonlocal") ? "nonlocal" : "global", span }];
      case "DeleteStatement":
        return [{ k: "delete", targets: parts.filter(isExpr).map((part) => this.expr(part)), span }];
      case "AssertStatement": {
        const test = parts.find(isExpr);
        return test ? [{ k: "assert", test: this.expr(test), span }] : [];
      }
      case "ImportStatement":
        return [this.importStatement(parts, span)];
      case "IfStatement":
        return [this.ifStatement(parts, span)];
      case "WhileStatement": {
        const bodies = parts.filter((part) => part.name === "Body");
        const test = parts.find(isExpr);
        if (!test || !bodies[0]) return [];
        return [
          {
            k: "while",
            test: this.expr(test),
            body: this.block(bodies[0]),
            orelse: bodies[1] ? this.block(bodies[1]) : [],
            span
          }
        ];
      }
      case "ForStatement":
        return [this.forStatement(parts, span)];
      case "TryStatement":
        return [this.tryStatement(parts, span)];
      case "WithStatement":
        return [this.withStatement(parts, span)];
      case "FunctionDefinition":
        return [this.functionDef(node, [], span)];
      case "ClassDefinition":
        return [this.classDef(node, [], span)];
      case "DecoratedStatement":
        return this.decorated(node, span);
      case "MatchStatement":
        return [this.matchStatement(parts, span)];
      case "Body":
        return this.block(node);
      default:
        // An expression standing alone where a statement was expected (error
        // recovery, or a node this converter does not know) is kept as one.
        if (isExpr(node)) return [{ k: "expr", value: this.expr(node), span }];
        return [];
    }
  }

  private assignment(parts: SyntaxNode[], span: Span): Stmt {
    // Groups separated by `=`. The last group is the value; every other group is a
    // target, and a group with commas is a tuple target.
    const groups: SyntaxNode[][] = [[]];
    let annotation: Expr | null = null;
    for (const part of parts) {
      if (part.name === "AssignOp") {
        groups.push([]);
        continue;
      }
      if (part.name === "TypeDef") {
        const typeExpr = childrenOf(part).find(isExpr);
        if (typeExpr) annotation = this.expr(typeExpr);
        continue;
      }
      groups[groups.length - 1]!.push(part);
    }
    if (groups.length === 1) {
      // A bare annotation: `name: str`.
      return { k: "assign", targets: [this.sequence(groups[0]!) ?? this.other([], span)], value: null, annotation, span };
    }
    const valueGroup = groups[groups.length - 1]!;
    const targets = groups.slice(0, -1).map((group) => this.sequence(group) ?? this.other([], span));
    return { k: "assign", targets, value: this.sequence(valueGroup), annotation, span };
  }

  private importStatement(parts: SyntaxNode[], span: Span): Stmt {
    const isFrom = parts[0]?.name === "from";
    if (!isFrom) {
      // import a.b as c, d
      const names: Array<{ module: string; asname: string | null }> = [];
      let current: string[] = [];
      let alias = false;
      let asname: string | null = null;
      const flush = () => {
        if (current.length > 0) names.push({ module: current.join("."), asname });
        current = [];
        asname = null;
        alias = false;
      };
      for (const part of parts.slice(1)) {
        if (part.name === ",") flush();
        else if (part.name === "as") alias = true;
        else if (part.name === "VariableName") {
          if (alias) asname = this.source(part);
          else current.push(this.source(part));
        }
      }
      flush();
      return { k: "import", names, span };
    }

    // from ..a.b import c as d, e
    let level = 0;
    const moduleParts: string[] = [];
    let index = 1;
    for (; index < parts.length; index += 1) {
      const part = parts[index]!;
      if (part.name === "import") break;
      if (part.name === ".") level += moduleParts.length === 0 ? 1 : 0;
      else if (part.name === "...") level += 3;
      else if (part.name === "VariableName") moduleParts.push(this.source(part));
    }
    const names: Array<{ name: string; asname: string | null }> = [];
    let pending: { name: string; asname: string | null } | null = null;
    let alias = false;
    for (const part of parts.slice(index + 1)) {
      if (part.name === "*") names.push({ name: "*", asname: null });
      else if (part.name === "as") alias = true;
      else if (part.name === "VariableName") {
        if (alias && pending) {
          pending.asname = this.source(part);
          alias = false;
        } else {
          pending = { name: this.source(part), asname: null };
          names.push(pending);
        }
      }
    }
    return { k: "importfrom", module: moduleParts.join("."), level, names, span };
  }

  private ifStatement(parts: SyntaxNode[], span: Span): Stmt {
    const branches: Array<{ test: Expr | null; body: Stmt[] }> = [];
    let test: Expr | null = null;
    let expectingTest = false;
    for (const part of parts) {
      if (part.name === "if" || part.name === "elif") {
        expectingTest = true;
        continue;
      }
      if (part.name === "else") {
        test = null;
        expectingTest = false;
        continue;
      }
      if (part.name === "Body") {
        branches.push({ test, body: this.block(part) });
        test = null;
        continue;
      }
      if (expectingTest && isExpr(part)) {
        test = this.expr(part);
        expectingTest = false;
      }
    }
    return { k: "if", branches, span };
  }

  private forStatement(parts: SyntaxNode[], span: Span): Stmt {
    const inIndex = parts.findIndex((part) => part.name === "in");
    const targetParts = parts.slice(0, inIndex).filter((part) => part.name !== "for" && part.name !== "async");
    const bodies = parts.filter((part) => part.name === "Body");
    const iterParts = parts.slice(inIndex + 1).filter((part) => part.name !== "Body" && part.name !== "else");
    return {
      k: "for",
      target: this.sequence(targetParts) ?? this.other([], span),
      iter: this.sequence(iterParts) ?? this.other([], span),
      body: bodies[0] ? this.block(bodies[0]) : [],
      orelse: bodies[1] ? this.block(bodies[1]) : [],
      isAsync: parts[0]?.name === "async",
      span
    };
  }

  private tryStatement(parts: SyntaxNode[], span: Span): Stmt {
    let body: Stmt[] = [];
    const handlers: Array<{ type: Expr | null; name: string | null; body: Stmt[] }> = [];
    let orelse: Stmt[] = [];
    let finalbody: Stmt[] = [];
    let mode: "try" | "except" | "else" | "finally" = "try";
    let handlerType: Expr | null = null;
    let handlerName: string | null = null;
    let afterAs = false;
    for (const part of parts) {
      switch (part.name) {
        case "try":
          mode = "try";
          continue;
        case "except":
          mode = "except";
          handlerType = null;
          handlerName = null;
          afterAs = false;
          continue;
        case "else":
          mode = "else";
          continue;
        case "finally":
          mode = "finally";
          continue;
        case "as":
          afterAs = true;
          continue;
        case "Body": {
          const block = this.block(part);
          if (mode === "try") body = block;
          else if (mode === "except") handlers.push({ type: handlerType, name: handlerName, body: block });
          else if (mode === "else") orelse = block;
          else finalbody = block;
          continue;
        }
        default:
          if (mode === "except" && isExpr(part)) {
            if (afterAs && part.name === "VariableName") handlerName = this.source(part);
            else handlerType = this.expr(part);
          }
      }
    }
    return { k: "try", body, handlers, orelse, finalbody, span };
  }

  private withStatement(parts: SyntaxNode[], span: Span): Stmt {
    const items: Array<{ expr: Expr; as: Expr | null }> = [];
    let afterAs = false;
    let body: Stmt[] = [];
    for (const part of parts) {
      if (part.name === "as") {
        afterAs = true;
        continue;
      }
      if (part.name === ",") {
        afterAs = false;
        continue;
      }
      if (part.name === "Body") {
        body = this.block(part);
        continue;
      }
      if (!isExpr(part)) continue;
      const expr = this.expr(part);
      if (afterAs && items.length > 0) {
        items[items.length - 1]!.as = expr;
        afterAs = false;
      } else if (expr.k === "tuple" && part.name === "ParenthesizedExpression") {
        for (const element of expr.elts) items.push({ expr: element, as: null });
      } else {
        items.push({ expr, as: null });
      }
    }
    return { k: "with", items, body, span };
  }

  private matchStatement(parts: SyntaxNode[], span: Span): Stmt {
    const subjectNode = parts.find(isExpr);
    const matchBody = parts.find((part) => part.name === "MatchBody");
    const cases: Stmt[][] = [];
    if (matchBody) {
      for (const clause of childrenOf(matchBody)) {
        if (clause.name !== "MatchClause") continue;
        const body = childrenOf(clause).find((part) => part.name === "Body");
        if (body) cases.push(this.block(body));
      }
    }
    return { k: "match", subject: subjectNode ? this.expr(subjectNode) : this.other([], span), cases, span };
  }

  private decorated(node: SyntaxNode, span: Span): Stmt[] {
    const decorators: Decorator[] = [];
    let result: Stmt[] = [];
    for (const child of childrenOf(node)) {
      if (child.name === "Decorator") decorators.push(this.decorator(child));
      else if (child.name === "FunctionDefinition") result = [this.functionDef(child, decorators, span)];
      else if (child.name === "ClassDefinition") result = [this.classDef(child, decorators, span)];
    }
    return result;
  }

  private decorator(node: SyntaxNode): Decorator {
    const span = this.span(node);
    let expr: Expr | null = null;
    for (const part of childrenOf(node)) {
      if (part.name === "At" || part.name === ".") continue;
      if (part.name === "VariableName" || part.name === "PropertyName") {
        const id = this.source(part);
        expr = expr === null ? { k: "name", id, span: this.span(part) } : { k: "attr", value: expr, attr: id, span };
        continue;
      }
      if (part.name === "ArgList" && expr) {
        expr = this.call(expr, part, span);
        continue;
      }
      if (isExpr(part)) expr = this.expr(part);
    }
    return { expr: expr ?? this.other([], span), span };
  }

  private functionDef(node: SyntaxNode, decorators: Decorator[], outer: Span): FunctionDef {
    const parts = childrenOf(node);
    const nameNode = parts.find((part) => part.name === "VariableName");
    const paramList = parts.find((part) => part.name === "ParamList");
    const returns = parts.find((part) => part.name === "TypeDef");
    const body = parts.find((part) => part.name === "Body");
    const own = this.span(node);
    const returnExpr = returns ? childrenOf(returns).find(isExpr) : undefined;
    return {
      k: "funcdef",
      name: nameNode ? this.source(nameNode) : "<anonymous>",
      params: paramList ? this.params(paramList) : [],
      decorators,
      body: body ? this.block(body) : [],
      isAsync: parts[0]?.name === "async",
      returns: returnExpr ? this.expr(returnExpr) : null,
      span: decorators.length > 0 ? { ...outer, endLine: own.endLine, to: own.to } : own,
      defLine: own.line
    };
  }

  private classDef(node: SyntaxNode, decorators: Decorator[], outer: Span): ClassDef {
    const parts = childrenOf(node);
    const nameNode = parts.find((part) => part.name === "VariableName");
    const argList = parts.find((part) => part.name === "ArgList");
    const body = parts.find((part) => part.name === "Body");
    const own = this.span(node);
    const { args, kwargs } = argList ? this.argList(argList) : { args: [], kwargs: [] };
    return {
      k: "classdef",
      name: nameNode ? this.source(nameNode) : "<anonymous>",
      bases: args,
      keywords: kwargs,
      decorators,
      body: body ? this.block(body) : [],
      span: decorators.length > 0 ? { ...outer, endLine: own.endLine, to: own.to } : own
    };
  }
}
