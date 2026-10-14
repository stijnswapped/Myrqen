import type { SyntaxNode } from "@lezer/common";
import type { Expr, Keyword, Param, Span } from "./ast.js";

/**
 * Expression conversion, the lower half of the converter in `convert.ts`.
 *
 * Split out so neither file has to be read whole to change one construct:
 * statements live in `convert.ts` and build on the expression, sequence and
 * parameter-list handling here.
 */

const EXPRESSION_NODES = new Set([
  "VariableName",
  "MemberExpression",
  "CallExpression",
  "String",
  "FormatString",
  "ContinuedString",
  "Number",
  "None",
  "Boolean",
  "Ellipsis",
  "BinaryExpression",
  "UnaryExpression",
  "AwaitExpression",
  "ParenthesizedExpression",
  "ConditionalExpression",
  "LambdaExpression",
  "NamedExpression",
  "TupleExpression",
  "ArrayExpression",
  "SetExpression",
  "DictionaryExpression",
  "ArrayComprehensionExpression",
  "ComprehensionExpression",
  "SetComprehensionExpression",
  "DictionaryComprehensionExpression",
  "YieldExpression"
]);

export function isExpr(node: SyntaxNode): boolean {
  return EXPRESSION_NODES.has(node.name);
}

export function childrenOf(node: SyntaxNode): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  for (let child = node.firstChild; child; child = child.nextSibling) {
    if (child.type.isError || child.name === "Comment") continue;
    out.push(child);
  }
  return out;
}

export class ExpressionConverter {
  private readonly lineStarts: number[] = [0];

  constructor(protected readonly text: string) {
    for (let index = 0; index < text.length; index += 1) {
      if (text.charCodeAt(index) === 10) this.lineStarts.push(index + 1);
    }
  }

  protected lineAt(position: number): number {
    let low = 0;
    let high = this.lineStarts.length - 1;
    while (low < high) {
      const middle = (low + high + 1) >> 1;
      if ((this.lineStarts[middle] ?? 0) <= position) low = middle;
      else high = middle - 1;
    }
    return low + 1;
  }

  span(node: SyntaxNode): Span {
    // The end of a block is the last non-whitespace character it owns, so a body
    // does not appear to run on to the blank line after it.
    let end = node.to;
    while (end > node.from && /\s/.test(this.text[end - 1] ?? "")) end -= 1;
    return { line: this.lineAt(node.from), endLine: this.lineAt(Math.max(node.from, end - 1)), from: node.from, to: node.to };
  }

  protected source(node: SyntaxNode): string {
    return this.text.slice(node.from, node.to);
  }

  /** A comma-separated run of expressions, as a tuple when there is more than one. */
  protected sequence(parts: SyntaxNode[]): Expr | null {
    const exprs: Expr[] = [];
    let star = false;
    let hasComma = false;
    for (const part of parts) {
      if (part.name === ",") {
        hasComma = true;
        continue;
      }
      if (part.name === "*") {
        star = true;
        continue;
      }
      if (!isExpr(part)) continue;
      const expr = this.expr(part);
      exprs.push(star ? { k: "starred", value: expr, double: false, span: expr.span } : expr);
      star = false;
    }
    if (exprs.length === 0) return null;
    if (exprs.length === 1 && !hasComma) return exprs[0]!;
    const first = exprs[0]!.span;
    const last = exprs[exprs.length - 1]!.span;
    return { k: "tuple", elts: exprs, span: { line: first.line, endLine: last.endLine, from: first.from, to: last.to } };
  }

  protected params(node: SyntaxNode): Param[] {
    const out: Param[] = [];
    let kind: Param["kind"] = "normal";
    let current: Param | null = null;
    let afterAssign = false;
    for (const part of childrenOf(node)) {
      switch (part.name) {
        case "(":
        case ")":
        case "/":
          continue;
        case ",":
          current = null;
          afterAssign = false;
          kind = "normal";
          continue;
        case "*":
          kind = "vararg";
          continue;
        case "**":
          kind = "kwarg";
          continue;
        case "AssignOp":
          afterAssign = true;
          continue;
        case "TypeDef": {
          const typeExpr = childrenOf(part).find(isExpr);
          if (current && typeExpr) current.annotation = this.expr(typeExpr);
          continue;
        }
        default:
          if (afterAssign && current && isExpr(part)) {
            current.default = this.expr(part);
            afterAssign = false;
            continue;
          }
          if (part.name === "VariableName") {
            current = { name: this.source(part), annotation: null, default: null, kind, span: this.span(part) };
            out.push(current);
          }
      }
    }
    return out;
  }

  /* ----------------------------------------------------------- expressions */

  protected firstExpr(parts: SyntaxNode[]): Expr | null {
    const node = parts.find(isExpr);
    return node ? this.expr(node) : null;
  }

  protected other(children: Expr[], span: Span): Expr {
    return { k: "other", children, span };
  }

  expr(node: SyntaxNode): Expr {
    const span = this.span(node);
    const parts = childrenOf(node);
    switch (node.name) {
      case "VariableName":
        return { k: "name", id: this.source(node), span };
      case "Number": {
        const value = Number(this.source(node).replace(/_/g, ""));
        return { k: "num", value: Number.isFinite(value) ? value : 0, span };
      }
      case "None":
      case "Ellipsis":
        return { k: "const", value: null, span };
      case "Boolean":
        return { k: "const", value: this.source(node) === "True", span };
      case "String":
        return this.stringLiteral(node, span);
      case "FormatString":
        return { k: "fstr", parts: this.formatParts(node), span };
      case "ContinuedString":
        return this.continuedString(parts, span);
      case "MemberExpression":
        return this.member(parts, span);
      case "CallExpression": {
        const callee = parts[0];
        const args = parts.find((part) => part.name === "ArgList");
        if (!callee || !args) return this.other(parts.filter(isExpr).map((part) => this.expr(part)), span);
        return this.call(this.expr(callee), args, span);
      }
      case "ParenthesizedExpression": {
        const inner = this.sequence(parts.filter((part) => part.name !== "(" && part.name !== ")"));
        return inner ?? this.other([], span);
      }
      case "TupleExpression":
        return { k: "tuple", elts: this.elements(parts), span };
      case "ArrayExpression":
        return { k: "list", elts: this.elements(parts), span };
      case "SetExpression":
        return { k: "set", elts: this.elements(parts), span };
      case "DictionaryExpression":
        return this.dictionary(parts, span);
      case "ArrayComprehensionExpression":
      case "ComprehensionExpression":
      case "SetComprehensionExpression":
      case "DictionaryComprehensionExpression":
        return this.comprehension(parts, span, node.name === "DictionaryComprehensionExpression");
      case "BinaryExpression":
        return this.binary(parts, span);
      case "UnaryExpression": {
        const operand = parts.find(isExpr);
        const op = parts[0] ? this.source(parts[0]) : "";
        if (!operand) return this.other([], span);
        return op === "not" ? this.negate(operand, span) : { k: "unary", op, operand: this.expr(operand), span };
      }
      case "AwaitExpression": {
        const value = parts.find(isExpr);
        return value ? { k: "await", value: this.expr(value), span } : this.other([], span);
      }
      case "ConditionalExpression": {
        const exprs = parts.filter(isExpr).map((part) => this.expr(part));
        if (exprs.length < 3) return this.other(exprs, span);
        return { k: "ifexp", body: exprs[0]!, test: exprs[1]!, orelse: exprs[2]!, span };
      }
      case "LambdaExpression": {
        const paramList = parts.find((part) => part.name === "ParamList");
        const bodyNode = [...parts].reverse().find(isExpr);
        return {
          k: "lambda",
          params: paramList ? this.params(paramList) : [],
          body: bodyNode ? this.expr(bodyNode) : this.other([], span),
          span
        };
      }
      case "NamedExpression": {
        const target = parts.find((part) => part.name === "VariableName");
        const value = [...parts].reverse().find(isExpr);
        if (!target || !value || value === target) return this.other([], span);
        return { k: "named", target: this.source(target), value: this.expr(value), span };
      }
      case "YieldExpression":
        return { k: "yield", value: this.firstExpr(parts), span };
      default:
        return this.other(parts.filter(isExpr).map((part) => this.expr(part)), span);
    }
  }

  /**
   * `not` applied to its operand with Python's precedence.
   *
   * The grammar gives `not` a lower precedence than `and`/`or`, so `not a or b`
   * arrives as `not (a or b)`. Python binds `not` tighter: it is `(not a) or b`.
   * Reading it the grammar's way inverts every guard written as
   * `if not allowed(x) or not other(x): abort()`, so the operator is pushed back
   * onto the leftmost operand whenever the boolean expression was not
   * parenthesised in the source.
   */
  protected negate(operand: SyntaxNode, span: Span): Expr {
    if (operand.name === "BinaryExpression") {
      const parts = childrenOf(operand);
      const exprIndexes = parts.map((part, index) => (isExpr(part) ? index : -1)).filter((index) => index >= 0);
      const leftIndex = exprIndexes[0];
      const rightIndex = exprIndexes[exprIndexes.length - 1];
      if (leftIndex !== undefined && rightIndex !== undefined && leftIndex !== rightIndex) {
        const op = parts
          .slice(leftIndex + 1, rightIndex)
          .map((part) => this.source(part))
          .join(" ")
          .trim();
        if (op === "and" || op === "or") {
          return {
            k: "boolop",
            op,
            left: this.negate(parts[leftIndex]!, this.span(parts[leftIndex]!)),
            right: this.expr(parts[rightIndex]!),
            span: this.span(operand)
          };
        }
      }
    }
    return { k: "not", operand: this.expr(operand), span };
  }

  protected member(parts: SyntaxNode[], span: Span): Expr {
    const object = parts[0];
    if (!object) return this.other([], span);
    const value = this.expr(object);
    const property = parts.find((part) => part.name === "PropertyName");
    if (property && parts[1]?.name === ".") return { k: "attr", value, attr: this.source(property), span };
    // Subscript: `a[b]`, `a[b, c]`, `a[1:2]`.
    const inside = parts.slice(1).filter((part) => part.name !== "[" && part.name !== "]");
    if (inside.some((part) => part.name === ":")) {
      return { k: "subscript", value, index: null, span };
    }
    return { k: "subscript", value, index: this.sequence(inside), span };
  }

  protected call(func: Expr, argList: SyntaxNode, span: Span): Expr {
    const { args, kwargs } = this.argList(argList);
    return { k: "call", func, args, kwargs, span };
  }

  protected argList(node: SyntaxNode): { args: Expr[]; kwargs: Keyword[] } {
    const parts = childrenOf(node);
    const args: Expr[] = [];
    const kwargs: Keyword[] = [];
    // A generator expression as the sole argument: `any(x for x in y)`.
    if (parts.some((part) => part.name === "for")) {
      const span = this.span(node);
      args.push(this.comprehension(parts.filter((part) => part.name !== "(" && part.name !== ")"), span, false));
      return { args, kwargs };
    }
    let pendingName: string | null = null;
    let star: "" | "*" | "**" = "";
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index]!;
      if (part.name === "(" || part.name === ")" || part.name === ",") continue;
      if (part.name === "*" || part.name === "**") {
        star = part.name;
        continue;
      }
      if (part.name === "VariableName" && parts[index + 1]?.name === "AssignOp") {
        pendingName = this.source(part);
        index += 1;
        continue;
      }
      if (!isExpr(part)) continue;
      const value = this.expr(part);
      if (pendingName !== null) {
        kwargs.push({ name: pendingName, value });
        pendingName = null;
      } else if (star === "**") {
        kwargs.push({ name: null, value });
      } else if (star === "*") {
        args.push({ k: "starred", value, double: false, span: value.span });
      } else {
        args.push(value);
      }
      star = "";
    }
    return { args, kwargs };
  }

  protected elements(parts: SyntaxNode[]): Expr[] {
    const out: Expr[] = [];
    let star = false;
    for (const part of parts) {
      if (part.name === "*") {
        star = true;
        continue;
      }
      if (!isExpr(part)) continue;
      const expr = this.expr(part);
      out.push(star ? { k: "starred", value: expr, double: false, span: expr.span } : expr);
      star = false;
    }
    return out;
  }

  protected dictionary(parts: SyntaxNode[], span: Span): Expr {
    const entries: Array<{ key: Expr | null; value: Expr }> = [];
    let key: Expr | null = null;
    let afterColon = false;
    let spread = false;
    for (const part of parts) {
      if (part.name === ":") {
        afterColon = true;
        continue;
      }
      if (part.name === ",") {
        key = null;
        afterColon = false;
        continue;
      }
      if (part.name === "**") {
        spread = true;
        continue;
      }
      if (!isExpr(part)) continue;
      const expr = this.expr(part);
      if (spread) {
        entries.push({ key: null, value: expr });
        spread = false;
      } else if (afterColon && key) {
        entries.push({ key, value: expr });
        key = null;
        afterColon = false;
      } else {
        key = expr;
      }
    }
    return { k: "dict", entries, span };
  }

  protected comprehension(parts: SyntaxNode[], span: Span, isDict: boolean): Expr {
    // elt [":" value] ("for" targets "in" iter ("if" cond)*)+
    let elt: Expr | null = null;
    let key: Expr | null = null;
    const targets: Expr[] = [];
    const iters: Expr[] = [];
    const conds: Expr[] = [];
    let mode: "elt" | "value" | "target" | "iter" | "cond" = "elt";
    let targetRun: SyntaxNode[] = [];
    for (const part of parts) {
      switch (part.name) {
        case "for":
          mode = "target";
          targetRun = [];
          continue;
        case "in":
          if (mode === "target") {
            const target = this.sequence(targetRun);
            if (target) targets.push(target);
            mode = "iter";
            continue;
          }
          break;
        case "if":
          mode = "cond";
          continue;
        case ":":
          if (mode === "elt" && isDict) mode = "value";
          continue;
        case "async":
          continue;
        default:
          break;
      }
      if (mode === "target") {
        targetRun.push(part);
        continue;
      }
      if (!isExpr(part)) continue;
      const expr = this.expr(part);
      if (mode === "elt") {
        if (isDict) key = expr;
        else elt = expr;
      } else if (mode === "value") elt = expr;
      else if (mode === "iter") iters.push(expr);
      else conds.push(expr);
    }
    return { k: "comp", elt: elt ?? this.other([], span), key, targets, iters, conds, span };
  }

  protected binary(parts: SyntaxNode[], span: Span): Expr {
    const exprIndexes = parts.map((part, index) => (isExpr(part) ? index : -1)).filter((index) => index >= 0);
    if (exprIndexes.length < 2) return this.other(parts.filter(isExpr).map((part) => this.expr(part)), span);
    const leftIndex = exprIndexes[0]!;
    const rightIndex = exprIndexes[exprIndexes.length - 1]!;
    const left = this.expr(parts[leftIndex]!);
    const right = this.expr(parts[rightIndex]!);
    const op = parts
      .slice(leftIndex + 1, rightIndex)
      .map((part) => this.source(part))
      .join(" ")
      .trim();
    if (op === "and" || op === "or") return { k: "boolop", op, left, right, span };
    if (/^(==|!=|<|>|<=|>=|<>|in|not in|is|is not)$/.test(op)) return { k: "compare", op, left, right, span };
    return { k: "binop", op, left, right, span };
  }

  /* ---------------------------------------------------------------- strings */

  protected stringLiteral(node: SyntaxNode, span: Span): Expr {
    const raw = this.source(node);
    const prefix = /^[A-Za-z]*/.exec(raw)?.[0] ?? "";
    const body = raw.slice(prefix.length);
    const quote = body.startsWith('"""') || body.startsWith("'''") ? 3 : 1;
    let value = body.slice(quote, Math.max(quote, body.length - quote));
    if (!/r/i.test(prefix)) value = unescape(value);
    return { k: "str", value, bytes: /b/i.test(prefix), span };
  }

  protected formatParts(node: SyntaxNode): Array<string | Expr> {
    const raw = this.source(node);
    const prefix = /^[A-Za-z]*/.exec(raw)?.[0] ?? "";
    const body = raw.slice(prefix.length);
    const quote = body.startsWith('"""') || body.startsWith("'''") ? 3 : 1;
    const contentStart = node.from + prefix.length + quote;
    const contentEnd = Math.max(contentStart, node.to - quote);
    const isRaw = /r/i.test(prefix);
    const parts: Array<string | Expr> = [];
    let cursor = contentStart;
    const pushLiteral = (from: number, to: number) => {
      if (to <= from) return;
      let text = this.text.slice(from, to).replace(/\{\{/g, "{").replace(/\}\}/g, "}");
      if (!isRaw) text = unescape(text);
      parts.push(text);
    };
    for (const child of childrenOf(node)) {
      if (child.name !== "FormatReplacement") continue;
      pushLiteral(cursor, child.from);
      for (const inner of childrenOf(child)) {
        if (isExpr(inner)) parts.push(this.expr(inner));
        else if (inner.name === "FormatSpec") {
          for (const nested of childrenOf(inner)) {
            if (nested.name !== "FormatReplacement") continue;
            for (const deep of childrenOf(nested)) if (isExpr(deep)) parts.push(this.expr(deep));
          }
        }
      }
      cursor = child.to;
    }
    pushLiteral(cursor, contentEnd);
    return parts;
  }

  protected continuedString(parts: SyntaxNode[], span: Span): Expr {
    const pieces = parts.map((part) => this.expr(part));
    if (pieces.every((piece) => piece.k === "str")) {
      return {
        k: "str",
        value: pieces.map((piece) => (piece.k === "str" ? piece.value : "")).join(""),
        bytes: pieces.some((piece) => piece.k === "str" && piece.bytes),
        span
      };
    }
    const merged: Array<string | Expr> = [];
    for (const piece of pieces) {
      if (piece.k === "str") merged.push(piece.value);
      else if (piece.k === "fstr") merged.push(...piece.parts);
      else merged.push(piece);
    }
    return { k: "fstr", parts: merged, span };
  }
}

function unescape(value: string): string {
  return value.replace(/\\(\\|'|"|n|t|r|\n)/g, (_match, char: string) => {
    switch (char) {
      case "n":
        return "\n";
      case "t":
        return "\t";
      case "r":
        return "\r";
      case "\n":
        return "";
      default:
        return char;
    }
  });
}
