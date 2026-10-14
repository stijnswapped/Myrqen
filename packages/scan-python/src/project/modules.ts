import type { ClassDef, Expr, FunctionDef, Module, Stmt } from "../syntax/ast.js";

/**
 * The project as a set of importable modules.
 *
 * Python's data flow crosses files through imports, and so does every fact this
 * engine needs from another file: a helper's body, a Pydantic model's field
 * types, a router's prefix, an allow-list constant. This module answers one
 * question for all of them — "what does this name, in this file, refer to?" —
 * and answers it only from the project's own source. A name that leaves the
 * project resolves to its dotted import path (`subprocess.run`) and nothing more.
 */

export interface PyModule {
  relativePath: string;
  /** Dotted module name, e.g. `app.api.orders`. */
  name: string;
  /** Alternative names the same file is importable under (`src.app.x` and `app.x`). */
  aliases: string[];
  isPackage: boolean;
  text: string;
  ast: Module;
  parseErrors: number;
  /** Local name to what was imported under it. */
  imports: Map<string, ImportBinding>;
  functions: Map<string, FunctionDef>;
  classes: Map<string, ClassDef>;
  /** Module-level names bound by a plain assignment, last binding wins. */
  assignments: Map<string, Expr>;
}

export interface ImportBinding {
  /** Absolute dotted module the name came from. */
  module: string;
  /** The attribute imported from it, or null for `import a.b as c`. */
  member: string | null;
}

export type Symbol =
  | { kind: "function"; fn: FunctionDef; module: PyModule }
  | { kind: "class"; cls: ClassDef; module: PyModule }
  | { kind: "value"; expr: Expr; module: PyModule; name: string }
  | { kind: "module"; module: PyModule }
  | { kind: "external"; qualified: string };

export class Project {
  readonly modules: PyModule[] = [];
  private readonly byName = new Map<string, PyModule>();

  add(module: PyModule): void {
    this.modules.push(module);
    for (const name of [module.name, ...module.aliases]) {
      if (!this.byName.has(name)) this.byName.set(name, module);
    }
  }

  module(name: string): PyModule | undefined {
    return this.byName.get(name);
  }

  /** What `name` refers to at module scope of `module`. */
  resolve(module: PyModule, name: string, depth = 0): Symbol | undefined {
    if (depth > 8) return undefined;
    const fn = module.functions.get(name);
    if (fn) return { kind: "function", fn, module };
    const cls = module.classes.get(name);
    if (cls) return { kind: "class", cls, module };
    const binding = module.imports.get(name);
    if (binding) return this.resolveBinding(binding, depth + 1);
    const value = module.assignments.get(name);
    if (value) return { kind: "value", expr: value, module, name };
    return undefined;
  }

  private resolveBinding(binding: ImportBinding, depth: number): Symbol | undefined {
    if (binding.member === null) {
      const target = this.module(binding.module);
      return target ? { kind: "module", module: target } : { kind: "external", qualified: binding.module };
    }
    // `from pkg import name`: a submodule wins over a package attribute only when
    // the package does not define the name itself, which is Python's own order.
    const owner = this.module(binding.module);
    if (owner) {
      const inner = this.resolve(owner, binding.member, depth);
      if (inner) return inner;
    }
    const submodule = this.module(`${binding.module}.${binding.member}`);
    if (submodule) return { kind: "module", module: submodule };
    return { kind: "external", qualified: `${binding.module}.${binding.member}` };
  }

  /**
   * A dotted reference (`orders.router`, `services.reports.run`) resolved through
   * modules, or the external dotted path it names.
   */
  resolveExpr(module: PyModule, expr: Expr): Symbol | undefined {
    if (expr.k === "name") return this.resolve(module, expr.id);
    if (expr.k !== "attr") return undefined;
    const base = this.resolveExpr(module, expr.value);
    if (!base) return undefined;
    if (base.kind === "module") {
      const inner = this.resolve(base.module, expr.attr);
      if (inner) return inner;
      const submodule = this.module(`${base.module.name}.${expr.attr}`);
      return submodule ? { kind: "module", module: submodule } : undefined;
    }
    if (base.kind === "external") return { kind: "external", qualified: `${base.qualified}.${expr.attr}` };
    if (base.kind === "class") {
      const method = methodOf(base.cls, expr.attr);
      return method ? { kind: "function", fn: method, module: base.module } : undefined;
    }
    return undefined;
  }

  /** The fully qualified external name an expression refers to, if any. */
  qualified(module: PyModule, expr: Expr): string | null {
    const symbol = this.resolveExpr(module, expr);
    if (symbol?.kind === "external") return symbol.qualified;
    if (symbol?.kind === "function") return `${symbol.module.name}.${symbol.fn.name}`;
    if (symbol?.kind === "class") return `${symbol.module.name}.${symbol.cls.name}`;
    return null;
  }

  /** Follow module-level aliases until a value expression that is not a bare name. */
  constantValue(module: PyModule, name: string, depth = 0): { expr: Expr; module: PyModule } | undefined {
    if (depth > 6) return undefined;
    const symbol = this.resolve(module, name);
    if (!symbol || symbol.kind !== "value") return undefined;
    if (symbol.expr.k === "name") return this.constantValue(symbol.module, symbol.expr.id, depth + 1) ?? { expr: symbol.expr, module: symbol.module };
    return { expr: symbol.expr, module: symbol.module };
  }
}

export function methodOf(cls: ClassDef, name: string): FunctionDef | undefined {
  for (const stmt of cls.body) if (stmt.k === "funcdef" && stmt.name === name) return stmt;
  return undefined;
}

/** `app/api/orders.py` is `app.api.orders`; `app/__init__.py` is `app`. */
export function moduleNames(relativePath: string): { name: string; aliases: string[]; isPackage: boolean } {
  const withoutExtension = relativePath.replace(/\.pyi?$/, "");
  const segments = withoutExtension.split("/").filter(Boolean);
  const isPackage = segments[segments.length - 1] === "__init__";
  if (isPackage) segments.pop();
  const name = segments.join(".");
  const aliases: string[] = [];
  // A `src/` layout is importable without the `src.` prefix, and so is any file
  // under a top-level directory that is itself not a package (`backend/app/…`).
  for (let index = 1; index < segments.length; index += 1) aliases.push(segments.slice(index).join("."));
  return { name, aliases, isPackage };
}

/** Build the per-module tables from a parsed module. */
export function indexModule(
  relativePath: string,
  text: string,
  ast: Module,
  parseErrors: number
): PyModule {
  const { name, aliases, isPackage } = moduleNames(relativePath);
  const module: PyModule = {
    relativePath,
    name,
    aliases,
    isPackage,
    text,
    ast,
    parseErrors,
    imports: new Map(),
    functions: new Map(),
    classes: new Map(),
    assignments: new Map()
  };
  indexBlock(module, ast.body);
  return module;
}

/**
 * Module-level bindings, including those made inside `if`/`try` at module scope
 * (`try: import ujson as json except ImportError: import json`), which is where
 * real projects put their optional imports.
 */
function indexBlock(module: PyModule, body: Stmt[]): void {
  for (const stmt of body) {
    switch (stmt.k) {
      case "funcdef":
        module.functions.set(stmt.name, stmt);
        break;
      case "classdef":
        module.classes.set(stmt.name, stmt);
        break;
      case "assign":
        if (!stmt.value) break;
        for (const target of stmt.targets) {
          if (target.k === "name") module.assignments.set(target.id, stmt.value);
        }
        break;
      case "import":
        for (const entry of stmt.names) {
          if (entry.asname) module.imports.set(entry.asname, { module: entry.module, member: null });
          else {
            // `import a.b` binds `a`; attribute access then walks to `a.b`.
            const head = entry.module.split(".")[0]!;
            module.imports.set(head, { module: head, member: null });
          }
        }
        break;
      case "importfrom": {
        const base = absoluteModule(module, stmt.module, stmt.level);
        for (const entry of stmt.names) {
          if (entry.name === "*") continue;
          module.imports.set(entry.asname ?? entry.name, { module: base, member: entry.name });
        }
        break;
      }
      case "if":
        for (const branch of stmt.branches) indexBlock(module, branch.body);
        break;
      case "try":
        indexBlock(module, stmt.body);
        for (const handler of stmt.handlers) indexBlock(module, handler.body);
        indexBlock(module, stmt.orelse);
        break;
      default:
        break;
    }
  }
}

function absoluteModule(module: PyModule, name: string, level: number): string {
  if (level === 0) return name;
  const segments = module.name.split(".").filter(Boolean);
  // A module's package is its name minus the last segment; a package is its own.
  const packageSegments = module.isPackage ? segments : segments.slice(0, -1);
  const base = packageSegments.slice(0, Math.max(0, packageSegments.length - (level - 1)));
  return [...base, ...(name ? [name] : [])].join(".");
}
