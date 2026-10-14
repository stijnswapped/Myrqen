import type { Expr, FunctionDef, Param, Stmt } from "../syntax/ast.js";
import { constString, dotted, exprsIn, keyword, walkExpr, walkStmts } from "../syntax/ast.js";
import { ALL_SINKS, type ModelInfo, type SinkClass, type SourceKind } from "../analysis/values.js";
import type { Project, PyModule } from "./modules.js";
import { markerName, patternCleans, type TypeReader } from "./types.js";

/**
 * Entry points: the functions a caller can reach, and what each parameter holds.
 *
 * Two frameworks, modelled from their own semantics rather than by shape:
 *
 *  - FastAPI. A path operation is a function decorated by `@router.get(...)` on
 *    an `APIRouter` or `FastAPI` instance. Its parameters are filled by the
 *    framework: from the path when the name appears in the template, from the
 *    body when the type is a Pydantic model, from the query string otherwise,
 *    and from a dependency when the default is `Depends(...)`. A dependency on a
 *    function that resolves the caller (`get_current_user`) is authentication.
 *
 *  - Flask. A view is a function decorated by `@app.route(...)` on a `Flask` or
 *    `Blueprint` instance. Its parameters come from the URL converters; every
 *    other input is read from the `request` proxy. Authentication is a decorator
 *    (`@login_required`), a `before_request` hook on the blueprint or the app,
 *    or a check in the body.
 *
 * Routers are followed through `include_router` and `register_blueprint`, so a
 * route declared as `/{id}` on a router mounted at `/api/orders` is reported at
 * `/api/orders/:id`.
 */

export type Framework = "fastapi" | "flask";

export interface ParamSource {
  kind: SourceKind | "dependency" | "injected";
  clean: ReadonlySet<SinkClass>;
  model?: ModelInfo;
  /** For a dependency: the function it calls, when resolvable. */
  dependency?: string;
  authDependency?: boolean;
}

export interface RouteInfo {
  framework: Framework;
  module: PyModule;
  fn: FunctionDef;
  methods: string[];
  /** Full path in `:param` form, mounts included where they were resolvable. */
  path: string;
  /** The path as the decorator alone spells it (with the router's own prefix). */
  declaredPath: string;
  /** Line of the route decorator. */
  line: number;
  ownerKey: string;
  authenticated: boolean;
  authEvidence: string | null;
  /** Authentication was considered and made optional (`@jwt_optional`, `required=False`). */
  optionalAuth: boolean;
  /** Names in the handler that hold the authenticated subject. */
  subjects: string[];
  params: Map<string, ParamSource>;
  pathParams: Set<string>;
}

interface RouterDecl {
  key: string;
  module: PyModule;
  name: string;
  framework: Framework;
  kind: "app" | "router";
  prefix: string;
  authenticated: string | null;
}

interface Mount {
  child: string;
  parent: string;
  prefix: string;
  authenticated: string | null;
}

const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options"]);

/** A dependency or decorator that resolves or requires the caller's identity. */
export const AUTH_NAME =
  /(current_?(\w*_)?(user|account|member|superuser|admin|principal|identity|staff)|authenticat|authoriz|login_?required|logged_?in|require_?(user|auth|login|role|admin|scope|permission|staff|member|superuser)|requires_?(auth|login|role|permission)|jwt_?required|token_?required|auth_?required|permission|roles?_?required|admin_?required|staff_?required|superuser|verify_?(token|jwt|user|api_?key|session)|get_?user|get_?principal|get_?identity|principal|get_?caller|api_?key_?auth|oauth2_scheme|bearer|check_?(auth|token)|is_?authenticated|ensure_?(user|auth|login)|user_?required|\.login_required$)/i;

/** An authentication check that deliberately lets anonymous callers through. */
export const OPTIONAL_AUTH = /(optional|required\s*=\s*False|allow_anonymous|anonymous_allowed)/i;

/** Dependencies whose name suggests identity but which supply infrastructure. */
const NOT_AUTH = /(^|_)(db|database|session|sessions|engine|conn|connection|settings|config|cache|redis|client|repo|repository|service|storage|logger|mailer|queue|http)$/i;

export function isAuthName(name: string | null | undefined): boolean {
  if (!name) return false;
  const tail = name.split(".").pop() ?? name;
  return AUTH_NAME.test(tail) && !NOT_AUTH.test(tail);
}

export class FrameworkModel {
  readonly routes: RouteInfo[] = [];
  readonly frameworks = new Set<Framework>();
  private readonly routers = new Map<string, RouterDecl>();
  private readonly mounts: Mount[] = [];
  private readonly beforeRequestAuth = new Map<string, string>();

  constructor(
    private readonly project: Project,
    private readonly types: TypeReader
  ) {
    for (const module of project.modules) this.collectRouters(module);
    for (const module of project.modules) this.collectMounts(module);
    for (const module of project.modules) this.collectRoutes(module);
    this.routes.sort((a, b) => a.module.relativePath.localeCompare(b.module.relativePath) || a.line - b.line);
  }

  /** The route a function implements, if any. */
  routeOf(fn: FunctionDef): RouteInfo | undefined {
    return this.routes.find((route) => route.fn === fn);
  }

  /** Every route a function implements: one per method and path. */
  routesOf(fn: FunctionDef): RouteInfo[] {
    return this.routes.filter((route) => route.fn === fn);
  }

  /* -------------------------------------------------------------- routers */

  private collectRouters(module: PyModule): void {
    // Module-level bindings, and those made inside an application factory
    // (`def create_app(): app = Flask(__name__)`), where most Flask apps live.
    const bindings: Array<[string, Expr]> = [...module.assignments];
    walkStmts(module.ast.body, (stmt) => {
      if (stmt.k !== "funcdef") return;
      walkStmts(stmt.body, (inner) => {
        if (inner.k !== "assign" || !inner.value) return;
        for (const target of inner.targets) {
          if (target.k === "name" && !module.assignments.has(target.id)) bindings.push([target.id, inner.value]);
        }
      });
    }, true);
    for (const [name, expr] of bindings) {
      if (expr.k !== "call") continue;
      const kind = this.constructorKind(module, expr);
      if (!kind) continue;
      const decl: RouterDecl = {
        key: `${module.name}:${name}`,
        module,
        name,
        framework: kind.framework,
        kind: kind.kind,
        prefix: normalisePath(constString(keyword(expr, kind.framework === "flask" ? "url_prefix" : "prefix")) ?? "", kind.framework),
        authenticated: this.dependenciesAuth(module, keyword(expr, "dependencies"))
      };
      this.routers.set(decl.key, decl);
      this.frameworks.add(kind.framework);
    }
    // `@bp.before_request` and `bp.before_request(fn)` hooks that check identity.
    for (const stmt of module.ast.body) {
      if (stmt.k === "funcdef") {
        for (const decorator of stmt.decorators) {
          const name = dotted(decorator.expr) ?? "";
          const match = /^(.+)\.before_(app_)?request$/.exec(name);
          if (match && looksLikeAuthHook(stmt)) this.beforeRequestAuth.set(`${module.name}:${match[1]}`, `${name} hook ${stmt.name}`);
        }
      }
      if (stmt.k === "expr" && stmt.value.k === "call") {
        const name = dotted(stmt.value.func) ?? "";
        const match = /^(.+)\.before_(app_)?request$/.exec(name);
        const hook = stmt.value.args[0];
        if (match && hook?.k === "name") {
          const fn = module.functions.get(hook.id);
          if (fn && looksLikeAuthHook(fn)) this.beforeRequestAuth.set(`${module.name}:${match[1]}`, `${name}(${hook.id})`);
        }
      }
    }
  }

  private constructorKind(module: PyModule, call: Extract<Expr, { k: "call" }>): { framework: Framework; kind: "app" | "router" } | null {
    const qualified = this.project.qualified(module, call.func) ?? dotted(call.func) ?? "";
    if (/(^|\.)FastAPI$/.test(qualified) && /fastapi|^FastAPI$/.test(qualified)) return { framework: "fastapi", kind: "app" };
    if (/(^|\.)APIRouter$/.test(qualified)) return { framework: "fastapi", kind: "router" };
    if (/(^|\.)Flask$/.test(qualified) && /flask|^Flask$/.test(qualified)) return { framework: "flask", kind: "app" };
    if (/(^|\.)Blueprint$/.test(qualified) && /flask|^Blueprint$/.test(qualified)) return { framework: "flask", kind: "router" };
    if (/(^|\.)(APIFlask|Quart)$/.test(qualified)) return { framework: "flask", kind: "app" };
    return null;
  }

  private dependenciesAuth(module: PyModule, list: Expr | undefined): string | null {
    if (!list || (list.k !== "list" && list.k !== "tuple")) return null;
    for (const element of list.elts) {
      if (element.k !== "call") continue;
      const marker = markerName(element);
      if (marker !== "Depends" && marker !== "Security") continue;
      const target = element.args[0];
      const name = target ? dotted(target) : null;
      if (isAuthName(name)) return `dependencies=[Depends(${name})]`;
    }
    return null;
  }

  /** The router declaration an expression names, following imports. */
  private routerFor(module: PyModule, expr: Expr): RouterDecl | undefined {
    if (expr.k === "name") {
      const local = this.routers.get(`${module.name}:${expr.id}`);
      if (local) return local;
      const symbol = this.project.resolve(module, expr.id);
      if (symbol?.kind === "value") return this.routers.get(`${symbol.module.name}:${symbol.name}`);
      return undefined;
    }
    if (expr.k === "attr") {
      const symbol = this.project.resolveExpr(module, expr.value);
      if (symbol?.kind === "module") {
        const direct = this.routers.get(`${symbol.module.name}:${expr.attr}`);
        if (direct) return direct;
        const inner = this.project.resolve(symbol.module, expr.attr);
        if (inner?.kind === "value") return this.routers.get(`${inner.module.name}:${inner.name}`);
      }
    }
    return undefined;
  }

  /* --------------------------------------------------------------- mounts */

  private collectMounts(module: PyModule): void {
    const visit = (expr: Expr) => {
      if (expr.k !== "call" || expr.func.k !== "attr") return;
      const method = expr.func.attr;
      if (method !== "include_router" && method !== "register_blueprint") return;
      const parent = this.routerFor(module, expr.func.value);
      const childExpr = expr.args[0];
      const child = childExpr ? this.routerFor(module, childExpr) : undefined;
      if (!parent || !child || parent === child) return;
      const framework = child.framework;
      const prefixExpr = keyword(expr, framework === "flask" ? "url_prefix" : "prefix");
      const prefix = prefixExpr ? staticPrefix(prefixExpr, child.prefix) : "";
      this.mounts.push({
        child: child.key,
        parent: parent.key,
        prefix: normalisePath(prefix ?? "", framework),
        authenticated: this.dependenciesAuth(module, keyword(expr, "dependencies"))
      });
      // Flask: a `url_prefix` given at registration replaces the blueprint's own.
      // When the given prefix cannot be read, the blueprint's own is kept, which
      // reports a shorter path rather than a wrong one.
      if (framework === "flask" && prefixExpr && prefix !== null) child.prefix = "";
    };
    for (const expr of exprsIn(module.ast.body)) walkExpr(expr, visit);
    walkStmts(module.ast.body, (stmt) => {
      if (stmt.k === "funcdef") for (const expr of exprsIn(stmt.body)) walkExpr(expr, visit);
      // `for module in (orders, products): app.include_router(module.router, prefix="/api")`
      if (stmt.k === "for" && stmt.target.k === "name" && (stmt.iter.k === "tuple" || stmt.iter.k === "list")) {
        const loopName = stmt.target.id;
        for (const element of stmt.iter.elts) {
          for (const expr of exprsIn(stmt.body)) {
            walkExpr(expr, (inner) => {
              if (inner.k !== "call" || !inner.args[0]) return;
              const child = substituteName(inner.args[0], loopName, element);
              if (child !== inner.args[0]) visit({ ...inner, args: [child, ...inner.args.slice(1)] });
            });
          }
        }
      }
    }, true);
  }

  /** The prefix above a router, and any authentication applied on the way down. */
  private mountChain(key: string, seen = new Set<string>()): { prefix: string; auth: string | null } {
    if (seen.has(key)) return { prefix: "", auth: null };
    seen.add(key);
    const mount = this.mounts.find((candidate) => candidate.child === key);
    const decl = this.routers.get(key);
    const ownAuth = decl?.authenticated ?? this.beforeRequestAuth.get(key) ?? null;
    if (!mount) return { prefix: decl?.prefix ?? "", auth: ownAuth };
    const parent = this.mountChain(mount.parent, seen);
    return {
      prefix: joinPaths(joinPaths(parent.prefix, mount.prefix), decl?.prefix ?? ""),
      auth: ownAuth ?? mount.authenticated ?? parent.auth
    };
  }

  /* --------------------------------------------------------------- routes */

  private collectRoutes(module: PyModule): void {
    const visit = (body: Stmt[]) => {
      for (const stmt of body) {
        if (stmt.k === "funcdef") {
          this.considerFunction(module, stmt);
          visit(stmt.body);
        } else if (stmt.k === "classdef") {
          visit(stmt.body);
        } else if (stmt.k === "if" || stmt.k === "try" || stmt.k === "with") {
          for (const block of stmt.k === "if" ? stmt.branches.map((b) => b.body) : stmt.k === "try" ? [stmt.body] : [stmt.body]) visit(block);
        }
      }
    };
    visit(module.ast.body);
  }

  private considerFunction(module: PyModule, fn: FunctionDef): void {
    for (const decorator of fn.decorators) {
      if (decorator.expr.k !== "call" || decorator.expr.func.k !== "attr") continue;
      const method = decorator.expr.func.attr;
      const receiver = decorator.expr.func.value;
      if (method !== "route" && method !== "api_route" && !ROUTE_METHODS.has(method)) continue;
      const pathArg = constString(decorator.expr.args[0] ?? keyword(decorator.expr, "path") ?? keyword(decorator.expr, "rule"));
      if (pathArg === null) continue;

      let router = this.routerFor(module, receiver);
      const framework: Framework | null = router?.framework ?? this.inferFramework(module, receiver);
      if (!framework) continue;
      this.frameworks.add(framework);

      const methods =
        method === "route" || method === "api_route"
          ? methodsOf(keyword(decorator.expr, "methods")) ?? (framework === "flask" ? ["GET"] : ["GET"])
          : [method.toUpperCase()];

      const ownerKey = router?.key ?? `${module.name}:${dotted(receiver) ?? "?"}`;
      const chain = router ? this.mountChain(router.key) : { prefix: "", auth: null };
      const routerPrefix = router?.prefix ?? "";
      const declared = joinPaths(routerPrefix, normalisePath(pathArg, framework));
      const full = router ? joinPaths(chain.prefix, normalisePath(pathArg, framework)) : declared;
      const pathParams = new Set(pathParameterNames(pathArg, framework));

      const params = framework === "fastapi" ? this.fastapiParams(module, fn, pathParams) : flaskParams(fn, pathArg);
      const decoratorAuth =
        framework === "fastapi"
          ? this.dependenciesAuth(module, keyword(decorator.expr, "dependencies"))
          : fn.decorators.map((d) => dotted(d.expr.k === "call" ? d.expr.func : d.expr)).find((name) => isAuthName(name) && !/\.(route|get|post|put|patch|delete)$/.test(name ?? "")) ?? null;

      const subjects: string[] = [];
      let paramAuth: string | null = null;
      for (const [name, source] of params) {
        if (source.authDependency) {
          subjects.push(name);
          paramAuth ??= `Depends(${source.dependency ?? "?"}) on ${name}`;
        }
      }
      const appAuth = framework === "flask" ? this.flaskAppHookFor(router) : null;
      const bodyAuth = inBodyAuth(module, fn, framework, params);
      if (framework === "flask") subjects.push(...flaskSubjects(module, fn));

      const authEvidence = decoratorAuth ?? paramAuth ?? chain.auth ?? appAuth ?? bodyAuth;
      const signature = [
        ...fn.decorators.map((d) => module.text.slice(d.span.from, d.span.to)),
        ...fn.params.map((p) => (p.default ? module.text.slice(p.default.span.from, p.default.span.to) : ""))
      ].join(" ");
      const optionalAuth = OPTIONAL_AUTH.test(signature);
      if (!router) router = undefined;
      for (const verb of methods) {
        this.routes.push({
          framework,
          module,
          fn,
          methods: [verb],
          path: full,
          declaredPath: declared,
          line: decorator.span.line,
          ownerKey,
          authenticated: authEvidence !== null,
          authEvidence,
          optionalAuth,
          subjects,
          params,
          pathParams
        });
      }
    }
  }

  /** Flask app-level `before_request` hooks apply to every blueprint mounted on it. */
  private flaskAppHookFor(router: RouterDecl | undefined): string | null {
    if (!router) return null;
    let key: string | undefined = router.key;
    const seen = new Set<string>();
    while (key && !seen.has(key)) {
      seen.add(key);
      const hook = this.beforeRequestAuth.get(key);
      if (hook) return hook;
      key = this.mounts.find((mount) => mount.child === key)?.parent;
    }
    return null;
  }

  private inferFramework(module: PyModule, receiver: Expr): Framework | null {
    const name = dotted(receiver) ?? "";
    if (!/^(app|api|router|bp|blueprint|\w+_(router|bp|blueprint|api)|\w+(Router|Blueprint))$/.test(name)) return null;
    const imports = [...module.imports.values()].map((binding) => binding.module);
    if (imports.some((m) => m === "fastapi" || m.startsWith("fastapi."))) return "fastapi";
    if (imports.some((m) => m === "flask" || m.startsWith("flask."))) return "flask";
    return null;
  }

  private fastapiParams(module: PyModule, fn: FunctionDef, pathParams: Set<string>): Map<string, ParamSource> {
    const out = new Map<string, ParamSource>();
    for (const param of fn.params) {
      if (param.kind !== "normal") continue;
      out.set(param.name, this.fastapiParam(module, param, pathParams));
    }
    return out;
  }

  private fastapiParam(module: PyModule, param: Param, pathParams: Set<string>): ParamSource {
    const info = this.types.annotation(module, param.annotation);
    const defaultMarker = markerName(param.default);
    const dependency =
      defaultMarker === "Depends" || defaultMarker === "Security"
        ? (param.default as Extract<Expr, { k: "call" }>).args[0] ?? param.annotation
        : info.dependency;
    if (dependency !== undefined && dependency !== null || defaultMarker === "Depends" || defaultMarker === "Security") {
      const name = dependency ? dotted(dependency) : null;
      const annotationName = param.annotation ? dotted(param.annotation) : null;
      const source: ParamSource = { kind: "dependency", clean: ALL_SINKS };
      if (name) source.dependency = name;
      if (isAuthName(name) || (defaultMarker === "Security") || (name === null && isAuthName(annotationName))) {
        source.authDependency = true;
      }
      return source;
    }
    if (info.request) return { kind: "request", clean: new Set() };
    if (info.injected) return { kind: "injected", clean: ALL_SINKS };
    if (info.upload) return { kind: "file", clean: new Set() };

    const marker = info.marker ?? (param.default?.k === "call" && markerName(param.default) ? param.default : undefined);
    const clean = new Set(info.clean);
    if (marker) {
      const pattern = constString(keyword(marker, "pattern") ?? keyword(marker, "regex"));
      if (pattern) for (const sink of patternCleans(pattern)) clean.add(sink);
    }
    const markerKind = marker ? markerName(marker) : null;
    let kind: SourceKind;
    if (pathParams.has(param.name) || markerKind === "Path") kind = "path";
    else if (markerKind === "Header") kind = "header";
    else if (markerKind === "Cookie") kind = "cookie";
    else if (markerKind === "Form") kind = "form";
    else if (markerKind === "File") kind = "file";
    else if (markerKind === "Body" || info.model) kind = "body";
    else kind = "query";
    // An unrecognised class annotation on a non-path parameter is a request body
    // whose fields this scan cannot see; it stays fully tainted.
    const source: ParamSource = { kind, clean };
    if (info.model) source.model = info.model;
    return source;
  }
}

function flaskParams(fn: FunctionDef, rule: string): Map<string, ParamSource> {
  const out = new Map<string, ParamSource>();
  const converters = new Map<string, string>();
  for (const match of rule.matchAll(/<(?:(\w+)(?:\([^)]*\))?:)?(\w+)>/g)) converters.set(match[2]!, match[1] ?? "string");
  for (const param of fn.params) {
    const converter = converters.get(param.name);
    if (converter === undefined) continue;
    const clean = /^(int|float|uuid)$/.test(converter) ? ALL_SINKS : new Set<SinkClass>();
    out.set(param.name, { kind: "path", clean });
  }
  return out;
}

/** Names a Flask view reads the authenticated subject through. */
function flaskSubjects(module: PyModule, fn: FunctionDef): string[] {
  const out = new Set<string>();
  const usesLogin = [...module.imports.values()].some((binding) => /flask_login|flask_jwt|flask_security|flask_httpauth/.test(binding.module));
  if (usesLogin || module.imports.has("current_user")) out.add("current_user");
  for (const expr of exprsIn(fn.body)) {
    walkExpr(expr, (inner) => {
      const name = dotted(inner) ?? "";
      if (/^g\.(user|current_user|account|member|principal|identity|viewer|actor|customer|shop|tenant|org)/.test(name)) out.add(name.split(".").slice(0, 2).join("."));
      if (/^(get_jwt_identity|current_identity|get_current_user|auth\.current_user)$/.test(name)) out.add(name);
      if (inner.k === "subscript" && dotted(inner.value) === "session") out.add("session");
      if (inner.k === "call" && dotted(inner.func) === "session.get") out.add("session");
    });
  }
  return [...out];
}

/** A `before_request` hook that refuses requests without an identity. */
function looksLikeAuthHook(fn: FunctionDef): boolean {
  const text = JSON.stringify(fn.body);
  const checksIdentity = /current_user|is_authenticated|"session"|g\.user|"user"|user_id|token|Authorization|api_key|login|verify|authenticate/i.test(text);
  const refuses = /"abort"|"raise"|redirect|Unauthorized|Forbidden|40[13]/.test(text);
  return checksIdentity && refuses;
}

/**
 * An identity check written into the handler itself: an explicit refusal when no
 * user is signed in, or a call that resolves the user from the request.
 */
function inBodyAuth(module: PyModule, fn: FunctionDef, framework: Framework, params: ReadonlyMap<string, ParamSource>): string | null {
  let evidence: string | null = null;
  const records = recordNames(fn, params);
  walkStmts(fn.body, (stmt) => {
    if (evidence) return;
    if (stmt.k === "if") {
      for (const branch of stmt.branches) {
        if (!branch.test) continue;
        // `user = session.get(User, user_id); if user is None: raise 404` tests a record
        // the handler loaded, not who is asking: its name says nothing about identity.
        const testText = JSON.stringify(branch.test, (key, value) =>
          value && typeof value === "object" && value.k === "name" && records.has(value.id) ? { k: "name", id: "_record" } : value
        );
        const refuses = branch.body.some((inner) => inner.k === "raise" || inner.k === "return" || (inner.k === "expr" && /abort/.test(JSON.stringify(inner))));
        if (refuses && /is_authenticated|current_user|g\.user|"user"|user_id|"session"|token|principal|identity/i.test(testText)) {
          evidence = `identity check at line ${stmt.span.line}`;
        }
      }
    }
  });
  if (evidence) return evidence;
  for (const expr of exprsIn(fn.body)) {
    let found: string | null = null;
    walkExpr(expr, (inner) => {
      if (found || inner.k !== "call") return;
      const name = dotted(inner.func);
      if (name && isAuthName(name) && !/^(request|self)\./.test(name)) found = `${name}() in the handler`;
    });
    if (found) return found;
  }
  void module;
  void framework;
  return null;
}

/** Verbs that load stored records, as opposed to resolving who is asking. */
const RECORD_LOAD = /^(get|get_or_404|get_one|first|first_or_404|one|one_or_none|scalar|scalars|scalar_one|scalar_one_or_none|execute|fetchone|fetchrow|fetch_one|find|find_one|filter|filter_by|load|lookup|by_id|get_by_id|find_by_id|retrieve)$/;

/**
 * Names in a handler that hold a record or an identifier the request chose: a
 * parameter bound from the path, query or body, and a local assigned from a data
 * lookup that is not itself an authentication helper. A test on one of them is not
 * an identity check, whatever the name (`user`, `token`, `user_id`).
 */
function recordNames(fn: FunctionDef, params: ReadonlyMap<string, ParamSource>): Set<string> {
  const out = new Set<string>();
  for (const [name, source] of params) {
    if (source.kind === "path" || source.kind === "query" || source.kind === "body" || source.kind === "form") out.add(name);
  }
  walkStmts(fn.body, (stmt) => {
    if (stmt.k !== "assign" || !stmt.value) return;
    let value: Expr = stmt.value;
    while (value.k === "await") value = value.value;
    if (value.k !== "call") return;
    const callee = dotted(value.func) ?? "";
    const tail = callee.split(".").pop() ?? (value.func.k === "attr" ? value.func.attr : "");
    const verb = value.func.k === "attr" ? value.func.attr : tail;
    if (!RECORD_LOAD.test(verb) || isAuthName(callee)) return;
    // `request.args.get(...)`, `g.get("user")` and Flask's `session.get("user_id")` read
    // the request or the signed-in session, not a stored record.
    if (/^(request|g)\./.test(callee) || (/(^|\.)session\.(get|pop)$/.test(callee) && constString(value.args[0]) !== null)) return;
    for (const target of stmt.targets) if (target.k === "name") out.add(target.id);
  });
  return out;
}

/**
 * A mount prefix built from literals and the router's own prefix:
 * `"/api" + (bp.url_prefix or "")`. Null when any part is not knowable.
 */
function staticPrefix(expr: Expr, ownPrefix: string): string | null {
  switch (expr.k) {
    case "str":
      return expr.value;
    case "binop": {
      if (expr.op !== "+") return null;
      const left = staticPrefix(expr.left, ownPrefix);
      const right = staticPrefix(expr.right, ownPrefix);
      return left === null || right === null ? null : left + right;
    }
    case "boolop":
      return expr.op === "or" ? staticPrefix(expr.left, ownPrefix) ?? staticPrefix(expr.right, ownPrefix) : null;
    case "attr":
      return /^(url_prefix|prefix)$/.test(expr.attr) ? ownPrefix : null;
    case "fstr": {
      const parts = expr.parts.map((part) => (typeof part === "string" ? part : staticPrefix(part, ownPrefix)));
      return parts.some((part) => part === null) ? null : parts.join("");
    }
    default:
      return null;
  }
}

/** `name` or `name.attr` with the loop variable replaced by one of its values. */
function substituteName(expr: Expr, name: string, value: Expr): Expr {
  if (expr.k === "name" && expr.id === name) return value;
  if (expr.k === "attr") {
    const inner = substituteName(expr.value, name, value);
    return inner === expr.value ? expr : { ...expr, value: inner };
  }
  return expr;
}

function methodsOf(expr: Expr | undefined): string[] | null {
  if (!expr || (expr.k !== "list" && expr.k !== "tuple" && expr.k !== "set")) return null;
  const methods = expr.elts.map((element) => constString(element)?.toUpperCase()).filter((m): m is string => Boolean(m));
  return methods.length > 0 ? methods : null;
}

export function pathParameterNames(path: string, framework: Framework): string[] {
  if (framework === "fastapi") return [...path.matchAll(/\{(\w+)(?::[^}]*)?\}/g)].map((match) => match[1]!);
  return [...path.matchAll(/<(?:\w+(?:\([^)]*\))?:)?(\w+)>/g)].map((match) => match[1]!);
}

/** `/{id}` and `/<int:id>` both become `/:id`. */
export function normalisePath(path: string, framework: Framework): string {
  let out = path;
  if (framework === "fastapi") out = out.replace(/\{(\w+)(?::[^}]*)?\}/g, ":$1");
  else out = out.replace(/<(?:\w+(?:\([^)]*\))?:)?(\w+)>/g, ":$1");
  return out;
}

export function joinPaths(prefix: string, path: string): string {
  const joined = `${prefix.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
  const collapsed = joined.replace(/\/{2,}/g, "/");
  if (collapsed.length > 1 && collapsed.endsWith("/") && !path.endsWith("/")) return collapsed.slice(0, -1);
  return collapsed.startsWith("/") ? collapsed : `/${collapsed}`;
}
