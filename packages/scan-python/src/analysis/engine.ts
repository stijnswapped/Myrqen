import type { ClassDef, Expr, FunctionDef, Span, Stmt } from "../syntax/ast.js";
import { calleeTail, constString, dotted, stmtExprs, walkExpr, walkStmts } from "../syntax/ast.js";
import { methodOf, type Project, type PyModule } from "../project/modules.js";
import type { FrameworkModel, RouteInfo } from "../project/frameworks.js";
import type { TypeReader } from "../project/types.js";
import { checkSinks, SQL_SHAPE, type CallSite, type SinkHit } from "./sinks.js";
import { factsOf, applyFacts, keysOf, type Facts } from "./guards.js";
import { callerChosen, fromParameter, observeLookup, type Lookup } from "./lookups.js";
import { isTerminatingCall, mergeInto, substitute, withPrefixCleaning, type Env } from "./flow.js";
import {
  REQUEST_SOURCE_ATTRS,
  REQUEST_SOURCE_METHODS,
  PREDICATE_METHODS,
  MUTATORS,
  CLEAN_ALL_FUNCTIONS,
  SANITIZERS,
  PROPAGATORS,
  PATH_CONSTRUCTORS,
  RESOLVERS,
  URL_PARSERS,
  ADDRESS_RESOLVERS,
  ADDRESS_PARSERS,
  HTTP_CLIENTS,
  JINJA_ENVIRONMENTS,
  JINJA_SANDBOXES,
  SIGNERS
} from "./library.js";
import {
  ALL_SINKS,
  CLEAN,
  concatValues,
  constant,
  joinTaint,
  joinValues,
  sourceValue,
  withClean,
  withDeps,
  withTags,
  type Origin,
  type SinkClass,
  type SourceKind,
  type Taint,
  type Tag,
  type Value
} from "./values.js";

/**
 * The taint interpreter.
 *
 * Each function is evaluated once, abstractly, statement by statement: an
 * assignment binds a value, a branch is evaluated on a copy of the environment
 * and the copies are merged, a loop body runs twice so a value carried round
 * the loop reaches its own sink. Guards are applied where Python applies them —
 * a refusal (`raise`, `abort`, `return`) inside `if name not in ALLOWED` cleans
 * `name` for everything after the `if`.
 *
 * Across functions the engine uses summaries. A function is analysed with each
 * parameter standing for "whatever the caller passed", and the summary records
 * which parameters reach its return value and which reach a sink. At a call site
 * the caller's actual values are substituted in. That is what lets a route
 * handler that passes a query parameter to `reports.build(segment)` in another
 * module be reported at the line in `reports.py` that formats `segment` into SQL,
 * attributed to the route that supplied it.
 */

export type { Env } from "./flow.js";

export interface Summary {
  returns: Value;
  hits: SinkHit[];
  /**
   * What a normal return proves about each parameter, by index: a validator that
   * raises unless `url`'s host is allowed guarantees `url` is clean for SSRF to a
   * caller that goes on using it after the call.
   */
  guarantees?: ReadonlyMap<number, ReadonlySet<SinkClass>>;
  /** Records the function fetches by an identifier its caller supplies. */
  lookups?: Lookup[];
  /** Record fields the function writes from its parameters. */
  stores?: StoredWrite[];
}

/** The project function a call reaches, as the engine resolved it. */
export interface CallTarget {
  module: PyModule;
  fn: FunctionDef;
  cls: ClassDef | null;
  /** Called on an instance, so the first parameter is `self`. */
  bound: boolean;
}

export interface Frame {
  module: PyModule;
  fn: FunctionDef | null;
  cls: ClassDef | null;
  route: RouteInfo | null;
  hits: SinkHit[];
  returns: Value | null;
  /** Names bound to a request object (`request: Request`, Flask's `request`). */
  requestNames: Set<string>;
  /** Records fetched by a caller-chosen identifier (route frames only). */
  lookups: Lookup[];
  /** Names bound to Flask's `session` proxy. */
  sessionNames: Set<string>;
  /** The environment at each normal exit (summary frames only). */
  exits: Env[] | null;
  /** Record fields a helper writes from its parameters (summary frames only). */
  stores: StoredWrite[];
}

/** A value written to a stored record's field: `note.body_html = …`, `Note(body_html=…)`. */
export interface StoredWrite {
  field: string;
  taint: Taint;
  line: number;
  module: PyModule;
}

/** What a route stored in the session under one key. */
export interface SessionWrite {
  taint: Taint;
  line: number;
  module: PyModule;
}

export class Engine {
  private readonly summaries = new Map<FunctionDef, Summary>();
  private readonly inProgress = new Set<FunctionDef>();
  private readonly templateCache = new Map<string, string | null>();
  /** Attacker data stored in the server-side session, by key, from route handlers. */
  readonly sessionWrites = new Map<string, SessionWrite[]>();
  /** Every call the engine resolved to a project function, by call expression. */
  readonly callTargets = new Map<Expr, CallTarget>();
  /** Attacker data route handlers wrote to stored record fields, by field name. */
  readonly storedWrites = new Map<string, StoredWrite[]>();
  /** Field names some function in the project assigns or constructs a record with. */
  private readonly storedFields: ReadonlySet<string>;
  private readonly persistedCache = new Map<ClassDef, boolean>();
  private readonly persistsCache = new Map<FunctionDef, boolean>();
  /** Steps taken, so a pathological file cannot run unbounded. */
  private budget = 2_000_000;

  constructor(
    readonly project: Project,
    readonly frameworks: FrameworkModel,
    readonly types: TypeReader,
    private readonly readTemplate: (name: string) => string | null
  ) {
    this.storedFields = this.storedFieldNames();
  }

  /* ------------------------------------------------------------- drivers */

  /** Analyse a route handler with its parameters seeded from the framework model. */
  analyzeRoute(route: RouteInfo, cls: ClassDef | null): Frame {
    const frame = this.newFrame(route.module, route.fn, cls, route);
    const env: Env = new Map();
    route.fn.params.forEach((param, index) => {
      const source = route.params.get(param.name);
      if (!source) {
        if (index === 0 && cls && (param.name === "self" || param.name === "cls")) env.set(param.name, this.selfValue(route.module, cls));
        else env.set(param.name, withDeps(CLEAN, [param.name]));
        return;
      }
      if (source.kind === "dependency" || source.kind === "injected") {
        const instance = this.annotatedInstance(route.module, param.annotation);
        env.set(param.name, { ...withDeps(CLEAN, [param.name]), ...(instance ? { instance } : {}) });
        return;
      }
      if (source.kind === "request") {
        frame.requestNames.add(param.name);
        env.set(param.name, withDeps(withTags(CLEAN, ["request"]), [param.name]));
        return;
      }
      const label = `${source.kind === "body" ? "request body" : `${source.kind} parameter`} ${param.name}`;
      const origin: Origin = { kind: "source", label, source: source.kind, line: param.span.line };
      const value = sourceValue(origin, source.clean, {
        deps: new Set([param.name]),
        ...(source.model ? { model: source.model } : {}),
        ...(source.kind === "file" ? { tags: new Set<Tag>(["upload"]) } : {})
      });
      env.set(param.name, value);
    });
    this.execBlock(route.fn.body, env, frame);
    return frame;
  }

  /** The summary of a function: parameters stand for whatever a caller passes. */
  summary(module: PyModule, fn: FunctionDef, cls: ClassDef | null): Summary {
    const cached = this.summaries.get(fn);
    if (cached) return cached;
    if (this.inProgress.has(fn)) return { returns: CLEAN, hits: [] };
    this.inProgress.add(fn);
    const frame = this.newFrame(module, fn, cls, null);
    const env: Env = new Map();
    fn.params.forEach((param, index) => {
      if (index === 0 && cls && (param.name === "self" || param.name === "cls")) {
        env.set(param.name, this.selfValue(module, cls));
        return;
      }
      env.set(param.name, sourceValue({ kind: "param", index, name: param.name }, new Set(), { deps: new Set([param.name]) }));
    });
    frame.exits = [];
    if (!this.execBlock(fn.body, env, frame)) frame.exits.push(new Map(env));
    const guarantees = guaranteesOf(fn, frame.exits);
    const summary: Summary = {
      returns: frame.returns ?? CLEAN,
      hits: frame.hits,
      ...(guarantees.size > 0 ? { guarantees } : {}),
      ...(frame.lookups.length > 0 ? { lookups: frame.lookups } : {}),
      ...(frame.stores.length > 0 ? { stores: frame.stores } : {})
    };
    this.inProgress.delete(fn);
    this.summaries.set(fn, summary);
    return summary;
  }

  private newFrame(module: PyModule, fn: FunctionDef | null, cls: ClassDef | null, route: RouteInfo | null): Frame {
    const requestNames = new Set<string>();
    const sessionNames = new Set<string>();
    for (const [local, binding] of module.imports) {
      if (binding.member === "request" && /^(flask|quart|werkzeug)/.test(binding.module)) requestNames.add(local);
      if (binding.member === "session" && /^(flask|quart)$/.test(binding.module)) sessionNames.add(local);
    }
    return { module, fn, cls, route, hits: [], returns: null, requestNames, lookups: [], sessionNames, exits: null, stores: [] };
  }

  private selfValue(module: PyModule, cls: ClassDef): Value {
    return { ...withDeps(CLEAN, ["self"]), instance: { module: module.name, cls: cls.name } };
  }

  private annotatedInstance(module: PyModule, annotation: Expr | null): Value["instance"] {
    if (!annotation) return undefined;
    const target = annotation.k === "subscript" && annotation.index?.k === "tuple" ? annotation.index.elts[0] : annotation;
    if (!target) return undefined;
    const symbol = this.project.resolveExpr(module, target);
    return symbol?.kind === "class" ? { module: symbol.module.name, cls: symbol.cls.name } : undefined;
  }

  /* ----------------------------------------------------------- statements */

  /** Execute a block. Returns true when control cannot fall off its end. */
  execBlock(body: Stmt[], env: Env, frame: Frame): boolean {
    for (const stmt of body) {
      if (this.execStmt(stmt, env, frame)) return true;
    }
    return false;
  }

  private execStmt(stmt: Stmt, env: Env, frame: Frame): boolean {
    if ((this.budget -= 1) <= 0) return false;
    switch (stmt.k) {
      case "assign": {
        if (!stmt.value) return false;
        const value = this.eval(stmt.value, env, frame);
        for (const target of stmt.targets) this.bind(target, value, env, frame);
        return false;
      }
      case "augassign": {
        const value = this.eval(stmt.value, env, frame);
        const key = dotted(stmt.target);
        if (key) env.set(key, concatValues([this.eval(stmt.target, env, frame), value]));
        return false;
      }
      case "expr": {
        this.eval(stmt.value, env, frame);
        return isTerminatingCall(stmt.value);
      }
      case "return": {
        if (stmt.value) {
          const value = this.eval(stmt.value, env, frame);
          frame.returns = frame.returns ? joinValues(frame.returns, value) : value;
          this.checkReturnedMarkup(stmt.value, value, frame);
        }
        frame.exits?.push(new Map(env));
        return true;
      }
      case "raise":
        if (stmt.exc) this.eval(stmt.exc, env, frame);
        return true;
      case "simple":
        return stmt.keyword === "break" || stmt.keyword === "continue";
      case "if":
        return this.execIf(stmt, env, frame);
      case "for": {
        // Iterating binds each item, not each position: `for a, b in (x, y)` does not
        // bind `a` to `x`.
        const iterable = itemsOf(this.eval(stmt.iter, env, frame));
        const before = new Map(env);
        for (let pass = 0; pass < 2; pass += 1) {
          this.bind(stmt.target, iterable, env, frame);
          this.execBlock(stmt.body, env, frame);
        }
        // Resolution either returns addresses or raises, so a loop over what
        // `getaddrinfo` returned has run at least once.
        if (!iterable.tags.has("resolved-address")) this.merge(frame, env, [before, new Map(env)]);
        this.execBlock(stmt.orelse, env, frame);
        return false;
      }
      case "while": {
        this.eval(stmt.test, env, frame);
        const before = new Map(env);
        for (let pass = 0; pass < 2; pass += 1) this.execBlock(stmt.body, env, frame);
        this.merge(frame, env, [before, new Map(env)]);
        this.execBlock(stmt.orelse, env, frame);
        return false;
      }
      case "with": {
        for (const item of stmt.items) {
          const value = this.eval(item.expr, env, frame);
          if (item.as) this.bind(item.as, value, env, frame);
        }
        return this.execBlock(stmt.body, env, frame);
      }
      case "try":
        return this.execTry(stmt, env, frame);
      case "match": {
        this.eval(stmt.subject, env, frame);
        const outcomes: Env[] = [];
        for (const body of stmt.cases) {
          const branch = new Map(env);
          if (!this.execBlock(body, branch, frame)) outcomes.push(branch);
        }
        outcomes.push(new Map(env));
        this.merge(frame, env, outcomes);
        return false;
      }
      case "assert": {
        this.eval(stmt.test, env, frame);
        applyFacts(env, factsOf(stmt.test, env, this, frame).whenTrue, this, frame);
        return false;
      }
      case "delete":
        return false;
      default:
        // Nested definitions are their own scope; they are analysed when called.
        return false;
    }
  }

  /** Merge alternative environments; an attribute one path did not assign keeps its earlier value. */
  private merge(frame: Frame, target: Env, alternatives: Env[]): void {
    mergeInto(target, alternatives, (key, env) => {
      const parts = key.split(".");
      let expr: Expr = { k: "name", id: parts[0]!, span: NO_SPAN };
      for (const attr of parts.slice(1)) expr = { k: "attr", value: expr, attr, span: NO_SPAN };
      return this.eval(expr, env, frame);
    });
  }

  private execIf(stmt: Extract<Stmt, { k: "if" }>, env: Env, frame: Frame): boolean {
    const outcomes: Env[] = [];
    const negations: Facts[] = [];
    let hasElse = false;
    for (const branch of stmt.branches) {
      const branchEnv = new Map(env);
      for (const negation of negations) applyFacts(branchEnv, negation, this, frame);
      if (branch.test) {
        this.eval(branch.test, branchEnv, frame);
        const facts = factsOf(branch.test, branchEnv, this, frame);
        applyFacts(branchEnv, facts.whenTrue, this, frame);
        negations.push(facts.whenFalse);
      } else {
        hasElse = true;
      }
      if (!this.execBlock(branch.body, branchEnv, frame)) outcomes.push(branchEnv);
    }
    if (!hasElse) {
      const fallthrough = new Map(env);
      for (const negation of negations) applyFacts(fallthrough, negation, this, frame);
      outcomes.push(fallthrough);
    }
    if (outcomes.length === 0) return true;
    this.merge(frame, env, outcomes);
    return false;
  }

  private execTry(stmt: Extract<Stmt, { k: "try" }>, env: Env, frame: Frame): boolean {
    const before = new Map(env);
    const bodyExits = this.execBlock(stmt.body, env, frame);
    const outcomes: Env[] = [];
    if (!bodyExits) {
      const afterBody = new Map(env);
      this.execBlock(stmt.orelse, afterBody, frame);
      outcomes.push(afterBody);
    }
    let handlersAllExit = stmt.handlers.length > 0;
    for (const handler of stmt.handlers) {
      const handlerEnv = new Map(before);
      this.merge(frame, handlerEnv, [before, env]);
      if (handler.name) handlerEnv.set(handler.name, CLEAN);
      if (!this.execBlock(handler.body, handlerEnv, frame)) {
        outcomes.push(handlerEnv);
        handlersAllExit = false;
      }
    }
    // `try: target.relative_to(base) except ValueError: abort(400)` is a
    // containment check written as an exception.
    if (handlersAllExit && outcomes.length > 0) {
      for (const outcome of outcomes) applyFacts(outcome, containmentByException(stmt.body, outcome, this, frame), this, frame);
    }
    if (outcomes.length === 0) {
      this.execBlock(stmt.finalbody, env, frame);
      return true;
    }
    this.merge(frame, env, outcomes);
    return this.execBlock(stmt.finalbody, env, frame);
  }

  private bind(target: Expr, value: Value, env: Env, frame: Frame): void {
    switch (target.k) {
      case "name":
        env.set(target.id, withDeps(value, [target.id]));
        return;
      case "tuple":
      case "list": {
        const positional = value.elements && value.elements.length === target.elts.length && target.elts.every((element) => element.k !== "starred");
        target.elts.forEach((element, index) => {
          this.bind(element.k === "starred" ? element.value : element, positional ? value.elements![index]! : value, env, frame);
        });
        return;
      }
      case "attr": {
        const key = dotted(target);
        if (key) env.set(key, value);
        if (this.isRecordTarget(target.value, env, frame)) this.recordStore(target.attr, value, target.span.line, frame);
        return;
      }
      case "subscript": {
        // `headers["Location"] = next_url` is a redirect; `params[key] = value`
        // adds the value to the container.
        const containerKey = dotted(target.value);
        if (this.eval(target.value, env, frame).tags.has("session-store")) {
          this.recordSessionWrite(constString(target.index), value, target.span.line, frame);
          return;
        }
        if (containerKey && /(^|\.)headers$/.test(containerKey) && /^location$/i.test(constString(target.index) ?? "")) {
          this.reportIf(value, "redirect", target.span, frame, "Location header");
        }
        if (containerKey) {
          const existing = env.get(containerKey) ?? this.eval(target.value, env, frame);
          env.set(containerKey, concatValues([existing, value], existing.tags));
        }
        return;
      }
      case "starred":
        this.bind(target.value, value, env, frame);
        return;
      default:
        return;
    }
  }

  /**
   * Attacker data a route handler stores in the session. Only a route's own sources
   * count: a helper's parameter is decided by its caller, which is not followed here.
   */
  private recordSessionWrite(key: string | null, value: Value, line: number, frame: Frame): void {
    if (key === null || !frame.route || !value.taint) return;
    const origins = value.taint.origins.filter((origin) => origin.kind === "source" && origin.source !== "session");
    if (origins.length === 0) return;
    const list = this.sessionWrites.get(key) ?? [];
    list.push({ taint: { origins, clean: value.taint.clean }, line, module: frame.module });
    this.sessionWrites.set(key, list);
  }

  /** A Flask view returns a string, and Flask serves a string as `text/html`; so does a FastAPI route declared with `response_class=HTMLResponse`. */
  private checkReturnedMarkup(expr: Expr, value: Value, frame: Frame): void {
    if (!frame.route) return;
    // FastAPI serves a returned string as HTML only when the route says so.
    if (frame.route.framework === "fastapi" && !declaresHtmlResponse(frame.route.fn)) return;
    if (!value.taint || !/<[a-z!/][^>]*>|<[a-z]/i.test(value.text)) return;
    if (expr.k !== "fstr" && expr.k !== "binop" && expr.k !== "name" && !(expr.k === "call" && calleeTail(expr) === "format")) return;
    this.reportIf(value, "xss", expr.span, frame, "the view's HTML response");
  }

  reportIf(value: Value, sink: SinkClass, span: Span, frame: Frame, sinkName: string, detail?: string): void {
    if (!value.taint || value.taint.clean.has(sink)) return;
    frame.hits.push({ sink, module: frame.module, span, taint: value.taint, sinkName, ...(detail ? { detail } : {}) });
  }

  /* ---------------------------------------------------------- expressions */

  eval(expr: Expr, env: Env, frame: Frame): Value {
    if ((this.budget -= 1) <= 0) return CLEAN;
    switch (expr.k) {
      case "name":
        return this.evalName(expr.id, env, frame);
      case "attr":
        return this.evalAttr(expr, env, frame);
      case "call":
        return this.evalCall(expr, env, frame);
      case "str":
        return constant(expr.value);
      case "num":
        return constant(String(expr.value));
      case "const":
        return CLEAN;
      case "fstr":
        return withPrefixCleaning(
          concatValues(expr.parts.map((part) => (typeof part === "string" ? constant(part) : this.eval(part, env, frame))))
        );
      case "binop":
        return this.evalBinop(expr, env, frame);
      case "boolop": {
        const left = this.eval(expr.left, env, frame);
        const right = this.eval(expr.right, env, frame);
        // `parts.hostname or ""`: the fallback is a literal, so the value is either the
        // left operand or nothing at all, and keeps what is known about the left.
        if (isLiteral(expr.right) && !right.taint) return { ...joinValues(left, right), tags: left.tags };
        if (isLiteral(expr.left) && !left.taint) return { ...joinValues(left, right), tags: right.tags };
        return joinValues(left, right);
      }
      case "compare":
      case "not":
      case "unary":
        this.eval(expr.k === "compare" ? expr.left : expr.operand, env, frame);
        if (expr.k === "compare") this.eval(expr.right, env, frame);
        return CLEAN;
      case "subscript":
        return this.evalSubscript(expr, env, frame);
      case "list":
      case "tuple":
      case "set": {
        const values = expr.elts.map((element) => this.eval(element, env, frame));
        const allConstant = expr.elts.every((element) => element.k === "str" || element.k === "num" || element.k === "const");
        const combined = concatValues(values, allConstant ? new Set<Tag>(["const-collection"]) : new Set<Tag>());
        if (expr.k !== "set" && values.length > 1 && expr.elts.every((element) => element.k !== "starred")) return { ...combined, elements: values };
        return combined;
      }
      case "dict": {
        const entryValues = new Map<string, Value>();
        const values = expr.entries.flatMap((entry) => {
          const value = this.eval(entry.value, env, frame);
          const key = entry.key ? constString(entry.key) : null;
          if (key !== null) entryValues.set(key, value);
          return [...(entry.key ? [this.eval(entry.key, env, frame)] : []), value];
        });
        const allConstant = expr.entries.every((entry) => entry.value.k === "str" || entry.value.k === "num" || entry.value.k === "const");
        const combined = concatValues(values, allConstant ? new Set<Tag>(["const-collection"]) : new Set<Tag>());
        return entryValues.size > 0 ? { ...combined, entryValues } : combined;
      }
      case "ifexp": {
        // `sort if sort in ALLOWED else "id"`: each arm is read under what the test proves there.
        this.eval(expr.test, env, frame);
        const facts = factsOf(expr.test, env, this, frame);
        const whenTrue = new Map(env);
        const whenFalse = new Map(env);
        applyFacts(whenTrue, facts.whenTrue, this, frame);
        applyFacts(whenFalse, facts.whenFalse, this, frame);
        return joinValues(this.eval(expr.body, whenTrue, frame), this.eval(expr.orelse, whenFalse, frame));
      }
      case "comp": {
        const inner = new Map(env);
        expr.targets.forEach((target, index) => {
          const iterable = expr.iters[index];
          if (iterable) this.bind(target, itemsOf(this.eval(iterable, inner, frame)), inner, frame);
        });
        for (const condition of expr.conds) {
          this.eval(condition, inner, frame);
          applyFacts(inner, factsOf(condition, inner, this, frame).whenTrue, this, frame);
        }
        const values = [this.eval(expr.elt, inner, frame), ...(expr.key ? [this.eval(expr.key, inner, frame)] : [])];
        return concatValues(values);
      }
      case "await":
        return this.eval(expr.value, env, frame);
      case "starred":
        return this.eval(expr.value, env, frame);
      case "named": {
        const value = this.eval(expr.value, env, frame);
        env.set(expr.target, withDeps(value, [expr.target]));
        return value;
      }
      case "yield":
        return expr.value ? this.eval(expr.value, env, frame) : CLEAN;
      case "lambda":
        return CLEAN;
      case "other":
        return concatValues(expr.children.map((child) => this.eval(child, env, frame)));
      default:
        return CLEAN;
    }
  }

  private evalName(id: string, env: Env, frame: Frame): Value {
    const bound = env.get(id);
    if (bound) return withDeps(bound, [id]);
    // Module-level names are not tracked as dependencies: a guard on one local
    // must not reach every value that also happens to use a shared constant.
    if (frame.requestNames.has(id)) return withTags(CLEAN, ["request"]);
    if (frame.sessionNames.has(id)) return withTags(CLEAN, ["session-store"]);
    const value = this.project.constantValue(frame.module, id);
    if (value) return constantShape(value.expr, this, value.module);
    return CLEAN;
  }

  private evalAttr(expr: Extract<Expr, { k: "attr" }>, env: Env, frame: Frame): Value {
    const key = dotted(expr);
    if (key && env.has(key)) return env.get(key)!;
    const qualified = this.project.qualified(frame.module, expr);
    if (qualified && /^(flask|quart)\.request$/.test(qualified)) return withTags(CLEAN, ["request"]);
    if (qualified) {
      const constantValue = this.qualifiedConstant(expr, frame);
      if (constantValue) return constantValue;
    }

    const base = this.eval(expr.value, env, frame);
    if (base.tags.has("request") && expr.attr === "session") return withTags(CLEAN, ["session-store"]);
    if (base.tags.has("request")) {
      const kind = REQUEST_SOURCE_ATTRS[expr.attr];
      if (!kind) return CLEAN;
      return sourceValue({ kind: "source", label: `request.${expr.attr}`, source: kind, line: expr.span.line }, new Set(), {
        tags: expr.attr === "files" ? new Set<Tag>(["upload"]) : new Set<Tag>()
      });
    }
    const field = base.fields?.get(expr.attr);
    if (field) return field;
    if (!base.taint) {
      // `note.body_html`, `current_user.signature`: a field of a stored record holds
      // whatever was last written to it, which may be another request's data.
      if (this.storedFields.has(expr.attr) && this.mayBeRecord(expr.value, base, frame)) return { ...storedRead(expr.attr, expr.span.line), deps: base.deps };
      return { ...CLEAN, deps: base.deps };
    }
    if (base.tags.has("path-object") && /^(name|stem|suffix|suffixes)$/.test(expr.attr)) return withClean(base, ["path"]);
    if (base.tags.has("upload") && expr.attr === "content_type") return base;
    if (base.model) {
      const field = base.model.fields.get(expr.attr);
      if (field) {
        const narrowed = withClean({ ...base, model: undefined as never }, field.clean);
        const out: Value = { taint: narrowed.taint, deps: base.deps, tags: new Set(), text: "", prefix: "" };
        if (field.model) out.model = field.model;
        return out;
      }
    }
    // A component of a parsed URL is not the URL: `parts.scheme` checked says nothing
    // about where `parts` points. Only its authority speaks for the destination.
    const component = base.tags.has("parsed-url") && URL_COMPONENTS.test(expr.attr);
    const keepTags: Tag[] = [...base.tags].filter((tag) => (tag === "parsed-url" && !component) || tag === "upload" || tag === "resolved-path" || tag === "resolved-address");
    if (component && URL_AUTHORITY.test(expr.attr)) keepTags.push("url-host");
    return { taint: base.taint, deps: base.deps, tags: new Set(keepTags), text: base.text, prefix: "" };
  }

  /** `config.ALLOWED_HOSTS` read from a project module. */
  private qualifiedConstant(expr: Extract<Expr, { k: "attr" }>, frame: Frame): Value | null {
    const owner = this.project.resolveExpr(frame.module, expr.value);
    if (owner?.kind !== "module") return null;
    const value = this.project.constantValue(owner.module, expr.attr);
    return value ? constantShape(value.expr, this, value.module) : null;
  }

  private evalBinop(expr: Extract<Expr, { k: "binop" }>, env: Env, frame: Frame): Value {
    const left = this.eval(expr.left, env, frame);
    const right = this.eval(expr.right, env, frame);
    if (expr.op === "+" || expr.op === "%" || expr.op === "|") {
      const joined = concatValues([left, right]);
      return joined.taint ? withPrefixCleaning(joined) : joined;
    }
    // `/` on a string is a TypeError, so a tainted operand of `/` is a pathlib join.
    if (expr.op === "/" && (left.tags.has("path-object") || right.tags.has("path-object") || left.taint || right.taint)) {
      return withTags(concatValues([left, right]), ["path-object"]);
    }
    if (expr.op === "*") return concatValues([left, right]);
    return CLEAN;
  }

  private evalSubscript(expr: Extract<Expr, { k: "subscript" }>, env: Env, frame: Frame): Value {
    const container = this.eval(expr.value, env, frame);
    const index = expr.index ? this.eval(expr.index, env, frame) : CLEAN;
    if (container.tags.has("session-store")) return sessionRead(constString(expr.index), expr.span.line);
    // A value looked up in a fixed table is one of the table's values, whoever
    // chose the key.
    if (container.tags.has("const-collection")) return { ...CLEAN, deps: container.deps };
    if (container.elements && expr.index?.k === "num" && Number.isInteger(expr.index.value)) {
      const position = expr.index.value < 0 ? container.elements.length + expr.index.value : expr.index.value;
      const element = container.elements[position];
      if (element) return element;
    }
    if (container.taint) {
      const element: Value = { taint: container.taint, deps: container.deps, tags: new Set([...container.tags].filter((t) => t === "upload" || t === "resolved-address")), text: container.text, prefix: "" };
      return keyedSource(element, expr.index);
    }
    void index;
    return { ...CLEAN, deps: container.deps };
  }

  private evalCall(call: Extract<Expr, { k: "call" }>, env: Env, frame: Frame): Value {
    const func = call.func;
    const tail = calleeTail(call);
    const receiverExpr = func.k === "attr" ? func.value : null;
    const receiver = receiverExpr ? this.eval(receiverExpr, env, frame) : null;
    const args = call.args.map((arg) => this.eval(arg, env, frame));
    const kwargs = new Map<string, Value>();
    for (const keyword of call.kwargs) {
      const value = this.eval(keyword.value, env, frame);
      if (keyword.name) kwargs.set(keyword.name, value);
      else args.push(value);
    }

    const symbol = this.project.resolveExpr(frame.module, func);
    const qualified = symbol?.kind === "external" ? symbol.qualified : null;
    const callee = this.calleeOf(func, receiver, frame, symbol);

    const site: CallSite = {
      call,
      module: frame.module,
      qualified,
      tail,
      receiver,
      args,
      kwargs,
      projectCallee: Boolean(callee) || symbol?.kind === "class",
      templateText: (name) => this.template(name),
      storedField: (attr, line) => (this.storedFields.has(attr) ? storedRead(attr, line) : null)
    };
    checkSinks(site, (hit) => frame.hits.push({ ...hit, module: hit.module ?? frame.module, span: hit.span ?? call.span }));
    // In a helper, an identifier is the caller's to choose when it is a parameter;
    // whether the caller let the request choose it is decided where it is called.
    const chosen = frame.route ? callerChosen : (value: Value | undefined) => callerChosen(value) || fromParameter(value);
    const lookup = observeLookup(call, receiver, args, kwargs, (expr) => this.eval(expr, env, frame), chosen);
    if (lookup) frame.lookups.push({ ...lookup, module: frame.module, path: [] });

    // Mutation of a local container: `parts.append(value)`.
    if (tail && MUTATORS.has(tail) && receiverExpr) {
      const key = dotted(receiverExpr);
      if (key && args.length > 0) {
        const current = env.get(key) ?? receiver ?? CLEAN;
        env.set(key, concatValues([current, ...args], current.tags.has("const-collection") && args.every((a) => !a.taint) ? current.tags : new Set()));
      }
      return CLEAN;
    }

    // A value read back from the session: `session.get("next")`, `request.session.pop("return_to")`.
    if (receiver?.tags.has("session-store") && tail && /^(get|pop|setdefault)$/.test(tail)) {
      return sessionRead(constString(call.args[0]), call.span.line);
    }

    // The request object's own readers.
    if (receiver?.tags.has("request") && tail && REQUEST_SOURCE_METHODS[tail]) {
      return sourceValue({ kind: "source", label: `request.${tail}()`, source: REQUEST_SOURCE_METHODS[tail]!, line: call.span.line });
    }
    if (receiver?.tags.has("upload") && receiver.taint && (tail === "read" || tail === "getvalue" || tail === "readlines")) {
      return { ...receiver, tags: new Set() };
    }

    // A project function handed to a scheduler with its arguments runs with them later:
    // `tasks.add_task(render, source, req)`, `executor.submit(fn, x)`, `job.delay(x)`.
    if (!callee) {
      const deferred = this.deferredCall(call, qualified, env, frame);
      if (deferred) this.applySummary(deferred.target, deferred.args, deferred.kwargs, deferred.call, frame, env);
    }

    // A function or method defined in this project.
    if (callee) {
      this.callTargets.set(call, callee);
      return this.applySummary(callee, args, kwargs, call, frame, env);
    }

    // A class defined in this project.
    if (symbol?.kind === "class") {
      if (this.isPersisted(symbol.module, symbol.cls)) {
        for (const [field, value] of kwargs) this.recordStore(field, value, call.span.line, frame);
      }
      const model = this.types.model(symbol.module, symbol.cls);
      const combined = concatValues([...args, ...kwargs.values()]);
      const out: Value = { ...combined, tags: new Set(), instance: { module: symbol.module.name, cls: symbol.cls.name } };
      if (model) out.model = model;
      if (kwargs.size > 0 && args.length === 0) out.fields = new Map(kwargs);
      return out;
    }

    const name = qualified ?? (func.k === "name" && !symbol ? func.id : null);
    const all = [...args, ...kwargs.values()];
    if (name) {
      if (CLEAN_ALL_FUNCTIONS.has(name)) return CLEAN;
      const sanitizes = SANITIZERS.get(name);
      if (sanitizes) return withClean(concatValues(all), sanitizes);
      if (RESOLVERS.has(name)) return withTags(concatValues(all), ["resolved-path"]);
      if (PATH_CONSTRUCTORS.test(name)) return withTags(concatValues(all), ["path-object"]);
      if (URL_PARSERS.has(name)) return withTags(concatValues(all), ["parsed-url"]);
      if (ADDRESS_RESOLVERS.has(name)) return withTags(concatValues(all), ["resolved-address"]);
      if (ADDRESS_PARSERS.has(name)) {
        const joined = concatValues(all);
        return all.some((value) => value.tags.has("resolved-address")) ? withTags(joined, ["resolved-address"]) : joined;
      }
      if (HTTP_CLIENTS.test(name)) return withTags(CLEAN, ["http-client"]);
      if (JINJA_ENVIRONMENTS.test(name)) return withTags(CLEAN, ["jinja-env"]);
      if (JINJA_SANDBOXES.test(name)) return withTags(CLEAN, ["jinja-sandbox"]);
      if (JINJA_TEMPLATES.test(name)) return withTags(CLEAN, ["jinja-templates"]);
      if (SIGNERS.test(name)) return withTags(CLEAN, ["signer"]);
      if (name === "re.compile") return withTags(constant(constString(call.args[0]) ?? ""), ["regex"]);
      if (/^(sqlalchemy(\.sql)?(\.expression)?|sqlmodel)\.text$/.test(name) || /^psycopg2?\.sql\.SQL$/.test(name)) {
        return withTags(concatValues(all), ["text-clause"]);
      }
      if (PROPAGATORS.has(name)) {
        const joined = concatValues(all);
        return withPrefixCleaning({ ...joined, tags: new Set([...(all[0]?.tags ?? [])].filter((t) => t === "resolved-path" || t === "path-object")) });
      }
      if (name === "escape" && [...frame.module.imports.values()].some((b) => /markupsafe|flask|jinja2/.test(b.module))) {
        return withClean(concatValues(all), ["xss"]);
      }
    }

    // Methods.
    if (receiver && tail) {
      if (receiver.tags.has("signer") && /^(loads|unsign|load)$/.test(tail)) return withClean(concatValues(all), ALL_SINKS);
      // `MENTION.sub(link, body)` is `body` edited.
      if (receiver.tags.has("regex") && /^(sub|subn|split|findall)$/.test(tail)) return concatValues(all);
      const compiled = compiledTemplate(call, receiver, (name) => this.template(name), frame.module);
      if (compiled) return compiled;
      if (tail === "format" && (receiver.taint || all.some((value) => value.taint))) {
        return withPrefixCleaning(concatValues([receiver, ...all]));
      }
      if (tail === "join" && !receiver.taint) return concatValues([receiver, ...all]);
      if (PREDICATE_METHODS.has(tail)) return CLEAN;
      if ((tail === "resolve" || tail === "absolute") && receiver.taint) return withTags(receiver, ["resolved-path", "path-object"]);
      if (receiver.tags.has("path-object") && /^(joinpath|with_name|with_suffix|relative_to|parent)$/.test(tail)) {
        return withTags(concatValues([receiver, ...all]), [...receiver.tags].filter((t) => t === "path-object" || t === "resolved-path"));
      }
      if (receiver.tags.has("http-client")) return CLEAN;
      if (receiver.taint) {
        const keep = [...receiver.tags].filter((t) => t === "resolved-path" || t === "path-object" || t === "parsed-url" || t === "url-host");
        const propagated: Value = { taint: receiver.taint, deps: receiver.deps, tags: new Set(keep), text: receiver.text, prefix: "" };
        if (tail === "get" || tail === "pop" || tail === "getlist") return keyedSource(propagated, call.args[0]);
        return concatValues([propagated, ...all.filter((value) => value.taint)], new Set(keep));
      }
      if (receiver.tags.has("const-collection") && (tail === "get" || tail === "pop")) return CLEAN;
    }
    return CLEAN;
  }

  /**
   * The project function a scheduling call will run, with the arguments it will run
   * with. Recognised by the scheduler's own calling convention, not by the callee:
   *
   *  - `add_task`, `submit`, `to_thread`, `run_sync`, `run_in_threadpool`, `start_soon`,
   *    `spawn`, `enqueue`: the function, then its positional and keyword arguments
   *    (`run_in_executor(executor, fn, *args)` after its executor);
   *  - `Thread(target=fn, args=(...), kwargs={...})` and `Process(...)`;
   *  - a task's own `fn.delay(*args)` and `fn.apply_async(args=[...], kwargs={...})`.
   */
  private deferredCall(
    call: Extract<Expr, { k: "call" }>,
    qualified: string | null,
    env: Env,
    frame: Frame
  ): { target: CallTarget; args: Value[]; kwargs: Map<string, Value>; call: Extract<Expr, { k: "call" }> } | null {
    const tail = calleeTail(call) ?? "";
    const resolve = (expr: Expr): CallTarget | null => {
      const symbol = this.project.resolveExpr(frame.module, expr);
      const receiver = expr.k === "attr" ? this.eval(expr.value, env, frame) : null;
      return this.calleeOf(expr, receiver, frame, symbol);
    };
    const build = (target: CallTarget, argExprs: Expr[], kwargExprs: Array<{ name: string | null; value: Expr }>) => {
      const args = argExprs.map((expr) => this.eval(expr, env, frame));
      const kwargs = new Map<string, Value>();
      for (const kw of kwargExprs) if (kw.name) kwargs.set(kw.name, this.eval(kw.value, env, frame));
      const synthetic: Extract<Expr, { k: "call" }> = { ...call, args: argExprs, kwargs: kwargExprs as typeof call.kwargs };
      return { target, args, kwargs, call: synthetic };
    };
    const elementsOf = (expr: Expr | undefined): Expr[] => (expr && (expr.k === "tuple" || expr.k === "list") ? expr.elts : []);
    const entriesOf = (expr: Expr | undefined) =>
      expr?.k === "dict" ? expr.entries.flatMap((entry) => (entry.key && constString(entry.key) !== null ? [{ name: constString(entry.key), value: entry.value }] : [])) : [];

    if (/^(threading\.Thread|multiprocessing\.Process|threading\.Timer)$/.test(qualified ?? "")) {
      const targetExpr = call.kwargs.find((kw) => kw.name === "target")?.value ?? (qualified === "threading.Timer" ? call.args[1] : undefined);
      const target = targetExpr ? resolve(targetExpr) : null;
      if (!target) return null;
      const argsExpr = call.kwargs.find((kw) => kw.name === "args")?.value ?? (qualified === "threading.Timer" ? call.args[2] : undefined);
      return build(target, elementsOf(argsExpr), entriesOf(call.kwargs.find((kw) => kw.name === "kwargs")?.value));
    }
    if ((tail === "delay" || tail === "apply_async") && call.func.k === "attr") {
      const target = resolve(call.func.value);
      if (!target) return null;
      if (tail === "delay") return build(target, call.args, call.kwargs.filter((kw) => kw.name !== null));
      const argsExpr = call.kwargs.find((kw) => kw.name === "args")?.value ?? call.args[0];
      return build(target, elementsOf(argsExpr), entriesOf(call.kwargs.find((kw) => kw.name === "kwargs")?.value ?? call.args[1]));
    }
    if (!/^(add_task|submit|to_thread|run_sync|run_in_threadpool|run_in_executor|start_soon|spawn|enqueue)$/.test(tail)) return null;
    const first = tail === "run_in_executor" ? 1 : 0;
    const fnExpr = call.args[first];
    const target = fnExpr && fnExpr.k !== "starred" ? resolve(fnExpr) : null;
    if (!target) return null;
    return build(target, call.args.slice(first + 1), call.kwargs.filter((kw) => kw.name !== null));
  }

  /** The project function a call reaches, when the engine can tell. */
  private calleeOf(
    func: Expr,
    receiver: Value | null,
    frame: Frame,
    symbol: ReturnType<Project["resolveExpr"]>
  ): CallTarget | null {
    if (symbol?.kind === "function") {
      const cls = func.k === "attr" ? this.classOfMethod(symbol.module, symbol.fn) : null;
      return { module: symbol.module, fn: symbol.fn, cls, bound: false };
    }
    if (func.k === "attr" && receiver?.instance) {
      const owner = this.project.module(receiver.instance.module);
      const cls = owner?.classes.get(receiver.instance.cls);
      const method = cls ? this.findMethod(owner!, cls, func.attr) : undefined;
      if (owner && method) return { module: method.module, fn: method.fn, cls: method.cls, bound: true };
    }
    return null;
  }

  private findMethod(module: PyModule, cls: ClassDef, name: string, depth = 0): { module: PyModule; fn: FunctionDef; cls: ClassDef } | undefined {
    if (depth > 5) return undefined;
    const own = methodOf(cls, name);
    if (own) return { module, fn: own, cls };
    for (const base of cls.bases) {
      const symbol = this.project.resolveExpr(module, base);
      if (symbol?.kind === "class") {
        const inherited = this.findMethod(symbol.module, symbol.cls, name, depth + 1);
        if (inherited) return inherited;
      }
    }
    return undefined;
  }

  private classOfMethod(module: PyModule, fn: FunctionDef): ClassDef | null {
    for (const cls of module.classes.values()) if (cls.body.includes(fn)) return cls;
    return null;
  }

  private applySummary(
    callee: { module: PyModule; fn: FunctionDef; cls: ClassDef | null; bound: boolean },
    args: Value[],
    kwargs: Map<string, Value>,
    call: Extract<Expr, { k: "call" }>,
    frame: Frame,
    env: Env
  ): Value {
    const summary = this.summary(callee.module, callee.fn, callee.cls);
    const offset = callee.bound && callee.fn.params[0] && /^(self|cls)$/.test(callee.fn.params[0].name) ? 1 : 0;
    const actual = new Map<number, Value>();
    callee.fn.params.forEach((param, index) => {
      if (param.kind === "vararg") {
        const rest = args.slice(index - offset);
        if (rest.length > 0) actual.set(index, concatValues(rest));
        return;
      }
      if (param.kind === "kwarg") {
        const named = [...kwargs.entries()].filter(([name]) => !callee.fn.params.some((p) => p.name === name)).map(([, v]) => v);
        if (named.length > 0) actual.set(index, concatValues(named));
        return;
      }
      const value = kwargs.get(param.name) ?? args[index - offset];
      if (value) actual.set(index, value);
    });

    // A validator returned normally: what it proves about its parameters now holds
    // for the caller's arguments.
    if (summary.guarantees) {
      const facts: Facts = [];
      callee.fn.params.forEach((param, index) => {
        const proven = summary.guarantees!.get(index);
        if (!proven || param.kind !== "normal") return;
        const named = call.kwargs.find((kw) => kw.name === param.name)?.value;
        const argument = named ?? call.args[index - offset];
        if (argument && argument.k !== "starred") for (const expr of keysOf(argument)) facts.push({ expr, clean: proven });
      });
      applyFacts(env, facts, this, frame);
    }
    for (const store of summary.stores ?? []) {
      const taint = substitute(store.taint, actual);
      if (taint) this.recordStore(store.field, { ...CLEAN, taint }, store.line, frame, store.module);
    }
    for (const lookup of summary.lookups ?? []) {
      const key: Value = { ...CLEAN, taint: substitute(lookup.key?.taint ?? null, actual) };
      if (callerChosen(key) || (!frame.route && fromParameter(key))) {
        frame.lookups.push({ ...lookup, key, path: [callee.fn, ...(lookup.path ?? [])], siteLine: call.span.line });
      }
    }
    for (const hit of summary.hits) {
      const taint = substitute(hit.taint, actual);
      if (!taint) continue;
      if (hit.deferredShape) {
        const deferred = this.decideDeferred(hit, taint, actual, call, frame);
        if (deferred) frame.hits.push(deferred);
        continue;
      }
      frame.hits.push({ ...hit, taint });
    }
    const returned = summary.returns;
    const taint = substitute(returned.taint, actual);
    const deps = new Set<string>();
    for (const origin of returned.taint?.origins ?? []) {
      if (origin.kind === "param") for (const dep of actual.get(origin.index)?.deps ?? []) deps.add(dep);
    }
    void call;
    const out: Value = { taint, deps, tags: returned.tags, text: returned.text, prefix: returned.prefix };
    if (returned.model) out.model = returned.model;
    if (returned.instance) out.instance = returned.instance;
    if (returned.elements) {
      out.elements = returned.elements.map((element) => {
        const elementDeps = new Set<string>();
        for (const origin of element.taint?.origins ?? []) {
          if (origin.kind === "param") for (const dep of actual.get(origin.index)?.deps ?? []) elementDeps.add(dep);
        }
        return { taint: substitute(element.taint, actual), deps: elementDeps, tags: element.tags, text: element.text, prefix: element.prefix };
      });
    }
    if (returned.fields) {
      const fields = new Map<string, Value>();
      for (const [name, value] of returned.fields) {
        fields.set(name, { ...value, taint: substitute(value.taint, actual), deps: new Set() });
      }
      out.fields = fields;
    }
    return out;
  }

  /**
   * A helper that executes whatever statement it is handed is reported where the
   * statement is built, which is the line a reader has to change. The caller's value
   * decides it: SQL text around caller data is the defect; another bare parameter
   * defers the decision one call further out.
   */
  private decideDeferred(
    hit: SinkHit,
    taint: Taint,
    actual: Map<number, Value>,
    call: Extract<Expr, { k: "call" }>,
    frame: Frame
  ): SinkHit | null {
    if (taint.clean.has(hit.sink)) return null;
    const passed = hit.taint.origins.flatMap((origin) => (origin.kind === "param" ? [actual.get(origin.index)] : []));
    const values = passed.filter((value): value is Value => Boolean(value?.taint));
    const relocated = { ...hit, taint, module: frame.module, span: call.span, sinkName: `${dotted(call.func) ?? calleeTail(call) ?? "a helper"}()` };
    if (values.some((value) => SQL_SHAPE.test(value.text))) {
      const { deferredShape: _settled, ...decided } = relocated;
      void _settled;
      return { ...decided, detail: `which runs it through ${hit.sinkName}` };
    }
    const stillPassThrough = values.every((value) => value.text === "") && taint.origins.every((origin) => origin.kind === "param");
    return stillPassThrough ? { ...relocated, sinkName: hit.sinkName } : null;
  }

  /* ------------------------------------------------------ stored records */

  /**
   * Attacker data written to a field of a stored record. A route's own sources are
   * recorded for the whole project; a helper's parameters are recorded on its summary
   * and decided where it is called. Only a function that persists something counts.
   */
  private recordStore(field: string, value: Value, line: number, frame: Frame, module: PyModule = frame.module): void {
    if (!value.taint || !frame.fn || !this.persists(frame.fn)) return;
    const own = value.taint.origins.filter((origin) => origin.kind === "source" && origin.source !== "session" && origin.source !== "stored");
    if (frame.route) {
      if (own.length === 0) return;
      const list = this.storedWrites.get(field) ?? [];
      list.push({ field, taint: { origins: own, clean: value.taint.clean }, line, module });
      this.storedWrites.set(field, list);
      return;
    }
    if (own.length > 0 || value.taint.origins.some((origin) => origin.kind === "param")) {
      frame.stores.push({ field, taint: value.taint, line, module });
    }
  }

  /** Does the function save something: `session.commit()`, `db.session.add(x)`, `repo.save(x)`? */
  private persists(fn: FunctionDef): boolean {
    const cached = this.persistsCache.get(fn);
    if (cached !== undefined) return cached;
    let found = false;
    walkStmts(fn.body, (stmt) => {
      if (found) return;
      for (const root of stmtExprs(stmt)) {
        walkExpr(root, (expr) => {
          if (expr.k === "call" && expr.func.k === "attr" && PERSIST_CALL.test(expr.func.attr)) found = true;
        });
      }
    });
    this.persistsCache.set(fn, found);
    return found;
  }

  /** A class whose instances are rows: an ORM model, by its table, its columns or its base. */
  isPersisted(module: PyModule, cls: ClassDef, depth = 0): boolean {
    const cached = this.persistedCache.get(cls);
    if (cached !== undefined) return cached;
    let persisted = cls.keywords.some((kw) => kw.name === "table" && kw.value.k === "const" && kw.value.value === true);
    for (const stmt of cls.body) {
      if (persisted) break;
      if (stmt.k !== "assign") continue;
      if (stmt.targets.some((target) => target.k === "name" && /^__(tablename|table__|collection)__?$/.test(target.id))) persisted = true;
      if (stmt.value?.k === "call" && /(^|\.)(Column|mapped_column|relationship|ReferenceField|StringField|IntField)$/.test(dotted(stmt.value.func) ?? "")) persisted = true;
    }
    for (const base of cls.bases) {
      if (persisted || depth > 4) break;
      const name = dotted(base) ?? "";
      if (/(^|\.)(Model|DeclarativeBase|Document|DynamicDocument)$/.test(name) || /^(db|database)\.Model$/.test(name)) persisted = true;
      const symbol = this.project.resolveExpr(module, base);
      if (symbol?.kind === "class" && symbol.cls !== cls && this.isPersisted(symbol.module, symbol.cls, depth + 1)) persisted = true;
    }
    this.persistedCache.set(cls, persisted);
    return persisted;
  }

  /**
   * Whether an attribute assignment writes a record: the signed-in user, an instance of
   * a persisted class, or a plain local the function loaded (not `self`, not the request,
   * not a module, not one of this analysis's own known objects).
   */
  private isRecordTarget(base: Expr, env: Env, frame: Frame): boolean {
    const name = dotted(base);
    if (!name) return false;
    if (frame.route?.subjects.includes(name)) return true;
    if (base.k !== "name" || /^(self|cls|request|response|resp|g|app|config|settings)$/.test(base.id) || frame.requestNames.has(base.id)) return false;
    const value = env.get(base.id);
    if (!value) return false;
    return this.mayBeRecord(base, value, frame);
  }

  /** Could this untainted value be a stored record, rather than a module, a client or a constant? */
  private mayBeRecord(expr: Expr, value: Value, frame: Frame): boolean {
    for (const tag of value.tags) if (tag !== "upload") return false;
    if (value.template || value.entryValues) return false;
    if (value.instance) {
      const owner = this.project.module(value.instance.module);
      const cls = owner?.classes.get(value.instance.cls);
      return Boolean(owner && cls && this.isPersisted(owner, cls));
    }
    const root = expr.k === "name" ? expr.id : (dotted(expr) ?? "").split(".")[0];
    if (!root) return true;
    const symbol = this.project.resolveExpr(frame.module, { k: "name", id: root, span: NO_SPAN });
    if (symbol?.kind === "module" || symbol?.kind === "class" || symbol?.kind === "function") return false;
    // `import config` binds a module; `from flask_login import current_user` an object.
    const binding = frame.module.imports.get(root);
    return !binding || binding.member !== null;
  }

  /** Field names written anywhere in the project, read syntactically before any analysis. */
  private storedFieldNames(): Set<string> {
    const out = new Set<string>();
    for (const module of this.project.modules) {
      walkStmts(
        module.ast.body,
        (stmt) => {
          if (stmt.k === "assign" && stmt.value && !isLiteralExpr(stmt.value)) {
            for (const target of stmt.targets) if (target.k === "attr" && target.value.k !== "call") out.add(target.attr);
          }
          for (const root of stmtExprs(stmt)) {
            walkExpr(root, (expr) => {
              if (expr.k !== "call" || expr.kwargs.length === 0) return;
              const symbol = this.project.resolveExpr(module, expr.func);
              if (symbol?.kind !== "class" || !this.isPersisted(symbol.module, symbol.cls)) return;
              for (const kw of expr.kwargs) if (kw.name) out.add(kw.name);
            });
          }
        },
        true
      );
    }
    return out;
  }

  private template(name: string): string | null {
    if (!this.templateCache.has(name)) this.templateCache.set(name, this.readTemplate(name));
    return this.templateCache.get(name) ?? null;
  }
}

/**
 * What every normal exit of a function proves about each parameter. Only a value
 * still carrying the parameter's own origin speaks for the caller's argument; a
 * parameter rebound to something else proves nothing about it.
 */
function guaranteesOf(fn: FunctionDef, exits: Env[]): Map<number, ReadonlySet<SinkClass>> {
  const out = new Map<number, ReadonlySet<SinkClass>>();
  if (exits.length === 0) return out;
  fn.params.forEach((param, index) => {
    if (param.kind !== "normal") return;
    let proven: Set<SinkClass> | undefined;
    for (const exit of exits) {
      const value = exit.get(param.name);
      const own = value?.taint?.origins.some((origin) => origin.kind === "param" && origin.index === index);
      if (!value?.taint || !own || value.taint.clean.size === 0) {
        proven = undefined;
        break;
      }
      proven = intersectSinks(proven, value.taint.clean);
      if (proven.size === 0) break;
    }
    if (proven && proven.size > 0) out.set(index, proven);
  });
  return out;
}

function intersectSinks(current: ReadonlySet<SinkClass> | undefined, next: ReadonlySet<SinkClass>): Set<SinkClass> {
  const out = new Set<SinkClass>();
  for (const sink of next) if (!current || current.has(sink)) out.add(sink);
  return out;
}

/** `@router.get(..., response_class=HTMLResponse)`: a returned string is the HTML page. */
function declaresHtmlResponse(fn: FunctionDef): boolean {
  return fn.decorators.some((decorator) => {
    if (decorator.expr.k !== "call") return false;
    const responseClass = decorator.expr.kwargs.find((kw) => kw.name === "response_class")?.value;
    return Boolean(responseClass && /(^|\.)HTMLResponse$/.test(dotted(responseClass) ?? ""));
  });
}

const NO_SPAN = { line: 0, endLine: 0, from: 0, to: 0 };
const PERSIST_CALL = /^(commit|save|flush|add|add_all|merge|insert|insert_one|insert_many|update_one|replace_one|bulk_save_objects|put|persist|store|upsert)$/;
const JINJA_TEMPLATES = /^(fastapi|starlette)\.templating\.Jinja2Templates$/;

function isLiteralExpr(expr: Expr): boolean {
  return expr.k === "str" || expr.k === "num" || expr.k === "const";
}

/**
 * A template whose source the engine can read: `env.from_string("…")` on an
 * environment that is not sandboxed, or `env.get_template("name.html")`.
 */
function compiledTemplate(call: Extract<Expr, { k: "call" }>, receiver: Value, readFile: (name: string) => string | null, module: PyModule): Value | null {
  if (call.func.k !== "attr" || !receiver.tags.has("jinja-env") || receiver.tags.has("jinja-sandbox")) return null;
  const source = call.args[0];
  if (call.func.attr === "from_string" && source && constString(source) !== null) {
    return { ...CLEAN, template: { text: constString(source)!, module, line: source.span.line } };
  }
  if (call.func.attr === "get_template" && source && constString(source) !== null) {
    const text = readFile(constString(source)!);
    return text === null ? null : { ...CLEAN, template: { text, module, line: null } };
  }
  return null;
}

/** A field read back from a stored record: attacker data only if some route wrote attacker data to it. */
function storedRead(field: string, line: number): Value {
  return sourceValue({ kind: "source", label: `stored field ${field}`, source: "stored", line, key: field });
}

/** Attributes of a parsed URL that are parts of it rather than the URL. */
const URL_COMPONENTS = /^(scheme|netloc|hostname|host|port|path|params|query|fragment|username|password)$/;
/** The parts of a parsed URL that decide where a request to it goes. */
const URL_AUTHORITY = /^(netloc|hostname|host)$/;

function isLiteral(expr: Expr): boolean {
  if (expr.k === "str" || expr.k === "num" || expr.k === "const") return true;
  return (expr.k === "list" || expr.k === "tuple" || expr.k === "dict" || expr.k === "set") && (expr.k === "dict" ? expr.entries.length === 0 : expr.elts.length === 0);
}

/** A value read from the session under `key`: attacker data only if a route stored some there. */
function sessionRead(key: string | null, line: number): Value {
  if (key === null || !/^[A-Za-z0-9_.:-]{1,64}$/.test(key)) return CLEAN;
  return sourceValue({ kind: "source", label: `session value ${key}`, source: "session", line, key });
}

/** A collection seen as the items it yields, whose positions say nothing about each item. */
function itemsOf(value: Value): Value {
  if (!value.elements) return value;
  const { elements: _positions, ...items } = value;
  void _positions;
  return items;
}

const KEYED_LABELS: Partial<Record<SourceKind, string>> = {
  query: "query parameter",
  form: "form field",
  body: "request body field",
  header: "header",
  cookie: "cookie",
  file: "uploaded file"
};

/**
 * `request.args.get("template")` names the parameter the report should name. Only the
 * label changes, and only when the value comes from exactly one request container,
 * so what is tainted and what is clean is untouched.
 */
function keyedSource(value: Value, key: Expr | null | undefined): Value {
  const name = key ? constString(key) : null;
  const origin = value.taint?.origins.length === 1 ? value.taint.origins[0] : undefined;
  if (!name || !/^[A-Za-z0-9_.-]{1,64}$/.test(name) || origin?.kind !== "source" || !/^request\.[a-z_]+$/.test(origin.label)) return value;
  const kind = KEYED_LABELS[origin.source];
  if (!kind) return value;
  return { ...value, taint: { origins: [{ ...origin, label: `${kind} ${name}` }], clean: value.taint!.clean } };
}

/** The shape of a module-level constant: a fixed collection, or a fixed string. */
function constantShape(expr: Expr, engine: Engine, module: PyModule): Value {
  if (expr.k === "str") return constant(expr.value);
  if (expr.k === "num") return constant(String(expr.value));
  if (expr.k === "list" || expr.k === "tuple" || expr.k === "set" || expr.k === "dict") {
    return withTags(constant(""), ["const-collection"]);
  }
  if (expr.k === "call") {
    const name = dotted(expr.func) ?? "";
    if (/^(frozenset|set|tuple|list|dict|MappingProxyType|types\.MappingProxyType)$/.test(name)) return withTags(constant(""), ["const-collection"]);
    if (PATH_CONSTRUCTORS.test(engine.project.qualified(module, expr.func) ?? name)) return withTags(constant(constString(expr.args[0]) ?? ""), ["path-object"]);
    if (/(^|\.)compile$/.test(name)) return withTags(constant(constString(expr.args[0]) ?? ""), /^re\.compile$/.test(engine.project.qualified(module, expr.func) ?? "") ? ["regex"] : []);
    // `PAGE = env.from_string("""…""")` at module level: a template whose source is known.
    if (expr.func.k === "attr" && expr.func.attr === "from_string") {
      const receiver = constantShape(expr.func.value.k === "name" ? engine.project.constantValue(module, expr.func.value.id)?.expr ?? expr.func.value : expr.func.value, engine, module);
      const compiled = compiledTemplate(expr, receiver, () => null, module);
      if (compiled) return compiled;
    }
    const qualified = engine.project.qualified(module, expr.func) ?? "";
    if (HTTP_CLIENTS.test(qualified)) return withTags(CLEAN, ["http-client"]);
    if (JINJA_ENVIRONMENTS.test(qualified)) return withTags(CLEAN, ["jinja-env"]);
    if (JINJA_SANDBOXES.test(qualified)) return withTags(CLEAN, ["jinja-sandbox"]);
    if (JINJA_TEMPLATES.test(qualified)) return withTags(CLEAN, ["jinja-templates"]);
    if (SIGNERS.test(qualified)) return withTags(CLEAN, ["signer"]);
    // `storage = Storage("/srv/data")` at module level: calls on it reach the class's methods.
    const symbol = engine.project.resolveExpr(module, expr.func);
    if (symbol?.kind === "class") return { ...CLEAN, instance: { module: symbol.module.name, cls: symbol.cls.name } };
  }
  if (expr.k === "fstr" || expr.k === "binop") {
    const text = expr.k === "fstr" ? expr.parts.filter((p): p is string => typeof p === "string").join("") : "";
    return constant(text);
  }
  return CLEAN;
}

function containmentByException(body: Stmt[], env: Env, engine: Engine, frame: Frame): Facts {
  const facts: Facts = [];
  for (const stmt of body) {
    const exprs = stmt.k === "assign" ? (stmt.value ? [stmt.value] : []) : stmt.k === "expr" ? [stmt.value] : [];
    for (const root of exprs) {
      walkExpr(root, (expr) => {
        if (expr.k !== "call" || expr.func.k !== "attr") return;
        if (!/^(relative_to|is_relative_to)$/.test(expr.func.attr)) return;
        const receiver = engine.eval(expr.func.value, env, frame);
        if (!receiver.tags.has("resolved-path")) return;
        facts.push({ expr: expr.func.value, clean: new Set<SinkClass>(["path"]) });
      });
    }
  }
  return facts;
}
