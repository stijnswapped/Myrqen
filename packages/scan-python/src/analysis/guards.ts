import type { Expr, FunctionDef, Stmt } from "../syntax/ast.js";
import { constString, dotted, walkExpr, walkStmts } from "../syntax/ast.js";
import { patternCleans } from "../project/types.js";
import type { Engine, Env, Frame } from "./engine.js";
import { ALL_SINKS, withClean, type SinkClass, type Value } from "./values.js";

/**
 * What a condition proves about the values it tests.
 *
 * A guard is only worth anything on the path it guards, so every test yields two
 * lists: what is known when it is true, and what is known when it is false. The
 * interpreter applies the first inside the `if` body and the second after an
 * `if` whose body refuses (`raise`, `abort`, `return`), which is how
 * `if name not in ALLOWED: abort(400)` cleans `name` for the rest of the handler.
 *
 * Each recognised guard is a real constraint on the value, not a name:
 *
 *  - membership in a fixed collection, or equality with a constant;
 *  - `str.isdigit()` and its relatives, `isinstance(x, int)`;
 *  - a full regular-expression match, cleaning only what the pattern excludes;
 *  - a containment test on a *resolved* path (`realpath`, `resolve()`):
 *    `startswith`, `is_relative_to`, `commonpath`. The same test on an
 *    unresolved path is bypassable with `..` and is deliberately not credited;
 *  - `".." in name` / `"/" in name` as a refusal;
 *  - a URL whose host is checked against an allow-list, or whose `netloc` is
 *    required to be empty;
 *  - a constant-time comparison of a signature, which authenticates the payload
 *    it was computed over.
 */

export type Facts = Array<{ expr: Expr; clean: ReadonlySet<SinkClass> }>;

const ALLOWLIST_NAME = /(allow|whitelist|permitted|valid|known|supported|accepted|choices|options|trusted|approved|safe|enabled|registered|^[A-Z][A-Z0-9_]+$)/;
const SAFE_URL_CHECK = /(is_?safe_?(url|redirect|next|path|host)|url_has_allowed_host_and_scheme|is_?(allowed|trusted|permitted)_?(url|host|redirect|domain|origin)|is_?valid_?(redirect|next|return)_?(url|path)?|is_?local_?url|is_?relative_?url|same_?origin)/i;
const SAFE_PATH_CHECK = /(is_?safe_?(path|file|filename)|is_?(allowed|valid)_?(path|file|filename)|within_?(base|root|dir)|is_?inside|is_?contained)/i;
const SIGNATURE_CHECK = /(^|\.)(compare_digest|verify_signature|verify_hmac|check_signature|is_valid_signature|valid_signature|verify)$/;

export function factsOf(test: Expr, env: Env, engine: Engine, frame: Frame): { whenTrue: Facts; whenFalse: Facts } {
  switch (test.k) {
    case "not": {
      const inner = factsOf(test.operand, env, engine, frame);
      return { whenTrue: inner.whenFalse, whenFalse: inner.whenTrue };
    }
    case "boolop": {
      const left = factsOf(test.left, env, engine, frame);
      const right = factsOf(test.right, env, engine, frame);
      if (test.op === "and") {
        const whenTrue = [...left.whenTrue, ...right.whenTrue, ...localRedirectPattern(test)];
        return { whenTrue, whenFalse: [] };
      }
      return { whenTrue: [], whenFalse: [...left.whenFalse, ...right.whenFalse, ...localRedirectPattern(test)] };
    }
    case "compare":
      return compareFacts(test, env, engine, frame);
    case "call":
      return { whenTrue: callFacts(test, env, engine, frame), whenFalse: [] };
    case "attr": {
      // `if parsed.netloc:` — a URL with no host is a path on this site.
      const base = engine.eval(test.value, env, frame);
      // `if address.is_private: abort(400)` on what the host name resolved to: the
      // request cannot reach an internal address. On a parsed literal it proves
      // nothing, because a name that resolves inward is not an address literal.
      if (base.tags.has("resolved-address") && /^is_(private|loopback|link_local|reserved|multicast|unspecified|site_local)$/.test(test.attr)) {
        return { whenTrue: [], whenFalse: resolvedFrom(test.value, base) };
      }
      if (base.tags.has("resolved-address") && test.attr === "is_global") return { whenTrue: resolvedFrom(test.value, base), whenFalse: [] };
      if (base.tags.has("parsed-url") && /^(netloc|scheme|hostname|host)$/.test(test.attr)) {
        return { whenTrue: [], whenFalse: namesOf(test.value).map((expr) => ({ expr, clean: new Set<SinkClass>(["redirect"]) })) };
      }
      return { whenTrue: [], whenFalse: [] };
    }
    case "named":
      return factsOf(test.value, env, engine, frame);
    default:
      return { whenTrue: [], whenFalse: [] };
  }
}

function compareFacts(test: Extract<Expr, { k: "compare" }>, env: Env, engine: Engine, frame: Frame): { whenTrue: Facts; whenFalse: Facts } {
  const none = { whenTrue: [] as Facts, whenFalse: [] as Facts };
  const positive = test.op === "in" || test.op === "==" || test.op === "is";
  const negative = test.op === "not in" || test.op === "!=" || test.op === "is not";
  if (!positive && !negative) return none;
  const place = (facts: Facts) => (positive ? { whenTrue: facts, whenFalse: [] } : { whenTrue: [], whenFalse: facts });
  const placeInverse = (facts: Facts) => (positive ? { whenTrue: [], whenFalse: facts } : { whenTrue: facts, whenFalse: [] });

  if (test.op === "in" || test.op === "not in") {
    // `".." in name`: true means dangerous, so the false branch is the clean one.
    const needle = constString(test.left);
    if (needle !== null && /^(\.\.|\/|\\|\.\.\/|\.\.\\)$/.test(needle)) {
      return placeInverse(namesOf(test.right).map((expr) => ({ expr, clean: new Set<SinkClass>(["path"]) })));
    }
    if (isFixedCollection(test.right, env, engine, frame)) {
      return place([...componentKeys(test.left, env, engine, frame).map((expr) => ({ expr, clean: ALL_SINKS })), ...pinnedHost(test.left, env, engine, frame)]);
    }
    return none;
  }

  if (test.op === "is" || test.op === "is not") return none;

  // Equality with a fixed value.
  const leftFixed = isFixedScalar(test.left, env, engine, frame);
  const rightFixed = isFixedScalar(test.right, env, engine, frame);
  if (rightFixed && !leftFixed) {
    const fromNetloc = netlocOf(test.left, env, engine, frame);
    if (fromNetloc && constString(test.right) === "") return place(fromNetloc.map((expr) => ({ expr, clean: new Set<SinkClass>(["redirect"]) })));
    return place([...componentKeys(test.left, env, engine, frame).map((expr) => ({ expr, clean: ALL_SINKS })), ...pinnedHost(test.left, env, engine, frame)]);
  }
  if (leftFixed && !rightFixed) return place([...componentKeys(test.right, env, engine, frame).map((expr) => ({ expr, clean: ALL_SINKS })), ...pinnedHost(test.right, env, engine, frame)]);

  // `urlparse(target).netloc == urlparse(request.host_url).netloc`: the destination is
  // this site. That keeps a redirect home; it says nothing about a server-side request.
  for (const [side, other] of [
    [test.left, test.right],
    [test.right, test.left]
  ] as const) {
    if (hostAttribute(side, env, engine, frame) && isOwnHost(other, env, engine, frame)) {
      return place(namesOf((side as Extract<Expr, { k: "attr" }>).value).map((expr) => ({ expr, clean: new Set<SinkClass>(["redirect"]) })));
    }
  }

  // `os.path.commonpath([base, target]) == base`
  for (const side of [test.left, test.right]) {
    if (side.k === "call" && /(^|\.)(commonpath|commonprefix)$/.test(dotted(side.func) ?? "")) {
      const list = side.args[0];
      const members = list && (list.k === "list" || list.k === "tuple") ? list.elts : side.args;
      const resolved = members.filter((member) => engine.eval(member, env, frame).tags.has("resolved-path"));
      if (resolved.length > 0) return place(resolved.flatMap((member) => keysOf(member)).map((expr) => ({ expr, clean: new Set<SinkClass>(["path"]) })));
    }
  }
  return none;
}

function callFacts(call: Extract<Expr, { k: "call" }>, env: Env, engine: Engine, frame: Frame): Facts {
  const name = dotted(call.func) ?? "";
  const qualified = engine.project.qualified(frame.module, call.func) ?? name;
  const method = call.func.k === "attr" ? call.func.attr : null;
  const receiver = call.func.k === "attr" ? call.func.value : null;

  // Containment of a resolved path.
  if (receiver && method && /^(startswith|is_relative_to)$/.test(method)) {
    const value = engine.eval(receiver, env, frame);
    if (value.tags.has("resolved-path")) return keysOf(receiver).map((expr) => ({ expr, clean: new Set<SinkClass>(["path"]) }));
    // `url.startswith("https://partner.example/")` fixes the host, because the prefix
    // ends the authority. Without the slash, `https://partner.example.evil.test` passes.
    if (method === "startswith" && call.args[0] && prefixes(call.args[0]).every((prefix) => FIXED_ORIGIN_PREFIX.test(prefix)) && prefixes(call.args[0]).length > 0) {
      return keysOf(receiver).map((expr) => ({ expr, clean: new Set<SinkClass>(["ssrf", "redirect"]) }));
    }
    // `next.startswith("/")` alone admits `//evil.example`; see localRedirectPattern.
    return [];
  }

  // `parsed.hostname.endswith(".partner.example")`: a suffix that starts at a label
  // boundary. `endswith("partner.example")` also admits `evilpartner.example`.
  if (receiver && method === "endswith" && call.args[0] && hostAttribute(receiver, env, engine, frame)) {
    const suffixes = prefixes(call.args[0]);
    if (suffixes.length > 0 && suffixes.every((suffix) => /^\.[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(suffix))) {
      return namesOf((receiver as Extract<Expr, { k: "attr" }>).value).map((expr) => ({ expr, clean: new Set<SinkClass>(["ssrf", "redirect"]) }));
    }
    return [];
  }

  if (receiver && method && /^(isdigit|isdecimal|isnumeric|isalnum|isalpha|isidentifier)$/.test(method)) {
    return keysOf(receiver).map((expr) => ({ expr, clean: ALL_SINKS }));
  }

  if (name === "isinstance" && call.args[0] && call.args[1]) {
    const typeName = dotted(call.args[1]) ?? "";
    if (/^(int|float|bool|uuid\.UUID|UUID|Decimal|datetime|date)$/.test(typeName)) return keysOf(call.args[0]).map((expr) => ({ expr, clean: ALL_SINKS }));
    return [];
  }

  // re.fullmatch(PATTERN, value) / PATTERN.fullmatch(value)
  const regexCall = /^(re\.)?(fullmatch|match|search)$/.test(qualified.replace(/^re\./, "re.")) && /^re\./.test(qualified);
  if (regexCall && call.args[0] && call.args[1]) {
    const pattern = engine.eval(call.args[0], env, frame).text;
    const full = /fullmatch$/.test(qualified);
    return keysOf(call.args[1]).map((expr) => ({ expr, clean: patternCleans(pattern, full) }));
  }
  if (receiver && method && /^(fullmatch|match|search)$/.test(method) && call.args[0]) {
    const pattern = engine.eval(receiver, env, frame).text;
    if (pattern) return keysOf(call.args[0]).map((expr) => ({ expr, clean: patternCleans(pattern, method === "fullmatch") }));
  }

  const tail = name.split(".").pop() ?? "";
  if (SAFE_URL_CHECK.test(tail) && call.args[0]) {
    return keysOf(call.args[0]).map((expr) => ({ expr, clean: new Set<SinkClass>(["redirect", "ssrf"]) }));
  }
  // A project predicate whose answer is a test on the URL's host, whatever it is called.
  if (call.args[0]) {
    const symbol = engine.project.resolveExpr(frame.module, call.func);
    const proves = symbol?.kind === "function" ? urlPredicate(symbol.fn) : null;
    if (proves && proves.size > 0) return keysOf(call.args[0]).map((expr) => ({ expr, clean: proves }));
  }
  if (SAFE_PATH_CHECK.test(tail) && call.args[0]) {
    return call.args.flatMap((arg) => keysOf(arg)).map((expr) => ({ expr, clean: new Set<SinkClass>(["path"]) }));
  }
  if (SIGNATURE_CHECK.test(qualified) || SIGNATURE_CHECK.test(name)) {
    const facts: Facts = [];
    for (const arg of call.args) {
      for (const expr of namesOf(arg)) facts.push({ expr, clean: new Set<SinkClass>(["deserialization"]) });
      const value = engine.eval(arg, env, frame);
      for (const dep of value.deps) facts.push({ expr: { k: "name", id: dep, span: call.span }, clean: new Set<SinkClass>(["deserialization"]) });
    }
    return facts;
  }
  return [];
}

/**
 * What a project function that returns a URL check proves about its first argument.
 *
 * Read from the shape of what it returns, not from its name: a host compared with
 * this request's own host keeps a redirect on this site; a host compared with a fixed
 * value or allow-list pins the destination for a server-side request too. A function
 * that returns anything else proves nothing, and neither does one whose host test
 * is a substring check.
 */
function urlPredicate(fn: FunctionDef): ReadonlySet<SinkClass> | null {
  if (fn.params.length === 0) return null;
  const returned: Expr[] = [];
  let bare = false;
  walkStmts(fn.body, (stmt) => {
    if (stmt.k !== "return") return;
    if (stmt.value) returned.push(stmt.value);
    else bare = true;
  });
  if (bare || returned.length === 0) return null;
  // Every way of answering yes has to be one of the recognised checks: a predicate
  // that also returns True for some other reason proves nothing about the URL.
  let proves: Set<SinkClass> | null = null;
  for (const root of returned) {
    if (root.k === "const" && root.value !== true) continue;
    const here = new Set<SinkClass>();
    if (root.k === "boolop" && root.op === "and" && localRedirectPattern(root).length > 0) here.add("redirect");
    // Only a comparison the answer requires: a conjunct of the returned expression,
    // never one under `not` or one alternative of an `or`.
    for (const expr of conjunctsOf(root)) {
      if (expr.k !== "compare" || !/^(==|in)$/.test(expr.op)) continue;
      for (const [side, other] of [
        [expr.left, expr.right],
        [expr.right, expr.left]
      ] as const) {
        if (side.k !== "attr" || !/^(netloc|hostname|host)$/.test(side.attr)) continue;
        if (other.k === "attr" && /^(netloc|hostname|host)$/.test(other.attr)) here.add("redirect");
        else if (/(^|\.)request\.(host|server_name)$/.test(dotted(other) ?? "")) here.add("redirect");
        else if ((expr.op === "in" && fixedLiteralCollection(other)) || (expr.op === "==" && other.k === "str" && other.value !== "")) {
          here.add("redirect");
          here.add("ssrf");
        }
        else if (expr.op === "==" && constString(other) === "") here.add("redirect");
      }
    }
    if (here.size === 0) return null;
    const previous: Set<SinkClass> | null = proves;
    proves = previous ? new Set<SinkClass>([...previous].filter((sink: SinkClass) => here.has(sink))) : here;
  }
  return proves;
}

function conjunctsOf(expr: Expr): Expr[] {
  if (expr.k === "boolop" && expr.op === "and") return [...conjunctsOf(expr.left), ...conjunctsOf(expr.right)];
  return [expr];
}

function fixedLiteralCollection(expr: Expr): boolean {
  if (expr.k === "list" || expr.k === "tuple" || expr.k === "set") return expr.elts.every((element) => element.k === "str");
  const tail = (dotted(expr) ?? "").split(".").pop() ?? "";
  return Boolean(tail) && ALLOWLIST_NAME.test(tail) && !/request|args|form|json|params|body|query/i.test(dotted(expr) ?? "");
}

/**
 * `next.startswith("/") and not next.startswith("//")` keeps a redirect on this site,
 * and so does its negation written as a refusal, `not next.startswith("/") or
 * next.startswith("//")`, on the branch where it is false.
 */
function localRedirectPattern(test: Extract<Expr, { k: "boolop" }>): Facts {
  const operands: Expr[] = [];
  const flatten = (expr: Expr) => {
    if (expr.k === "boolop" && expr.op === test.op) {
      flatten(expr.left);
      flatten(expr.right);
    } else operands.push(expr);
  };
  flatten(test);
  // The `or` form is false exactly when every operand is false: read each negated.
  const conjuncts = test.op === "and" ? operands : operands.map((operand): Expr => (operand.k === "not" ? operand.operand : { k: "not", operand, span: operand.span }));
  const startsWithSlash = conjuncts.find(
    (operand) => operand.k === "call" && operand.func.k === "attr" && operand.func.attr === "startswith" && constString(operand.args[0]) === "/"
  );
  const notProtocolRelative = conjuncts.some((operand) => {
    if (operand.k !== "not" || operand.operand.k !== "call" || operand.operand.func.k !== "attr") return false;
    if (operand.operand.func.attr !== "startswith") return false;
    const arg = operand.operand.args[0];
    if (!arg) return false;
    if (constString(arg) === "//") return true;
    return arg.k === "tuple" && arg.elts.some((element) => constString(element) === "//");
  });
  if (!startsWithSlash || !notProtocolRelative || startsWithSlash.k !== "call" || startsWithSlash.func.k !== "attr") return [];
  return keysOf(startsWithSlash.func.value).map((expr) => ({ expr, clean: new Set<SinkClass>(["redirect"]) }));
}

function isFixedCollection(expr: Expr, env: Env, engine: Engine, frame: Frame): boolean {
  if (expr.k === "list" || expr.k === "tuple" || expr.k === "set" || expr.k === "dict") {
    const elements = expr.k === "dict" ? expr.entries.map((entry) => entry.key).filter((key): key is Expr => key !== null) : expr.elts;
    return elements.every((element) => element.k === "str" || element.k === "num" || element.k === "const");
  }
  const value = engine.eval(expr, env, frame);
  if (value.taint) return false;
  if (value.tags.has("const-collection")) return true;
  const name = dotted(expr) ?? "";
  const tail = name.split(".").pop() ?? "";
  // A collection whose name says it is a policy (`ALLOWED_HOSTS`, `settings.TRUSTED_ORIGINS`).
  return Boolean(tail) && ALLOWLIST_NAME.test(tail) && !/request|args|form|json|params|body|query/i.test(name);
}

function isFixedScalar(expr: Expr, env: Env, engine: Engine, frame: Frame): boolean {
  if (expr.k === "str" || expr.k === "num" || expr.k === "const") return true;
  if (expr.k === "name" || expr.k === "attr") {
    const value = engine.eval(expr, env, frame);
    if (value.taint) return false;
    const name = dotted(expr) ?? "";
    return value.text.length > 0 || /^[A-Z][A-Z0-9_]+$/.test(name.split(".").pop() ?? "");
  }
  return false;
}

const FIXED_ORIGIN_PREFIX = /^https?:\/\/[^/?#@\s\\]+\//i;

/**
 * The places a fixed-value test speaks for. `urlparse(url).scheme == "https"` fixes
 * the scheme of `url` and nothing else about it, so a component of a URL parsed in
 * place is no fact about the URL's own name; `parsed.scheme` as a dotted place still is.
 */
function componentKeys(expr: Expr, env: Env, engine: Engine, frame: Frame): Expr[] {
  if (expr.k === "attr" && (dotted(expr) ?? "()").includes("()") && engine.eval(expr.value, env, frame).tags.has("parsed-url")) return [];
  return keysOf(expr);
}

/** The literal strings a `startswith`/`endswith` argument tests: one, or a tuple of them. */
function prefixes(expr: Expr): string[] {
  const single = constString(expr);
  if (single !== null) return [single];
  if (expr.k === "tuple" || expr.k === "list") {
    const values = expr.elts.map((element) => constString(element));
    return values.every((value): value is string => value !== null) ? values : [];
  }
  return [];
}

/** `parsed.hostname`, `urlsplit(url).netloc`: the authority of a parsed URL. Not its scheme. */
function hostAttribute(expr: Expr, env: Env, engine: Engine, frame: Frame): boolean {
  if (expr.k !== "attr" || !/^(netloc|hostname|host)$/.test(expr.attr)) return false;
  return engine.eval(expr.value, env, frame).tags.has("parsed-url");
}

/**
 * The host of a parsed URL tested against a fixed allow-list or a fixed host pins the
 * destination of the URL it was parsed from, so the URL itself is clean for both a
 * server-side request and a redirect.
 */
function pinnedHost(expr: Expr, env: Env, engine: Engine, frame: Frame): Facts {
  if (!hostAttribute(expr, env, engine, frame)) return [];
  return namesOf((expr as Extract<Expr, { k: "attr" }>).value).map((name) => ({ expr: name, clean: new Set<SinkClass>(["ssrf", "redirect"]) }));
}

/** This application's own host: `request.host`, or the authority of `request.host_url` parsed. */
function isOwnHost(expr: Expr, env: Env, engine: Engine, frame: Frame): boolean {
  const name = dotted(expr) ?? "";
  if (/(^|\.)request\.(host|server_name)$|(^|\.)request\.(url|base_url)\.(hostname|netloc)$/.test(name)) return true;
  if (expr.k !== "attr" || !/^(netloc|hostname|host)$/.test(expr.attr)) return false;
  const base = expr.value;
  if (base.k === "call") return base.args.some((arg) => /(^|\.)request\.(host_url|url_root|base_url|host)$/.test(dotted(arg) ?? ""));
  if (base.k !== "name") return false;
  const bound = frame.fn ? lastAssignment(frame.fn.body, base.id) : null;
  return Boolean(bound && bound.k === "call" && bound.args.some((arg) => /(^|\.)request\.(host_url|url_root|base_url|host)$/.test(dotted(arg) ?? "")) && engine.eval(base, env, frame).tags.has("parsed-url"));
}

function lastAssignment(body: Stmt[], id: string): Expr | null {
  let found: Expr | null = null;
  walkStmts(body, (stmt) => {
    if (stmt.k === "assign" && stmt.value && stmt.targets.some((target) => target.k === "name" && target.id === id)) found = stmt.value;
  });
  return found;
}

/** The names a resolved address was computed from: the URL and host it came from. */
function resolvedFrom(expr: Expr, value: Value): Facts {
  const clean = new Set<SinkClass>(["ssrf"]);
  const names = new Set<string>([...value.deps, ...namesOf(expr).map((name) => (name as Extract<Expr, { k: "name" }>).id)]);
  return [...names].map((id) => ({ expr: { k: "name", id, span: expr.span } as Expr, clean }));
}

/** `urlparse(next_url).netloc` names `next_url`. */
function netlocOf(expr: Expr, env: Env, engine: Engine, frame: Frame): Expr[] | null {
  if (expr.k !== "attr" || !/^(netloc|hostname|host|scheme)$/.test(expr.attr)) return null;
  const base = engine.eval(expr.value, env, frame);
  if (!base.tags.has("parsed-url")) return null;
  return namesOf(expr.value);
}

/**
 * The places a fact is about. A name or a dotted attribute is itself the place;
 * anything else (a call on the value) is about every local name inside it.
 */
export function keysOf(expr: Expr): Expr[] {
  // `urlparse(url).hostname` is a fact about `url`, not about an attribute path.
  if (expr.k === "name" || (expr.k === "attr" && !(dotted(expr) ?? "()").includes("()"))) return [expr];
  return namesOf(expr);
}

export function namesOf(expr: Expr): Expr[] {
  const out: Expr[] = [];
  walkExpr(expr, (inner) => {
    if (inner.k === "name") out.push(inner);
  });
  // Callee names are not values.
  if (expr.k === "call" && expr.func.k === "name") return out.filter((name) => name !== expr.func);
  return out;
}

export function applyFacts(env: Env, facts: Facts, engine: Engine, frame: Frame): void {
  for (const fact of facts) {
    if (fact.clean.size === 0) continue;
    if (fact.expr.k === "name") {
      cleanName(env, fact.expr.id, fact.clean, engine, frame);
      continue;
    }
    const key = dotted(fact.expr);
    if (key && fact.expr.k === "attr") {
      env.set(key, withClean(engine.eval(fact.expr, env, frame), fact.clean));
    }
  }
}

/**
 * Clean a local name, the names it was computed from, and the names computed
 * from it. A check on `resolved` speaks for `name` when `resolved` was derived
 * from `name`, and for `full_path` when that was derived from `name` too.
 */
function cleanName(env: Env, id: string, clean: ReadonlySet<SinkClass>, engine: Engine, frame: Frame): void {
  const current: Value = env.get(id) ?? engine.eval({ k: "name", id, span: { line: 0, endLine: 0, from: 0, to: 0 } }, env, frame);
  env.set(id, withClean(current, clean));
  // Backwards only through resolution or URL parsing: a check on
  // `realpath(join(base, name))` is a check on `name`, but a check on
  // `name = body.filename` says nothing about the rest of `body`. A check on the host
  // of a parsed URL speaks for the URL only as a destination (where a request or a
  // redirect goes), and a check on any other component of it not at all.
  const backward: ReadonlySet<SinkClass> =
    current.tags.has("resolved-path") || current.tags.has("parsed-url")
      ? clean
      : current.tags.has("url-host")
        ? new Set([...clean].filter((sink) => sink === "ssrf" || sink === "redirect"))
        : new Set();
  const related = new Set<string>([id, ...(backward.size > 0 ? current.deps : [])]);
  for (const [key, value] of env) {
    if (key === id) continue;
    const forward = value.deps.has(id);
    if (!forward && !related.has(key) && ![...value.deps].some((dep) => related.has(dep))) continue;
    // Attribute overrides of a different value are left alone.
    if (key.includes(".") && !related.has(key.split(".")[0]!)) continue;
    env.set(key, withClean(value, forward || key.split(".")[0] === id ? clean : backward));
  }
}
