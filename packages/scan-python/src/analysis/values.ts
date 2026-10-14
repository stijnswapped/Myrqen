/**
 * What the analysis knows about a value.
 *
 * Taint is not a boolean here. A value can be attacker-chosen and still be safe
 * for a particular sink — an `int` path parameter cannot break out of a SQL
 * literal, a `shlex.quote`d word cannot start a second shell command, an
 * escaped string cannot open a tag — and the same value can be safe for one sink
 * and dangerous for another. So a tainted value carries the set of sink classes
 * it has been made safe for, and a sink fires only when its own class is absent.
 *
 * Merging two values (two branches, two operands of a concatenation) keeps every
 * origin and only the sink classes both were safe for: a string built from one
 * quoted part and one raw part is not quoted.
 */

export type SinkClass = "sql" | "command" | "path" | "ssrf" | "template" | "deserialization" | "redirect" | "xss";

export const ALL_SINKS: ReadonlySet<SinkClass> = new Set<SinkClass>([
  "sql",
  "command",
  "path",
  "ssrf",
  "template",
  "deserialization",
  "redirect",
  "xss"
]);

/**
 * `session` is a value read back from the server-side session. It is only attacker
 * data when some route stored attacker data under the same key, which is decided
 * once every route has been analysed (see `resolveSessionTaint`).
 *
 * `stored` is a field read back from a stored record (`note.body_html`). Like a
 * session value, it is attacker data only when some route wrote attacker data to a
 * record field of that name, and it is followed only to the sinks where stored data
 * is the classic defect: markup sent unescaped and template source.
 */
export type SourceKind = "path" | "query" | "body" | "header" | "cookie" | "form" | "file" | "request" | "session" | "stored";

export type Origin =
  | { kind: "source"; label: string; source: SourceKind; line: number; key?: string }
  | { kind: "param"; index: number; name: string };

export interface Taint {
  origins: readonly Origin[];
  clean: ReadonlySet<SinkClass>;
}

export type Tag =
  | "text-clause"
  | "resolved-path"
  | "path-object"
  | "parsed-url"
  /** The authority (`hostname`, `netloc`) of a parsed URL: a check on it pins where the URL goes. */
  | "url-host"
  | "http-client"
  | "request"
  | "const-collection"
  | "session-store"
  | "jinja-env"
  | "jinja-sandbox"
  /** An address the host name resolved to (`socket.getaddrinfo`), not the name itself. */
  | "resolved-address"
  | "signer"
  | "upload"
  /** A compiled regular expression (`re.compile(...)`): `.sub()` returns its subject edited. */
  | "regex"
  /** FastAPI/Starlette `Jinja2Templates`: `TemplateResponse(name, context)` renders a file. */
  | "jinja-templates";

export interface FieldInfo {
  clean: ReadonlySet<SinkClass>;
  model?: ModelInfo;
}

export interface ModelInfo {
  name: string;
  fields: Map<string, FieldInfo>;
  /** True when every field is known; otherwise an unknown attribute stays tainted. */
  complete: boolean;
}

export interface Value {
  taint: Taint | null;
  /** Local names this value was computed from, transitively. */
  deps: ReadonlySet<string>;
  tags: ReadonlySet<Tag>;
  /** Literal text the value is assembled from, for shape tests (is this SQL? HTML?). */
  text: string;
  /**
   * The literal text that precedes the first attacker-controlled part, when the
   * value is a composition. `https://api.partner.test/v1/` followed by an id is a
   * fixed destination; the same id followed by nothing is not.
   */
  prefix: string;
  model?: ModelInfo;
  /** A project class this value is an instance of, as `module:Class`. */
  instance?: { module: string; cls: string };
  /**
   * Per-attribute values of an object built in this project with keyword
   * arguments: `EmailData(subject=tainted, html=clean).html` is clean. Without
   * this, every attribute of an object inherits the taint of all of them.
   */
  fields?: ReadonlyMap<string, Value>;
  /**
   * Per-position values of a tuple or list literal: `return where, params` keeps the
   * SQL text apart from the bound values, so `where, params = build(args)` gives
   * `where` only what the text was built from.
   */
  elements?: readonly Value[];
  /**
   * A compiled template whose source is known: its text, and for a template written
   * in the code, where (so a finding can point at the line that marks a value safe).
   */
  template?: { text: string; module: unknown; line: number | null };
  /** Per-key values of a dict literal with string keys: a template context. */
  entryValues?: ReadonlyMap<string, Value>;
}

const EMPTY_SET: ReadonlySet<never> = new Set<never>();
const TEXT_LIMIT = 4000;

export const CLEAN: Value = Object.freeze({ taint: null, deps: EMPTY_SET, tags: EMPTY_SET, text: "", prefix: "" });

export function constant(text: string, tags: ReadonlySet<Tag> = EMPTY_SET): Value {
  return { taint: null, deps: EMPTY_SET, tags, text: text.slice(0, TEXT_LIMIT), prefix: text.slice(0, 200) };
}

export function sourceValue(origin: Origin, clean: ReadonlySet<SinkClass> = EMPTY_SET, extra: Partial<Value> = {}): Value {
  return { taint: { origins: [origin], clean }, deps: EMPTY_SET, tags: EMPTY_SET, text: "", prefix: "", ...extra };
}

export function originKey(origin: Origin): string {
  return origin.kind === "source" ? `s:${origin.label}:${origin.line}` : `p:${origin.index}`;
}

export function joinTaint(a: Taint | null, b: Taint | null): Taint | null {
  if (!a) return b;
  if (!b) return a;
  const origins = new Map<string, Origin>();
  for (const origin of [...a.origins, ...b.origins]) origins.set(originKey(origin), origin);
  const clean = new Set<SinkClass>();
  for (const sink of a.clean) if (b.clean.has(sink)) clean.add(sink);
  return { origins: [...origins.values()].slice(0, 12), clean };
}

function intersect<T>(a: ReadonlySet<T>, b: ReadonlySet<T>): ReadonlySet<T> {
  if (a.size === 0 || b.size === 0) return EMPTY_SET as ReadonlySet<T>;
  const out = new Set<T>();
  for (const item of a) if (b.has(item)) out.add(item);
  return out;
}

function union<T>(a: ReadonlySet<T>, b: ReadonlySet<T>): ReadonlySet<T> {
  if (a.size === 0) return b;
  if (b.size === 0) return a;
  return new Set([...a, ...b]);
}

/** Two alternatives for one value: either branch may have run. */
export function joinValues(a: Value, b: Value): Value {
  if (a === b) return a;
  const joined: Value = {
    taint: joinTaint(a.taint, b.taint),
    deps: union(a.deps, b.deps),
    tags: intersect(a.tags, b.tags),
    text: a.text === b.text ? a.text : `${a.text} ${b.text}`.slice(0, TEXT_LIMIT),
    prefix: a.prefix === b.prefix ? a.prefix : commonPrefix(a.prefix, b.prefix)
  };
  const model = a.model ?? b.model;
  if (model) joined.model = model;
  const instance = a.instance ?? b.instance;
  if (instance) joined.instance = instance;
  if (a.elements && b.elements && a.elements.length === b.elements.length) {
    joined.elements = a.elements.map((element, index) => joinValues(element, b.elements![index]!));
  }
  return joined;
}

/** Several values combined into one string or collection, in order. */
export function concatValues(values: readonly Value[], keepTags: ReadonlySet<Tag> = EMPTY_SET): Value {
  let taint: Taint | null = null;
  let deps: ReadonlySet<string> = EMPTY_SET;
  let text = "";
  let prefix = "";
  let prefixOpen = true;
  for (const value of values) {
    taint = joinTaint(taint, value.taint);
    deps = union(deps, value.deps);
    text = `${text}${value.text}`.slice(0, TEXT_LIMIT);
    if (prefixOpen) {
      prefix += value.taint ? "" : value.text;
      if (value.taint) prefixOpen = false;
    }
  }
  return { taint, deps, tags: keepTags, text, prefix: prefix.slice(0, 200) };
}

export function withClean(value: Value, sinks: Iterable<SinkClass>): Value {
  if (!value.taint) return value;
  const clean = new Set(value.taint.clean);
  for (const sink of sinks) clean.add(sink);
  return { ...value, taint: { origins: value.taint.origins, clean } };
}

export function withTags(value: Value, tags: Iterable<Tag>): Value {
  return { ...value, tags: union(value.tags, new Set(tags)) };
}

export function withDeps(value: Value, names: Iterable<string>): Value {
  return { ...value, deps: union(value.deps, new Set(names)) };
}

export function isTaintedFor(value: Value, sink: SinkClass): boolean {
  return Boolean(value.taint && !value.taint.clean.has(sink) && value.taint.origins.length > 0);
}

export function hasSourceOrigin(taint: Taint | null): boolean {
  return Boolean(taint?.origins.some((origin) => origin.kind === "source"));
}

function commonPrefix(a: string, b: string): string {
  let index = 0;
  while (index < a.length && index < b.length && a[index] === b[index]) index += 1;
  return a.slice(0, index);
}

/** A human description of where a value came from, for the report. */
export function describeOrigins(taint: Taint | null): string {
  if (!taint) return "an unknown source";
  const sources = taint.origins.filter((origin): origin is Extract<Origin, { kind: "source" }> => origin.kind === "source");
  if (sources.length === 0) return "a caller-supplied parameter";
  return [...new Set(sources.map((origin) => origin.label))].slice(0, 3).join(", ");
}
