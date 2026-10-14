import type { ClassDef, Expr } from "../syntax/ast.js";
import { constString, dotted, keyword, walkStmts } from "../syntax/ast.js";
import { ALL_SINKS, type FieldInfo, type ModelInfo, type SinkClass } from "../analysis/values.js";
import type { Project, PyModule } from "./modules.js";

/**
 * Declared types as evidence.
 *
 * FastAPI and Pydantic validate a request against its annotations before the
 * handler runs, so `order_id: int` is a promise that the value is an integer by
 * the time anything reads it. A scanner that ignores that reports injection
 * through every integer path parameter in the application. A scanner that
 * believes it too readily misses `str` fields hiding inside a model. This file
 * is where that judgement is made, once.
 */

const NONE: ReadonlySet<SinkClass> = new Set();

/** Types whose values cannot carry markup, quotes, separators or a URL. */
const SCALAR_TYPES = new Set([
  "int",
  "float",
  "bool",
  "complex",
  "Decimal",
  "UUID",
  "UUID1",
  "UUID3",
  "UUID4",
  "UUID5",
  "datetime",
  "date",
  "time",
  "timedelta",
  "PositiveInt",
  "NegativeInt",
  "NonNegativeInt",
  "NonPositiveInt",
  "PositiveFloat",
  "NonNegativeFloat",
  "StrictInt",
  "StrictFloat",
  "StrictBool",
  "conint",
  "confloat",
  "condecimal",
  "IPvAnyAddress",
  "IPv4Address",
  "IPv6Address",
  "PastDate",
  "FutureDate",
  "AwareDatetime",
  "NaiveDatetime"
]);

/** Framework-injected parameters that are not request data. */
const INJECTED_TYPES = new Set([
  "Response",
  "BackgroundTasks",
  "Session",
  "AsyncSession",
  "Connection",
  "AsyncConnection",
  "SecurityScopes",
  "Engine",
  "Redis",
  "Settings",
  "Logger"
]);

const REQUEST_TYPES = new Set(["Request", "WebSocket", "HTTPConnection"]);

export interface AnnotationInfo {
  clean: ReadonlySet<SinkClass>;
  model?: ModelInfo;
  request?: boolean;
  upload?: boolean;
  injected?: boolean;
  /** `Annotated[T, Depends(fn)]` — the dependency expression. */
  dependency?: Expr;
  /** `Annotated[str, Query(...)]` and friends — the marker call. */
  marker?: Extract<Expr, { k: "call" }>;
  /** Whether the declared type was recognised at all. */
  known: boolean;
}

const MARKERS = new Set(["Query", "Path", "Body", "Header", "Cookie", "Form", "File"]);

export function markerName(expr: Expr | null | undefined): string | null {
  if (!expr || expr.k !== "call") return null;
  const name = expr.func.k === "name" ? expr.func.id : expr.func.k === "attr" ? expr.func.attr : null;
  return name && (MARKERS.has(name) || name === "Depends" || name === "Security") ? name : null;
}

export class TypeReader {
  private readonly models = new Map<ClassDef, ModelInfo | null>();

  constructor(private readonly project: Project) {}

  annotation(module: PyModule, expr: Expr | null, depth = 0): AnnotationInfo {
    if (!expr || depth > 6) return { clean: NONE, known: false };
    switch (expr.k) {
      case "str":
        // A forward reference: `"Order"`.
        return this.annotation(module, { k: "name", id: expr.value, span: expr.span }, depth + 1);
      case "const":
        return { clean: ALL_SINKS, known: true };
      case "binop":
        // `str | None`
        if (expr.op === "|") return this.either(module, [expr.left, expr.right], depth);
        return { clean: NONE, known: false };
      case "call":
        return this.callAnnotation(module, expr);
      case "subscript":
        return this.genericAnnotation(module, expr, depth);
      case "name":
      case "attr":
        return this.namedAnnotation(module, expr, depth);
      default:
        return { clean: NONE, known: false };
    }
  }

  private either(module: PyModule, options: Expr[], depth: number): AnnotationInfo {
    const infos = options
      .filter((option) => !(option.k === "const" && option.value === null) && !(option.k === "name" && option.id === "None"))
      .map((option) => this.annotation(module, option, depth + 1));
    if (infos.length === 0) return { clean: ALL_SINKS, known: true };
    const clean = new Set<SinkClass>(ALL_SINKS);
    for (const info of infos) for (const sink of ALL_SINKS) if (!info.clean.has(sink)) clean.delete(sink);
    const first = infos[0]!;
    const out: AnnotationInfo = { clean, known: infos.every((info) => info.known) };
    if (first.model) out.model = first.model;
    if (first.request) out.request = true;
    if (first.upload) out.upload = true;
    if (first.injected) out.injected = true;
    return out;
  }

  private callAnnotation(module: PyModule, call: Extract<Expr, { k: "call" }>): AnnotationInfo {
    const name = call.func.k === "name" ? call.func.id : call.func.k === "attr" ? call.func.attr : "";
    if (/^con(int|float|decimal|date)$/.test(name)) return { clean: ALL_SINKS, known: true };
    if (name === "constr" || name === "StringConstraints") {
      const pattern = constString(keyword(call, "pattern") ?? keyword(call, "regex"));
      return { clean: pattern ? patternCleans(pattern) : NONE, known: true };
    }
    if (name === "conlist" || name === "conset") {
      const inner = call.args[0];
      return inner ? this.annotation(module, inner, 1) : { clean: NONE, known: false };
    }
    return { clean: NONE, known: false };
  }

  private genericAnnotation(module: PyModule, expr: Extract<Expr, { k: "subscript" }>, depth: number): AnnotationInfo {
    const head = dotted(expr.value)?.split(".").pop() ?? "";
    const args = expr.index ? (expr.index.k === "tuple" ? expr.index.elts : [expr.index]) : [];
    switch (head) {
      case "Optional":
        return args[0] ? this.annotation(module, args[0], depth + 1) : { clean: NONE, known: false };
      case "Union":
        return this.either(module, args, depth);
      case "Literal":
        return { clean: ALL_SINKS, known: true };
      case "list":
      case "List":
      case "set":
      case "Set":
      case "frozenset":
      case "FrozenSet":
      case "Sequence":
      case "tuple":
      case "Tuple":
        return args[0] ? this.annotation(module, args[0], depth + 1) : { clean: NONE, known: false };
      case "dict":
      case "Dict":
      case "Mapping":
        return { clean: NONE, known: true };
      case "Annotated": {
        const base = args[0] ? this.annotation(module, args[0], depth + 1) : { clean: NONE, known: false };
        const clean = new Set(base.clean);
        let marker: Extract<Expr, { k: "call" }> | undefined;
        let dependency: Expr | undefined;
        for (const extra of args.slice(1)) {
          if (extra.k !== "call") continue;
          const name = markerName(extra);
          if (name === "Depends" || name === "Security") {
            dependency = extra.args[0] ?? extra;
            continue;
          }
          if (name) marker = extra;
          const pattern = constString(keyword(extra, "pattern") ?? keyword(extra, "regex"));
          if (pattern) for (const sink of patternCleans(pattern)) clean.add(sink);
          const fieldName = extra.func.k === "name" ? extra.func.id : extra.func.k === "attr" ? extra.func.attr : "";
          if (fieldName === "StringConstraints" || fieldName === "Field") {
            const innerPattern = constString(keyword(extra, "pattern"));
            if (innerPattern) for (const sink of patternCleans(innerPattern)) clean.add(sink);
          }
        }
        const out: AnnotationInfo = { ...base, clean };
        if (marker) out.marker = marker;
        if (dependency) out.dependency = dependency;
        return out;
      }
      default:
        return { clean: NONE, known: false };
    }
  }

  private namedAnnotation(module: PyModule, expr: Expr, depth: number): AnnotationInfo {
    const name = expr.k === "name" ? expr.id : expr.k === "attr" ? expr.attr : "";
    if (SCALAR_TYPES.has(name)) return { clean: ALL_SINKS, known: true };
    if (name === "str" || name === "bytes" || name === "Any" || name === "EmailStr" || name === "SecretStr" || name === "Json") {
      return { clean: NONE, known: true };
    }
    if (/^(HttpUrl|AnyUrl|AnyHttpUrl|Url)$/.test(name)) return { clean: NONE, known: true };
    if (REQUEST_TYPES.has(name)) return { clean: NONE, known: true, request: true };
    if (name === "UploadFile") return { clean: NONE, known: true, upload: true };
    if (INJECTED_TYPES.has(name)) return { clean: ALL_SINKS, known: true, injected: true };

    // A project alias: `CurrentUser = Annotated[User, Depends(current_user)]`,
    // `SessionDep = Annotated[Session, Depends(get_session)]`, `Slug = constr(...)`.
    if (expr.k === "name") {
      const alias = this.project.constantValue(module, expr.id);
      if (alias && alias.expr.k !== "name") return this.annotation(alias.module, alias.expr, depth + 1);
    }

    const symbol = this.project.resolveExpr(module, expr);
    if (symbol?.kind === "class") {
      if (isEnumClass(this.project, symbol.module, symbol.cls)) return { clean: ALL_SINKS, known: true };
      const model = this.model(symbol.module, symbol.cls);
      if (model) return { clean: NONE, known: true, model };
      return { clean: NONE, known: false };
    }
    if (symbol?.kind === "external") {
      const tail = symbol.qualified.split(".").pop() ?? "";
      if (SCALAR_TYPES.has(tail)) return { clean: ALL_SINKS, known: true };
      if (/^sqlalchemy|^sqlmodel/.test(symbol.qualified)) return { clean: ALL_SINKS, known: true, injected: true };
    }
    return { clean: NONE, known: false };
  }

  /** Field-level knowledge of a Pydantic (or SQLModel / dataclass) model. */
  model(module: PyModule, cls: ClassDef, depth = 0): ModelInfo | null {
    if (this.models.has(cls)) return this.models.get(cls) ?? null;
    if (depth > 6) return null;
    this.models.set(cls, null);
    if (!isModelClass(this.project, module, cls)) return null;

    const fields = new Map<string, FieldInfo>();
    let complete = true;
    // Inherited fields first, so a subclass can narrow them.
    for (const base of cls.bases) {
      const symbol = this.project.resolveExpr(module, base);
      if (symbol?.kind === "class") {
        const inherited = this.model(symbol.module, symbol.cls, depth + 1);
        if (inherited) for (const [name, field] of inherited.fields) fields.set(name, field);
        else if (!/^(BaseModel|SQLModel|object)$/.test(symbol.cls.name)) complete = false;
      }
    }

    const validated = validatedFields(cls);
    for (const stmt of cls.body) {
      if (stmt.k !== "assign" || !stmt.annotation) continue;
      const target = stmt.targets[0];
      if (!target || target.k !== "name") continue;
      const info = this.annotation(module, stmt.annotation, depth + 1);
      const clean = new Set(info.clean);
      if (stmt.value?.k === "call") {
        const pattern = constString(keyword(stmt.value, "pattern") ?? keyword(stmt.value, "regex"));
        if (pattern) for (const sink of patternCleans(pattern)) clean.add(sink);
      }
      if (validated.has(target.id)) for (const sink of ALL_SINKS) clean.add(sink);
      const field: FieldInfo = { clean };
      if (info.model) field.model = info.model;
      fields.set(target.id, field);
    }
    const model: ModelInfo = { name: cls.name, fields, complete };
    this.models.set(cls, model);
    return model;
  }
}

/**
 * Fields a validator rejects unless they pass a membership or pattern test.
 *
 * Only a validator that can *refuse* counts: one that strips or lower-cases a
 * value and returns it has changed the value without constraining it.
 */
function validatedFields(cls: ClassDef): Set<string> {
  const out = new Set<string>();
  for (const stmt of cls.body) {
    if (stmt.k !== "funcdef") continue;
    const decorator = stmt.decorators.find((d) => {
      const name = dotted(d.expr.k === "call" ? d.expr.func : d.expr) ?? "";
      return /(^|\.)(field_validator|validator)$/.test(name);
    });
    if (!decorator || decorator.expr.k !== "call") continue;
    let refuses = false;
    let tests = false;
    walkStmts(stmt.body, (inner) => {
      if (inner.k === "raise") refuses = true;
      if (inner.k === "if" && inner.branches.some((branch) => branch.test && /\b(in|match|fullmatch|isdigit|isalnum)\b|not in/.test(JSON.stringify(branch.test)))) {
        tests = true;
      }
    });
    if (!refuses || !tests) continue;
    for (const arg of decorator.expr.args) {
      const name = constString(arg);
      if (name) out.add(name);
    }
  }
  return out;
}

export function isModelClass(project: Project, module: PyModule, cls: ClassDef, depth = 0): boolean {
  if (depth > 6) return false;
  if (cls.decorators.some((d) => /dataclass/.test(dotted(d.expr.k === "call" ? d.expr.func : d.expr) ?? ""))) return true;
  for (const base of cls.bases) {
    const name = dotted(base) ?? "";
    if (/(^|\.)(BaseModel|SQLModel|BaseSettings|RootModel|TypedDict|Schema)$/.test(name)) return true;
    const symbol = project.resolveExpr(module, base);
    if (symbol?.kind === "class" && isModelClass(project, symbol.module, symbol.cls, depth + 1)) return true;
    if (symbol?.kind === "external" && /(pydantic|sqlmodel|marshmallow)/.test(symbol.qualified)) return true;
  }
  return false;
}

export function isEnumClass(project: Project, module: PyModule, cls: ClassDef, depth = 0): boolean {
  if (depth > 6) return false;
  for (const base of cls.bases) {
    const name = dotted(base) ?? "";
    if (/(^|\.)(Enum|IntEnum|StrEnum|Flag|IntFlag)$/.test(name)) return true;
    const symbol = project.resolveExpr(module, base);
    if (symbol?.kind === "class" && isEnumClass(project, symbol.module, symbol.cls, depth + 1)) return true;
  }
  return false;
}

/* ------------------------------------------------------------- patterns */

/**
 * Which sinks a regular expression constraint makes a string safe for.
 *
 * Read conservatively. An unanchored pattern constrains nothing (`[a-z]+` matches
 * inside `a'; DROP TABLE x`), and a wildcard or a negated class admits every
 * character that matters. Otherwise the characters the pattern can match are
 * compared against what each sink needs: a quote for SQL, a shell metacharacter
 * for a command, a separator for a path, a scheme or host for a URL.
 */
export function patternCleans(pattern: string, fullMatch = false): ReadonlySet<SinkClass> {
  let body = pattern;
  const anchoredStart = /^(\^|\\A)/.test(body);
  const anchoredEnd = /(\$|\\Z|\\z)$/.test(body) && !/\\\$$/.test(body);
  if (!fullMatch && !(anchoredStart && anchoredEnd)) return NONE;
  body = body.replace(/^(\^|\\A)/, "").replace(/(\$|\\Z|\\z)$/, "");
  // Alternation at the top level makes the anchors apply to one branch only.
  if (!fullMatch && topLevelAlternation(body)) return NONE;

  const allowed = allowedCharacters(body);
  if (!allowed) return NONE;
  const admits = (characters: string) => [...characters].some((character) => allowed(character));

  const clean = new Set<SinkClass>();
  if (!admits(`'"; (\\`)) clean.add("sql");
  if (!admits(";|&$`<>()\n\r'\"\\")) clean.add("command");
  if (!admits("/\\")) clean.add("path");
  if (!admits(":/\\@")) clean.add("ssrf");
  if (!admits("{}%#'\"")) clean.add("template");
  if (!admits("/\\:")) clean.add("redirect");
  if (!admits("<>\"'")) clean.add("xss");
  return clean;
}

function topLevelAlternation(body: string): boolean {
  let depth = 0;
  let inClass = false;
  for (let index = 0; index < body.length; index += 1) {
    const character = body[index];
    if (character === "\\") {
      index += 1;
      continue;
    }
    if (inClass) {
      if (character === "]") inClass = false;
      continue;
    }
    if (character === "[") inClass = true;
    else if (character === "(") depth += 1;
    else if (character === ")") depth -= 1;
    else if (character === "|" && depth === 0) return true;
  }
  return false;
}

/** A predicate for "can this pattern match this character", or null for "anything". */
function allowedCharacters(body: string): ((character: string) => boolean) | null {
  const ranges: Array<[number, number]> = [];
  const add = (from: string, to = from) => ranges.push([from.charCodeAt(0), to.charCodeAt(0)]);
  const addClassEscape = (letter: string): boolean => {
    switch (letter) {
      case "w":
        add("a", "z");
        add("A", "Z");
        add("0", "9");
        add("_");
        return true;
      case "d":
        add("0", "9");
        return true;
      case "s":
        add(" ");
        add("\t");
        add("\n");
        add("\r");
        return true;
      case "S":
      case "W":
      case "D":
        return false;
      default:
        add(letter);
        return true;
    }
  };

  for (let index = 0; index < body.length; index += 1) {
    const character = body[index]!;
    if (character === "\\") {
      const next = body[index + 1] ?? "";
      index += 1;
      if (!addClassEscape(next)) return null;
      continue;
    }
    if (character === ".") return null;
    if (character === "[") {
      const close = findClassEnd(body, index);
      if (close === -1) return null;
      const content = body.slice(index + 1, close);
      if (content.startsWith("^")) return null;
      for (let inner = 0; inner < content.length; inner += 1) {
        const c = content[inner]!;
        if (c === "\\") {
          const next = content[inner + 1] ?? "";
          inner += 1;
          if (!addClassEscape(next)) return null;
          continue;
        }
        if (content[inner + 1] === "-" && inner + 2 < content.length && content[inner + 2] !== "]") {
          add(c, content[inner + 2]!);
          inner += 2;
          continue;
        }
        add(c);
      }
      index = close;
      continue;
    }
    if ("()?*+{}|,0123456789".includes(character) && /[(){}?*+|]/.test(character)) continue;
    if (character === "{" || character === "}") continue;
    add(character);
  }
  return (character: string) => {
    const code = character.charCodeAt(0);
    return ranges.some(([from, to]) => code >= from && code <= to);
  };
}

function findClassEnd(body: string, open: number): number {
  for (let index = open + 1; index < body.length; index += 1) {
    if (body[index] === "\\") {
      index += 1;
      continue;
    }
    if (body[index] === "]" && index > open + 1) return index;
  }
  return -1;
}
