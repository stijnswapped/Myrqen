import ts from "typescript";
import type { ParsedFile } from "./parse.js";

/**
 * Entry points: where caller-controlled data enters the application.
 *
 * The engine used to know exactly one shape of entry point — an Express-style
 * `app.get("/x", handler)` registration, plus a few dialects of it. Everything
 * else was invisible, and invisibility is total: with no entry point there is no
 * request parameter, with no request parameter there is no taint, and with no
 * taint every data-flow rule in the engine stays silent on a file that is full
 * of defects.
 *
 * An entry point is therefore not only a route label for the report. It is the
 * declaration of which bindings inside a handler hold data the caller chose, and
 * which bindings only look like they do.
 */

export type EntryPointKind =
  /** Reachable over HTTP by a URL. */
  | "http"
  /** Addressed by procedure name rather than by path. */
  | "rpc"
  /** An inter-process channel, such as an Electron renderer calling the main process. */
  | "ipc"
  /** A job taken off a queue whose payload an outside party influenced. */
  | "queue"
  /** A command-line invocation. */
  | "cli"
  /** A framework action invoked by a form or a client component. */
  | "action";

/** A binding inside a handler that holds caller-controlled data. */
export interface TaintSeed {
  /** The local binding name. */
  name: string;
  /** Human-readable origin, used verbatim in evidence. */
  origin: string;
}

export interface EntryPoint {
  /** Which adapter recognised this, for coverage reporting. */
  framework: string;
  kind: EntryPointKind;
  /** HTTP verb, or `INVOKE`, `CONSUME`, `RUN` for non-HTTP kinds. `ANY` when unknown. */
  method: string;
  /** Route path, channel name, queue name, or command name. */
  path: string;
  line: number;
  /** The function whose body implements this entry point. */
  node?: ts.Node;
  /**
   * Bindings inside `node` that hold caller data, named explicitly because the
   * generic parameter-name model cannot see them: a NestJS `@Param('id') id` is
   * an ordinary-looking string parameter, and a BullMQ `job` is not called `req`.
   */
  seeds?: TaintSeed[];
  /**
   * Parameters the generic model would call caller data and which are not.
   * An Electron `IpcMainInvokeEvent` is named `event` and carries the *sender*,
   * not the payload; treating it as attacker data would invent flows that the
   * renderer never controls.
   */
  trustedParameters?: string[];
  /**
   * Free functions that return caller data when called with this entry point's
   * request object, such as h3's `getQuery(event)`. Recorded per entry point
   * because the same name means nothing in a file that does not use h3.
   */
  accessorFunctions?: string[];
  /**
   * Expressions declared alongside the handler that gate it: a `preHandler` array, a
   * `policies` list, a `middleware` option.
   *
   * Recorded because ignoring it produces a *false claim*, not a missed finding. A
   * registration written as `{ preHandler: [authenticate, requireRole("manager")], handler }`
   * puts nothing in the handler body, so a rule asking "does this endpoint authenticate"
   * and looking only at the body answers no — and says so confidently about code that
   * gates itself twice. The mutation ratchet caught exactly that the first time the
   * generic adapter claimed a Fastify route whose instance had been renamed.
   */
  gate?: ts.Node[];
}

export interface FrameworkAdapter {
  id: string;
  /** A cheap text pre-check, so 40 adapters do not each walk every AST. */
  applies: (file: ParsedFile) => boolean;
  detect: (file: ParsedFile) => EntryPoint[];
}

const adapters: FrameworkAdapter[] = [];

/** Registered once at module load by `./frameworks/index.js`. */
export function registerAdapter(adapter: FrameworkAdapter): void {
  if (adapters.some((existing) => existing.id === adapter.id)) return;
  adapters.push(adapter);
}

export function registeredAdapters(): readonly FrameworkAdapter[] {
  return adapters;
}

const cache = new WeakMap<ts.SourceFile, EntryPoint[]>();

/**
 * Every entry point in this file, computed once and memoised on the source file.
 *
 * Route discovery and taint analysis both need this, and they run at different
 * times from different call sites, so the memo lives with the parsed file rather
 * than being threaded through every rule's signature.
 */
export function entryPointsOf(file: ParsedFile): EntryPoint[] {
  const cached = cache.get(file.source);
  if (cached) return cached;

  const found: EntryPoint[] = [];
  for (const adapter of adapters) {
    let applies = false;
    try {
      applies = adapter.applies(file);
    } catch {
      applies = false;
    }
    if (!applies) continue;
    try {
      found.push(...adapter.detect(file));
    } catch {
      // An adapter that throws must not take the scan down with it. The gap
      // shows up as a missing entry point, which the coverage note already
      // reports, rather than as a lost file.
    }
  }

  found.sort((a, b) => a.line - b.line);
  cache.set(file.source, found);
  return found;
}

/** The entry point whose handler is exactly this function, if any. */
export function entryPointForFunction(file: ParsedFile, fn: ts.Node): EntryPoint | undefined {
  return entryPointsOf(file).find((entry) => entry.node === fn);
}

/** Frameworks recognised in this file, for the coverage section of a report. */
export function frameworksIn(file: ParsedFile): string[] {
  return [...new Set(entryPointsOf(file).map((entry) => entry.framework))].sort();
}

/* ---------- helpers shared by the adapters ---------- */

/** Does this file import anything from one of these modules? */
export function importsFrom(file: ParsedFile, pattern: RegExp): boolean {
  for (const statement of file.source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      if (pattern.test(statement.moduleSpecifier.text)) return true;
    }
    if (ts.isImportEqualsDeclaration(statement)) {
      const reference = statement.moduleReference;
      if (ts.isExternalModuleReference(reference) && reference.expression && ts.isStringLiteralLike(reference.expression)) {
        if (pattern.test(reference.expression.text)) return true;
      }
    }
  }
  // `const { Worker } = require("bullmq")` is the same dependency written the
  // other way, and half of the Node code in the world is written that way.
  for (const call of allCalls(file)) {
    if (call.expression.getText(file.source) !== "require") continue;
    const first = call.arguments[0];
    if (first && ts.isStringLiteralLike(first) && pattern.test(first.text)) return true;
  }
  return false;
}

let callCache = new WeakMap<ts.SourceFile, ts.CallExpression[]>();

export function allCalls(file: ParsedFile): ts.CallExpression[] {
  const cached = callCache.get(file.source);
  if (cached) return cached;
  const calls: ts.CallExpression[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) calls.push(node);
    node.forEachChild(visit);
  };
  visit(file.source);
  callCache.set(file.source, calls);
  return calls;
}

/** Reset memoisation. Only used by tests that reparse the same text. */
export function resetEntryPointCaches(): void {
  callCache = new WeakMap();
}

/** The function-like node an argument or initialiser resolves to, if any. */
export function functionOf(node: ts.Node | undefined): ts.Node | undefined {
  if (!node) return undefined;
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node)) return node;
  if (ts.isMethodDeclaration(node)) return node;
  if (ts.isParenthesizedExpression(node)) return functionOf(node.expression);
  if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) return functionOf(node.expression);
  return undefined;
}

/** Parameter names of a function-like node, in order, skipping patterns. */
export function parameterNames(fn: ts.Node | undefined): Array<string | null> {
  const parameters = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters;
  if (!parameters) return [];
  return parameters.map((parameter) => (ts.isIdentifier(parameter.name) ? parameter.name.text : null));
}

/** A string literal argument, or null when the argument is computed. */
export function stringArgument(call: ts.CallExpression, index: number): string | null {
  const argument = call.arguments[index];
  if (!argument) return null;
  if (ts.isStringLiteralLike(argument)) return argument.text;
  if (ts.isNoSubstitutionTemplateLiteral(argument)) return argument.text;
  return null;
}

/** `/a//b/` becomes `/a/b`; an empty result becomes `/`. */
export function joinRoute(...parts: Array<string | null | undefined>): string {
  const joined = parts
    .filter((part): part is string => Boolean(part))
    .map((part) => part.replace(/^\/+|\/+$/g, ""))
    .filter((part) => part.length > 0)
    .join("/");
  return joined.length === 0 ? "/" : `/${joined}`;
}
