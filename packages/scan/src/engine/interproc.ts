/**
 * Inter-procedural taint: which parameters of which functions hold caller data because a
 * real call site handed it to them.
 *
 * The taint model in `ast/taint.ts` is intra-procedural, and that was a stated limit of
 * the product: a value that becomes attacker-controlled in a handler and is used in a
 * service, a repository, or a helper module was not connected. Three ad-hoc one-hop
 * bridges existed — in `rules/parsing.ts`, `rules/injection.ts` and `ast/call-sites.ts` —
 * each with its own resolver and each stopping after one call. This replaces the *reach*
 * of all three with one fixed point over the call graph, and leaves each of them in place
 * for what they still add.
 *
 * ## Where a chain may start
 *
 * Only in a function that receives caller data **by contract**: a handler registered with
 * a router or a server (`engine/handlers.ts`), an entry point an adapter recognised, or a
 * function whose parameter is typed as a request. The taint model also calls a parameter
 * the request when it is merely *named* `context` or `input`, which is a useful guess
 * inside one function and a poor foundation for a chain: measured on this repository, it
 * walked a CLI adapter's `context` object through three modules into an `execFile`.
 *
 * ## What is recorded, and the guard that keeps it honest
 *
 * The same contract `call-sites.ts` was built on, which an earlier widening was closed
 * with after it reported a validated executable path in this project's own source:
 * **observed, never inferred** (`engine/observed.ts`). A parameter is seeded only when a
 * call site that exists passes an argument the engine *reads* as caller-controlled there —
 * not one it merely assumes is, because an unknown function was handed caller data, and
 * not one the code has visibly validated. Each hop is the same observation one call
 * further on, so a chain of hops is a chain of observations.
 *
 * Further guards, each from a failure already measured in this repository:
 *
 *  - **The authenticated subject is not the caller's data** (`namesTheSubject`). A session
 *    handed to a service would otherwise unscope every ownership predicate built from it.
 *  - **Object arguments are seeded per property.** `load({ id: req.params.id, user:
 *    req.user })` taints `id` and leaves `user` alone.
 *  - **A command-line program's arguments are its operator's.** They are judged inside the
 *    handler that receives them, and not carried into every function the program calls.
 *  - **Fan-in marks a utility.** A parameter handed caller data from more than
 *    `maxCallerFiles` other files, or from more than `maxCallerFunctions` functions, is a
 *    general-purpose helper, and a finding attributed to it is a finding about none of its
 *    callers. Blocked parameters are removed and the propagation is rerun without them, so
 *    nothing a blocked seed caused survives.
 *  - **Bounded and deterministic.** At most `maxHops` calls from the handler, a fixed cap
 *    on re-examination, files in path order and calls in source order.
 */
import ts from "typescript";
import type { ParsedFile } from "../ast/parse.js";
import { analyzeFunction, type TaintScope } from "../ast/taint.js";
import { namesTheSubject } from "../ast/call-sites.js";
import { functionName } from "../ast/helpers.js";
import { entryPointForFunction } from "../ast/entrypoints.js";
import { observedOrigin } from "./observed.js";
import { resolveCall, isCallableBody, type CallTarget, type Invocation } from "./callgraph.js";
import { isRequestHandler, type RequestHandler } from "./handlers.js";
import type { ModuleGraph } from "./modules.js";

export const INTERPROCEDURAL_LIMITS = Object.freeze({
  /** Calls between the handler where the value entered and the furthest seeded parameter. */
  maxHops: 4,
  /** Distinct *other* files that may hand caller data to one parameter before it is a utility. */
  maxCallerFiles: 2,
  /** Distinct calling functions, anywhere, before a parameter is a utility. */
  maxCallerFunctions: 4,
  /** How many times one function may be re-examined as its seeds grow. */
  maxVisitsPerFunction: 6,
  /** How many times the whole propagation reruns after blocking utilities. */
  maxRestarts: 3,
  /** How many enclosing functions a nested callback may borrow a closure scope from. */
  maxClosureDepth: 4
});

/** `function node → parameter index → why it holds caller data`. */
export type ParameterSeeds = Map<ts.Node, Map<number, string>>;
/** `function node → parameter index → property → why`, for object-literal arguments. */
export type PropertySeeds = Map<ts.Node, Map<number, Map<string, string>>>;

export interface CallEdge {
  call: Invocation;
  target: CallTarget;
}

/** A call site that handed caller data to a function, kept so a finding can borrow its route. */
export interface SeedSite {
  file: ParsedFile;
  call: Invocation;
}

export interface InterproceduralResult {
  /** Resolved call edges, by calling function. */
  edges: Map<ts.Node, { file: ParsedFile; edges: CallEdge[] }>;
  /** Name-keyed view of the seeds per file, for rules that look parameters up by name. */
  byName: Map<string, Map<string, Map<number, string>>>;
  /** Parameters refused as utilities, as `file:line:name#index`, for diagnostics. */
  blocked: string[];
  /** For each seeded function, the call sites that seeded it, in discovery order. */
  seedSites: Map<ts.Node, SeedSite[]>;
  stats: { calls: number; resolved: number; seededFunctions: number; restarts: number };
}

export interface PropagationOptions {
  /** Request handlers by function node, from `engine/handlers.ts`. */
  handlers?: ReadonlyMap<ts.Node, RequestHandler>;
}

interface Observation {
  origin: string;
  hops: number;
}

/** Who filled one parameter, whole or by property — the fan-in test reads this. */
interface FanIn {
  callerFiles: Set<string>;
  callerFunctions: Set<ts.Node>;
}

interface RunState {
  seeds: Map<ts.Node, Map<number, Observation>>;
  properties: Map<ts.Node, Map<number, Map<string, Observation>>>;
  fanIn: Map<ts.Node, Map<number, FanIn>>;
  sites: Map<ts.Node, SeedSite[]>;
}

/** Origins that name the program's own operator rather than a remote caller. */
const OPERATOR_INPUT = /\(command-line (argument|input)\)/;

/** At most this many seeding call sites are kept per function. */
const MAX_SEED_SITES = 8;

function unwrap(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAwaitExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

function isCallable(node: ts.Node): boolean {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  );
}

function enclosingCallable(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (isCallable(current)) return current;
    current = current.parent;
  }
  return undefined;
}

/** `fn` and the functions lexically enclosing it, innermost first. */
function closureChain(fn: ts.Node): ts.Node[] {
  const chain = [fn];
  let current = enclosingCallable(fn);
  while (current && chain.length <= INTERPROCEDURAL_LIMITS.maxClosureDepth) {
    chain.push(current);
    current = enclosingCallable(current);
  }
  return chain;
}

function contains(outer: ts.Node, inner: ts.Node): boolean {
  return inner.pos >= outer.pos && inner.end <= outer.end;
}

function targetLabel(target: CallTarget): string {
  if (ts.isConstructorDeclaration(target.fn)) {
    const owner = target.fn.parent;
    return owner.name ? `new ${owner.name.text}` : "constructor";
  }
  return functionName(target.fn) ?? "an anonymous function";
}

/** Every resolved call with at least one argument, grouped by the function that makes it. */
function collectEdges(graph: ModuleGraph, files: readonly ParsedFile[]): {
  edges: Map<ts.Node, { file: ParsedFile; edges: CallEdge[] }>;
  calls: number;
} {
  const edges = new Map<ts.Node, { file: ParsedFile; edges: CallEdge[] }>();
  let calls = 0;
  for (const file of files) {
    const visit = (node: ts.Node): void => {
      if ((ts.isCallExpression(node) || ts.isNewExpression(node)) && (node.arguments?.length ?? 0) > 0) {
        calls += 1;
        const target = resolveCall(graph, file, node);
        if (target) {
          const caller = enclosingCallable(node) ?? file.source;
          // A recursive call proves nothing about where the value came from.
          if (target.fn !== caller && !(target.file === file && contains(target.fn, node))) {
            const entry = edges.get(caller) ?? { file, edges: [] };
            entry.edges.push({ call: node, target });
            edges.set(caller, entry);
          }
        }
      }
      node.forEachChild(visit);
    };
    visit(file.source);
  }
  return { edges, calls };
}

export function propagateTaint(graph: ModuleGraph, files: readonly ParsedFile[], options: PropagationOptions = {}): InterproceduralResult {
  const ordered = [...files].sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  const { edges, calls } = collectEdges(graph, ordered);
  const fileOf = new Map<ts.Node, ParsedFile>();
  for (const file of ordered) fileOf.set(file.source, file);
  for (const [caller, entry] of edges) {
    fileOf.set(caller, entry.file);
    for (const edge of entry.edges) fileOf.set(edge.target.fn, edge.target.file);
  }
  const handlers = options.handlers ?? new Map<ts.Node, RequestHandler>();

  const blocked = new Set<string>();
  const keyOf = (fn: ts.Node, index: number) => `${fileOf.get(fn)?.relativePath ?? "?"}:${fn.pos}:${index}`;
  const blockedLabels: string[] = [];

  let final: RunState | null = null;
  let restarts = 0;

  for (; restarts <= INTERPROCEDURAL_LIMITS.maxRestarts; restarts += 1) {
    const state = run(edges, fileOf, handlers, blocked, keyOf);
    const newlyBlocked: Array<[ts.Node, number]> = [];
    for (const [fn, byIndex] of state.fanIn) {
      const own = fileOf.get(fn)?.relativePath;
      for (const [index, fanIn] of byIndex) {
        const otherFiles = [...fanIn.callerFiles].filter((path) => path !== own).length;
        if (
          otherFiles > INTERPROCEDURAL_LIMITS.maxCallerFiles ||
          fanIn.callerFunctions.size > INTERPROCEDURAL_LIMITS.maxCallerFunctions
        ) {
          newlyBlocked.push([fn, index]);
        }
      }
    }
    if (newlyBlocked.length === 0 || restarts === INTERPROCEDURAL_LIMITS.maxRestarts) {
      // On the last permitted round, drop the over-limit seeds rather than keep them.
      for (const [fn, index] of newlyBlocked) {
        state.seeds.get(fn)?.delete(index);
        state.properties.get(fn)?.delete(index);
      }
      final = state;
      break;
    }
    for (const [fn, index] of newlyBlocked) {
      const key = keyOf(fn, index);
      if (blocked.has(key)) continue;
      blocked.add(key);
      const file = fileOf.get(fn);
      const line = file ? file.source.getLineAndCharacterOfPosition(fn.getStart(file.source)).line + 1 : 0;
      blockedLabels.push(`${file?.relativePath ?? "?"}:${line}:${functionName(fn) ?? "anonymous"}#${index}`);
    }
  }

  // Commit the final seeds onto the files, where `analyzeFunction` reads them.
  const byName = new Map<string, Map<string, Map<number, string>>>();
  let seededFunctions = 0;
  for (const file of files) {
    delete file.parameterSeeds;
    delete file.propertySeeds;
  }
  for (const [fn, byIndex] of final?.seeds ?? []) {
    if (byIndex.size === 0) continue;
    const file = fileOf.get(fn);
    if (!file) continue;
    seededFunctions += 1;
    const seeds = (file.parameterSeeds ??= new Map());
    const origins = new Map<number, string>();
    for (const [index, observation] of byIndex) origins.set(index, observation.origin);
    seeds.set(fn, origins);
    const name = functionName(fn);
    if (name) {
      const forFile = byName.get(file.relativePath) ?? new Map<string, Map<number, string>>();
      const forName = forFile.get(name) ?? new Map<number, string>();
      for (const [index, origin] of origins) if (!forName.has(index)) forName.set(index, origin);
      forFile.set(name, forName);
      byName.set(file.relativePath, forFile);
    }
  }
  for (const [fn, byIndex] of final?.properties ?? []) {
    const file = fileOf.get(fn);
    if (!file) continue;
    const seeds = (file.propertySeeds ??= new Map());
    const forFn = new Map<number, Map<string, string>>();
    for (const [index, properties] of byIndex) {
      if (properties.size === 0) continue;
      forFn.set(index, new Map([...properties].map(([name, observation]) => [name, observation.origin])));
    }
    if (forFn.size > 0) seeds.set(fn, forFn);
  }

  let resolved = 0;
  for (const entry of edges.values()) resolved += entry.edges.length;
  const seedSites = new Map<ts.Node, SeedSite[]>();
  for (const [fn, sites] of final?.sites ?? []) {
    const stillSeeded = (final?.seeds.get(fn)?.size ?? 0) > 0 || (final?.properties.get(fn)?.size ?? 0) > 0;
    if (stillSeeded) seedSites.set(fn, sites);
  }
  return { edges, byName, blocked: blockedLabels, seedSites, stats: { calls, resolved, seededFunctions, restarts } };
}

function run(
  edges: Map<ts.Node, { file: ParsedFile; edges: CallEdge[] }>,
  fileOf: Map<ts.Node, ParsedFile>,
  handlers: ReadonlyMap<ts.Node, RequestHandler>,
  blocked: Set<string>,
  keyOf: (fn: ts.Node, index: number) => string
): RunState {
  const seeds = new Map<ts.Node, Map<number, Observation>>();
  const properties = new Map<ts.Node, Map<number, Map<string, Observation>>>();
  const fanIn = new Map<ts.Node, Map<number, FanIn>>();
  const sites = new Map<ts.Node, SeedSite[]>();
  const scopes = new Map<ts.Node, TaintScope>();
  const visits = new Map<ts.Node, number>();

  // Start from nothing: `analyzeFunction` reads the live seeds off each file.
  for (const file of new Set(fileOf.values())) {
    delete file.parameterSeeds;
    delete file.propertySeeds;
  }

  /** The file a function lives in, for functions only reached as a closure. */
  const owner = (fn: ts.Node): ParsedFile | undefined => fileOf.get(fn) ?? fileOf.get(fn.getSourceFile());

  /** Does this function receive caller data by contract (hop 0)? */
  const contractual = new Map<ts.Node, boolean>();
  const byContract = (fn: ts.Node): boolean => {
    let answer = contractual.get(fn);
    if (answer === undefined) {
      const file = owner(fn);
      answer = file ? isRequestHandler(file, fn, handlers) : false;
      contractual.set(fn, answer);
    }
    return answer;
  };
  const isOperatorEntry = (fn: ts.Node): boolean => {
    const file = owner(fn);
    return file ? entryPointForFunction(file, fn)?.kind === "cli" : false;
  };

  const publish = (fn: ts.Node): void => {
    const file = owner(fn);
    if (!file) return;
    const byIndex = seeds.get(fn);
    if (byIndex && byIndex.size > 0) {
      const map = (file.parameterSeeds ??= new Map());
      map.set(fn, new Map([...byIndex].map(([index, observation]) => [index, observation.origin])));
    }
    const byProperty = properties.get(fn);
    if (byProperty && byProperty.size > 0) {
      const map = (file.propertySeeds ??= new Map());
      map.set(
        fn,
        new Map([...byProperty].map(([index, props]) => [index, new Map([...props].map(([k, v]) => [k, v.origin]))]))
      );
    }
    // Its own scope, and the scopes of everything nested in it, have changed.
    for (const cached of [...scopes.keys()]) if (cached === fn || contains(fn, cached)) scopes.delete(cached);
  };

  const scopeOf = (fn: ts.Node): TaintScope | null => {
    let scope = scopes.get(fn);
    if (!scope) {
      const file = owner(fn);
      if (!file) return null;
      scope = analyzeFunction(file, fn);
      scopes.set(fn, scope);
    }
    return scope;
  };

  /** Hops from a handler to this function: 0 for a handler, else its nearest seed. */
  const hopsOf = (fn: ts.Node): number => {
    if (byContract(fn)) return 0;
    let best = Number.POSITIVE_INFINITY;
    for (const observation of seeds.get(fn)?.values() ?? []) best = Math.min(best, observation.hops);
    for (const props of properties.get(fn)?.values() ?? []) {
      for (const observation of props.values()) best = Math.min(best, observation.hops);
    }
    return best;
  };

  const tally = (fn: ts.Node, index: number, file: ParsedFile, caller: ts.Node): void => {
    const byIndex = fanIn.get(fn) ?? new Map<number, FanIn>();
    const record = byIndex.get(index) ?? { callerFiles: new Set<string>(), callerFunctions: new Set<ts.Node>() };
    record.callerFiles.add(file.relativePath);
    record.callerFunctions.add(caller);
    byIndex.set(index, record);
    fanIn.set(fn, byIndex);
  };

  // Callers whose closure chain includes a function: re-examined when it gains a seed.
  const dependants = new Map<ts.Node, ts.Node[]>();
  for (const caller of edges.keys()) {
    for (const fn of closureChain(caller)) {
      const list = dependants.get(fn) ?? [];
      list.push(caller);
      dependants.set(fn, list);
    }
  }

  const queue: ts.Node[] = [...edges.keys()];
  const queued = new Set<ts.Node>(queue);
  const enqueue = (fn: ts.Node): void => {
    for (const caller of dependants.get(fn) ?? []) {
      if (queued.has(caller)) continue;
      queue.push(caller);
      queued.add(caller);
    }
  };

  while (queue.length > 0) {
    const caller = queue.shift()!;
    queued.delete(caller);
    const count = (visits.get(caller) ?? 0) + 1;
    if (count > INTERPROCEDURAL_LIMITS.maxVisitsPerFunction) continue;
    visits.set(caller, count);

    const entry = edges.get(caller)!;
    /*
     * The scopes this call can see caller data in: its own function, and the functions
     * enclosing it, for a callback reading a handler's request through a closure. Only
     * those that receive caller data by contract or by an earlier hop may start a chain.
     */
    const candidates = closureChain(caller)
      .filter((fn) => !isOperatorEntry(fn))
      .filter((fn) => byContract(fn) || seeds.has(fn) || properties.has(fn));
    if (candidates.length === 0) continue;

    for (const edge of entry.edges) {
      const targetFn = edge.target.fn;
      const parameters = targetFn.parameters;
      let changed = false;
      const crossFile = edge.target.file.relativePath !== entry.file.relativePath;
      const label = targetLabel(edge.target);
      const describe = (origin: string, bound: string) =>
        `${origin}, handed to \`${label}\` as \`${bound}\`${crossFile ? ` from ${entry.file.relativePath}` : ""}`;
      const boundName = (index: number): string => {
        const parameter = parameters[index];
        return parameter && ts.isIdentifier(parameter.name) ? parameter.name.text : `argument ${index + 1}`;
      };

      const record = (index: number, property: string | null, origin: string, hops: number): void => {
        tally(targetFn, index, entry.file, caller);
        const known = sites.get(targetFn) ?? [];
        if (known.length < MAX_SEED_SITES && !known.some((site) => site.call === edge.call)) {
          known.push({ file: entry.file, call: edge.call });
          sites.set(targetFn, known);
        }
        if (property === null) {
          const byIndex = seeds.get(targetFn) ?? new Map<number, Observation>();
          const existing = byIndex.get(index);
          if (!existing) {
            byIndex.set(index, { origin: describe(origin, boundName(index)), hops });
            changed = true;
          } else if (hops < existing.hops) {
            existing.hops = hops;
            changed = true;
          }
          seeds.set(targetFn, byIndex);
          return;
        }
        const byIndex = properties.get(targetFn) ?? new Map<number, Map<string, Observation>>();
        const byName = byIndex.get(index) ?? new Map<string, Observation>();
        const existing = byName.get(property);
        if (!existing) {
          byName.set(property, { origin: describe(origin, property), hops });
          changed = true;
        } else if (hops < existing.hops) {
          existing.hops = hops;
          changed = true;
        }
        byIndex.set(index, byName);
        properties.set(targetFn, byIndex);
      };

      /** The first scope in the chain that reads this expression as caller data. */
      const originOf = (expression: ts.Node): { origin: string; hops: number } | null => {
        for (const fn of candidates) {
          const hops = hopsOf(fn) + 1;
          if (!Number.isFinite(hops) || hops > INTERPROCEDURAL_LIMITS.maxHops) continue;
          const scope = scopeOf(fn);
          if (!scope) continue;
          const origin = observedOrigin(expression, scope);
          if (origin && !OPERATOR_INPUT.test(origin)) return { origin, hops };
          if (origin) return null;
        }
        return null;
      };

      (edge.call.arguments ?? []).forEach((argument, index) => {
        if (ts.isSpreadElement(argument)) return;
        const parameter = parameters[index];
        if (!parameter || parameter.dotDotDotToken) return;
        if (blocked.has(keyOf(targetFn, index))) return;
        if (namesTheSubject(argument)) return;

        const whole = originOf(argument);
        if (whole) {
          record(index, null, whole.origin, whole.hops);
          return;
        }

        // `load({ id: req.params.id, user: req.user })` — seed the property, not the object.
        const bare = unwrap(argument);
        if (!ts.isObjectLiteralExpression(bare)) return;
        for (const property of bare.properties) {
          let name: string | null = null;
          let value: ts.Node | null = null;
          if (ts.isPropertyAssignment(property) && (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))) {
            name = property.name.text;
            value = property.initializer;
          } else if (ts.isShorthandPropertyAssignment(property)) {
            name = property.name.text;
            value = property.name;
          }
          if (!name || !value || namesTheSubject(value)) continue;
          const found = originOf(value);
          if (found) record(index, name, found.origin, found.hops);
        }
      });

      if (changed) {
        publish(targetFn);
        if (isCallableBody(targetFn)) enqueue(targetFn);
      }
    }
  }

  return { seeds, properties, fanIn, sites };
}
