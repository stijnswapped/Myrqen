import ts from "typescript";
import type { Candidate, CandidateEvidence } from "../types.js";
import type { ParsedFile } from "../ast/parse.js";
import { endLineOf, lineOf, snippetAround } from "../ast/parse.js";
import { enclosingFunction, expressionName, functionName } from "../ast/helpers.js";
import type { TaintScope } from "../ast/taint.js";

export interface RuleContext {
  file: ParsedFile;
  /** Route strings discovered in this file, used to attribute a sink. */
  routes: RouteHint[];
  report: (candidate: Candidate) => void;
}

export interface RouteHint {
  method: string;
  path: string;
  line: number;
  /** The node whose body implements the route, when one was identified. */
  node?: ts.Node;
}

export interface Rule {
  id: string;
  category: string;
  describes: string;
  /** Runs once per parsed file. */
  run: (context: RuleContext) => void;
}

/**
 * Attribute a sink to the closest route declared above it in the same file.
 * Imprecise by design: it is used to make evidence readable, never to decide
 * whether a finding exists.
 */
export function routeFor(context: RuleContext, node: ts.Node): string | undefined {
  const hint = routeHintFor(context, node);
  if (!hint) return undefined;
  return hint.method === "ANY" ? hint.path : `${hint.method} ${hint.path}`;
}

/**
 * The route a sink belongs to.
 *
 * Preference order, in the order a reader would reason:
 *
 *  1. A route whose own handler body contains the node. That is certain.
 *  2. The nearest route declared above it, which is right for inline handlers.
 *  3. The nearest route declared below it, which is right for a helper defined above
 *     the registrations — a common shape, and one that previously produced no route
 *     at all.
 *
 * A mount (`app.use("/embed", …)`) is consulted last: it is a prefix, not an answer
 * to "which endpoint is this".
 */
export function routeHintFor(context: RuleContext, node: ts.Node): RouteHint | undefined {
  const line = lineOf(context.file, node);
  const endpoints = context.routes.filter((hint) => hint.method !== "ANY");
  const mounts = context.routes.filter((hint) => hint.method === "ANY");

  const containing = endpoints.find((hint) => hint.node && containsNode(hint.node, node));
  if (containing) return containing;

  const above = (list: RouteHint[]) =>
    list.reduce<RouteHint | undefined>(
      (best, hint) => (hint.line <= line && (!best || hint.line > best.line) ? hint : best),
      undefined
    );
  const below = (list: RouteHint[]) =>
    list.reduce<RouteHint | undefined>(
      (best, hint) => (hint.line > line && (!best || hint.line < best.line) ? hint : best),
      undefined
    );

  return above(endpoints) ?? below(endpoints) ?? above(mounts) ?? below(mounts);
}

function containsNode(container: ts.Node, node: ts.Node): boolean {
  return node.getStart() >= container.getStart() && node.getEnd() <= container.getEnd();
}

export function locationOf(context: RuleContext, node: ts.Node) {
  const container = functionName(enclosingFunction(node));
  return {
    file: context.file.relativePath,
    line: lineOf(context.file, node),
    endLine: endLineOf(context.file, node),
    ...(container ? { container } : {})
  };
}

export function sourceEvidence(
  context: RuleContext,
  node: ts.Node,
  description: string
): CandidateEvidence {
  return {
    kind: "source",
    description,
    snippet: snippetAround(context.file, node),
    location: `${context.file.relativePath}:${lineOf(context.file, node)}`
  };
}

export function taintEvidence(origin: string, sink: string): CandidateEvidence {
  return {
    kind: "source",
    description: `Data flow: ${origin} reaches ${sink} in the same function with no validating guard between them.`
  };
}

export function describeSink(node: ts.CallExpression): string {
  return `${expressionName(node.expression)}()`;
}

export function taintScopeName(scope: TaintScope): string {
  return functionName(scope.fn) ?? "module scope";
}
