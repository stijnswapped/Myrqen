/**
 * Which parameters of which exported functions are handed caller data, by a call in
 * another file.
 *
 * Taint analysis here is intra-procedural, and `parameterTaintAt` in
 * `rules/parsing.ts` already crosses one call boundary **inside a single file**: a
 * handler that hands its input to `decode(job)` leaves `decode` holding a parameter
 * with no origin, so the hop is taken and the argument checked at the call site.
 *
 * The same reasoning stops at the file, and that is what holdout-6 measured. A layered
 * application — a controller that validates and delegates, a service that does the work
 * — puts the caller's value in a plain function parameter one module away. The service
 * file has no entry point, so it has no seeds, so nothing in it is caller-controlled and
 * every rule judging a sink inside it stays silent. Verified by transplanting the
 * identical code into a controller, where it reports. Three of holdout-6's misses are
 * this shape and no vocabulary fixes it.
 *
 * **The guard that makes this safe is the one the last attempt was closed with.**
 * `docs/12-release/DETECTION-PLAN.md` records an earlier widening that immediately
 * reported a validated executable path in Myrqen's own source as command injection, and
 * says it was fixed by requiring *observed* taint rather than *inferred* taint across a
 * second boundary. So this index records nothing about what a parameter might hold. It
 * records only that a real call site, in a real file, was observed passing an argument
 * this engine can already prove is caller-controlled — the same question
 * `parameterTaintAt` asks in-file, asked one file over.
 *
 * Computed once per scan, in the pass that already holds every parsed file. Rules never
 * reach across files: they get a lookup keyed by their own path, which keeps
 * `RuleContext` one-file-at-a-time and keeps the cost off the per-file loop.
 */
import ts from "typescript";
import { analyzeFunction, taintOrigin } from "./taint.js";
import { enclosingFunction, walk } from "./helpers.js";
import type { ParsedFile } from "./parse.js";
import { IDENTITY_SEGMENT } from "../rules/records-origin.js";
import { entryPointForFunction } from "./entrypoints.js";

/**
 * May a call in this function hand caller data across a file? Yes for an entry point an
 * adapter recognised, and for a function taking `req`, `request`, a typed request, or a
 * framework-shaped destructuring. Not for a parameter merely called `context` or `input`.
 * Kept in step with `receivesRequestByConvention` in `engine/handlers.ts`, which cannot be
 * imported here without a cycle.
 */
function startsHop(file: ParsedFile, fn: ts.Node): boolean {
  if (entryPointForFunction(file, fn)) return true;
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? [];
  return parameters.some((parameter) => {
    if (ts.isIdentifier(parameter.name)) {
      if (/^(req|request)$/.test(parameter.name.text)) return true;
      const type = parameter.type && ts.isTypeReferenceNode(parameter.type) ? parameter.type.typeName.getText(file.source) : "";
      return /^(Request|NextRequest|IncomingMessage|FastifyRequest|HttpRequest|FormData)$/.test(type);
    }
    if (!ts.isObjectBindingPattern(parameter.name)) return false;
    return parameter.name.elements.some((element) => {
      const key = element.propertyName && ts.isIdentifier(element.propertyName)
        ? element.propertyName.text
        : ts.isIdentifier(element.name)
          ? element.name.text
          : null;
      return key !== null && ["params", "input", "query", "body", "searchParams", "headers", "cookies"].includes(key);
    });
  });
}

/**
 * How many distinct files may hand caller data to one parameter before it is treated as
 * a utility rather than as domain logic. See the note in `buildCallSiteIndex`.
 */
const MAX_CALLERS = 2;

interface Observation {
  origin: string;
  callers: Set<string>;
}

/** `exported name → parameter index → why that parameter holds caller data`. */
export type TaintedParameters = Map<string, Map<number, string>>;

/** `file path → its exported functions' caller-controlled parameters`. */
export type CallSiteIndex = Map<string, TaintedParameters>;

/**
 * Where a relative specifier points, judged against the files actually discovered.
 *
 * Deliberately not `ts.resolveModuleName`: that wants a compiler host and a tsconfig,
 * and would resolve into `node_modules`, which is both slower and useless here — a call
 * into a dependency is not a call into code this scan can see. The file set the scan
 * already walked is a better oracle than a resolver, because it answers the only
 * question being asked: which of *these* files is meant.
 *
 * Bare specifiers are refused rather than guessed at — a call into a dependency is not a
 * call into code this scan can see. Alias forms (`@/`, `~/`) are resolved separately; see
 * `resolveAlias`.
 */
/**
 * Alias prefixes that mean "somewhere in this project", not "a package".
 *
 * `@/lib/db` is the Next.js default and `~/server/utils` is Nuxt's; both are `paths`
 * entries in a tsconfig. `@nestjs/common` must not match, which is why the slash has to
 * come directly after the `@`: a scoped package always has a name in between.
 */
const ALIAS_PREFIX = /^(@\/|~\/|#\/|src\/)/;

/**
 * An aliased specifier, resolved by suffix against the files actually discovered.
 *
 * Reading `paths` out of a tsconfig would work and would be more machinery for a worse
 * answer: the mapping can be several entries deep, `baseUrl` shifts it, monorepos nest
 * configs, and none of that changes which file is meant. The file set does. `@/lib/db`
 * becomes "the known file whose path ends in `lib/db` plus an extension".
 *
 * **Ambiguity is refused rather than guessed.** Two files ending `lib/db.ts` mean the
 * specifier cannot be resolved from the file set alone, and inventing a call graph edge
 * between the wrong two modules is worse than not having one: it would attribute a
 * finding to a file that never received the value.
 */
function resolveAlias(specifier: string, known: Set<string>): string | null {
  const tail = specifier.replace(ALIAS_PREFIX, "").replace(/\.(m|c)?(j|t)sx?$/, "");
  if (tail.length === 0) return null;
  const extensions = ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];
  const wanted = extensions.flatMap((extension) => [`/${tail}.${extension}`, `/${tail}/index.${extension}`]);
  const matches: string[] = [];
  for (const candidate of known) {
    if (wanted.some((suffix) => candidate.endsWith(suffix)) || wanted.some((suffix) => candidate === suffix.slice(1))) {
      matches.push(candidate);
    }
  }
  return matches.length === 1 ? matches[0]! : null;
}

export function resolveRelative(fromPath: string, specifier: string, known: Set<string>): string | null {
  if (ALIAS_PREFIX.test(specifier)) return resolveAlias(specifier, known);
  if (!specifier.startsWith(".")) return null;
  const directory = fromPath.split("/").slice(0, -1).join("/");
  const joined = normalise(`${directory}/${specifier}`);
  if (joined === null) return null;

  // TypeScript source is written importing `.js`; the file on disk is `.ts`.
  const withoutExtension = joined.replace(/\.(m|c)?(j|t)sx?$/, "");
  const extensions = ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];
  for (const candidate of [joined, ...extensions.flatMap((extension) => [
    `${withoutExtension}.${extension}`,
    `${withoutExtension}/index.${extension}`
  ])]) {
    if (known.has(candidate)) return candidate;
  }
  return null;
}

function normalise(path: string): string | null {
  const parts: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (parts.length === 0) return null;
      parts.pop();
      continue;
    }
    parts.push(segment);
  }
  return parts.join("/");
}

/** What a file imports, and from where: `local name → resolved target path`. */
export function importsOf(file: ParsedFile, known: Set<string>): Map<string, string> {
  const resolved = new Map<string, string>();
  for (const statement of file.source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier)) continue;
    const target = resolveRelative(file.relativePath, statement.moduleSpecifier.text, known);
    if (!target) continue;
    const clause = statement.importClause;
    if (!clause) continue;
    if (clause.name) resolved.set(clause.name.text, target);
    const bindings = clause.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) resolved.set(element.name.text, target);
    }
  }
  return resolved;
}

/**
 * Class members whose declared type names an imported class: `member name → target`.
 *
 * This is the shape the layered architectures use, and it is why reading only bare
 * imported functions would have missed the cases that prompted the work:
 *
 *     constructor(private readonly invoices: InvoicesService) {}
 *     ...
 *     this.invoices.getInvoiceDetail(invoiceId, actor)
 *
 * The link from the call to the other file runs through the member's *type*, not through
 * anything named at the call site. `storeMembers` in `rules/records-origin.ts` reads
 * declared types the same way to recognise an injected repository, which is the
 * precedent for doing it here rather than matching member names.
 */
function injectedMembersOf(file: ParsedFile, imports: Map<string, string>): Map<string, string> {
  const members = new Map<string, string>();
  const consider = (name: ts.Node | undefined, type: ts.TypeNode | undefined): void => {
    if (!name || !ts.isIdentifier(name) || !type) return;
    const declared = type.getText(file.source).replace(/<[\s\S]*$/, "").trim();
    const target = imports.get(declared);
    if (target) members.set(name.text, target);
  };
  walk(file.source, (node) => {
    if (ts.isPropertyDeclaration(node)) consider(node.name, node.type);
    if (!ts.isConstructorDeclaration(node)) return;
    // A constructor parameter carrying an accessibility modifier declares a member,
    // which is how every injected dependency is written.
    for (const parameter of node.parameters) consider(parameter.name, parameter.type);
  });
  return members;
}

/**
 * The function or method a call addresses in another file, or null.
 *
 * Two shapes only: a bare imported identifier, and a method on a member whose declared
 * type is an imported class. Anything else — a value passed around, a dynamic property,
 * a re-export chain — is left alone, because guessing which function a call reaches is
 * exactly the inference this index exists to avoid.
 */
function targetOf(
  call: ts.CallExpression,
  imports: Map<string, string>,
  members: Map<string, string>
): { path: string; name: string } | null {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) {
    const path = imports.get(callee.text);
    return path ? { path, name: callee.text } : null;
  }
  if (!ts.isPropertyAccessExpression(callee)) return null;

  const receiver = callee.expression;
  // `this.invoices.getInvoiceDetail(…)`
  if (ts.isPropertyAccessExpression(receiver) && receiver.expression.kind === ts.SyntaxKind.ThisKeyword) {
    const path = members.get(receiver.name.text);
    return path ? { path, name: callee.name.text } : null;
  }
  // `invoices.getInvoiceDetail(…)` where `invoices` is a locally declared member or a
  // bare imported binding used as a namespace.
  if (ts.isIdentifier(receiver)) {
    const path = members.get(receiver.text) ?? imports.get(receiver.text);
    return path ? { path, name: callee.name.text } : null;
  }
  return null;
}

/** Does this expression name the authenticated subject rather than the caller's input? */
export function namesTheSubject(node: ts.Node): boolean {
  const segments: string[] = [];
  let current: ts.Node = node;
  for (let depth = 0; depth < 8; depth += 1) {
    if (ts.isPropertyAccessExpression(current)) {
      segments.push(current.name.text);
      current = current.expression;
      continue;
    }
    if (ts.isCallExpression(current) || ts.isAwaitExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isIdentifier(current)) segments.push(current.text);
    break;
  }
  return segments.some((segment) => IDENTITY_SEGMENT.test(segment));
}

/**
 * For every file, which of its exported functions' parameters are handed caller data.
 *
 * One pass over files that import from within the project. The scope of each call site's
 * enclosing function is analysed once and reused across its arguments, because
 * `analyzeFunction` is the expensive part and a handler routinely contains several calls.
 */
export function buildCallSiteIndex(files: readonly ParsedFile[]): CallSiteIndex {
  const observations = new Map<string, Map<string, Map<number, Observation>>>();
  const known = new Set(files.map((file) => file.relativePath));

  for (const file of files) {
    const imports = importsOf(file, known);
    if (imports.size === 0) continue;
    const members = injectedMembersOf(file, imports);
    const scopes = new Map<ts.Node, ReturnType<typeof analyzeFunction>>();

    walk(file.source, (node) => {
      if (!ts.isCallExpression(node) || node.arguments.length === 0) return;
      const target = targetOf(node, imports, members);
      if (!target || target.path === file.relativePath) return;

      const fn = enclosingFunction(node);
      if (!fn) return;
      // Only a function that receives a request by contract or by the strongest naming
      // convention starts a hop; see `receivesRequestByConvention`.
      if (!startsHop(file, fn)) return;
      let scope = scopes.get(fn);
      if (!scope) {
        scope = analyzeFunction(file, fn);
        scopes.set(fn, scope);
      }

      node.arguments.forEach((argument, position) => {
        /*
         * The authenticated subject is not the caller's data, even though it came from
         * the request.
         *
         * `taintOrigin` says a resolved session is tainted, and for its own purposes it
         * is right: `getSession(request)` was handed caller data, and the model assumes a
         * function handed caller data returns something influenced by it. That
         * assumption is what keeps ordinary handlers visible and it is the wrong answer
         * here. Recording `session` as a caller-controlled parameter tells every rule
         * downstream that the identity is attacker-chosen, which unscopes every predicate
         * built from it — `WHERE owner_id = $2` with `session.userId` stops counting as
         * ownership, and the correctly scoped query becomes the reported defect.
         *
         * Measured: without this, holdout-2's wallet withdrawal — a query scoped by
         * `owner_id` and guarded twice — was reported, and the index had marked all three
         * parameters of the handler caller-controlled including the session.
         *
         * `IDENTITY_SEGMENT` is the vocabulary the ownership rules already use for this
         * question, reused rather than reinvented.
         */
        if (namesTheSubject(argument)) return;
        // The whole guard, in one line: the argument has to be provably caller data
        // *here*, at a call site that exists, before anything is recorded about the
        // callee's parameter.
        const origin = taintOrigin(argument, scope);
        if (!origin) return;
        const forFile = observations.get(target.path) ?? new Map<string, Map<number, Observation>>();
        const forName = forFile.get(target.name) ?? new Map<number, Observation>();
        const existing = forName.get(position);
        if (existing) {
          existing.callers.add(file.relativePath);
        } else {
          forName.set(position, {
            origin: `${origin}, handed to \`${target.name}\` from ${file.relativePath}`,
            callers: new Set([file.relativePath])
          });
        }
        forFile.set(target.name, forName);
        observations.set(target.path, forFile);
      });
    });
  }

  /*
   * A parameter handed caller data from many places is a utility, and a finding
   * attributed to it is a finding about none of its callers.
   *
   * `readIfPresent(target)` is a one-line wrapper around `fs.readFile`. Every caller
   * passes it a path, some of those paths derive from input, and reporting the wrapper
   * asserts something about all of them at once — which is false for most and unhelpful
   * for the rest, because the defect, if there is one, is at the call site that failed to
   * validate. Measured on this project's own source: seeding without this reported
   * `readIfPresent` and a session-file helper as path traversal, neither of which a
   * reviewer would accept.
   *
   * A service method its controller delegates to is the opposite shape: one caller, or
   * two, and the finding belongs exactly where it is reported. So the fan-in is the
   * discriminator, and the threshold is deliberately tight — this crosses a boundary on
   * an observation, and an observation made from four different directions is closer to
   * "this parameter is a path" than to "this call passes user input".
   */
  const index: CallSiteIndex = new Map();
  for (const [target, byName] of observations) {
    for (const [name, byIndex] of byName) {
      for (const [position, observation] of byIndex) {
        if (observation.callers.size > MAX_CALLERS) continue;
        const forFile = index.get(target) ?? new Map<string, Map<number, string>>();
        const forName = forFile.get(name) ?? new Map<number, string>();
        forName.set(position, observation.origin);
        forFile.set(name, forName);
        index.set(target, forFile);
      }
    }
  }
  return index;
}
