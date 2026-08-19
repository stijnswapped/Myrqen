import ts from "typescript";
import { calleeName, calleeTail, collect, isConstantString, literalTextOf } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, resolveExpression, taintOrigin, type TaintScope } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { describeSink, locationOf, sourceEvidence, taintEvidence, type Rule, type RuleContext } from "./context.js";

/** Process-spawning sinks. A tainted argument here is remote code execution. */
const COMMAND_SINKS = new Map<string, string>([
  ["exec", "child_process.exec"],
  ["execSync", "child_process.execSync"],
  ["spawn", "child_process.spawn"],
  ["spawnSync", "child_process.spawnSync"],
  ["execFile", "child_process.execFile"],
  ["execFileSync", "child_process.execFileSync"],
  ["fork", "child_process.fork"]
]);

/**
 * `execFile` and `spawn` are only dangerous in the shell sense when the command
 * itself is tainted or `shell: true` is set; a tainted *argument* to them is an
 * argument-injection concern rather than command injection, and is reported at
 * lower severity.
 */
const ARGUMENT_SAFE_SINKS = new Set(["execFile", "execFileSync", "spawn", "spawnSync"]);

const SQL_SINKS = new Set(["query", "execute", "raw", "unsafe", "exec", "all", "get", "run", "prepare"]);

/**
 * Drivers that name their escape hatch rather than their query method.
 *
 * Prisma's `$queryRawUnsafe` takes a plain string and interpolates nothing for
 * you — it is the one call in that client that can be injected, and a rule that
 * only knows the word `query` cannot see it. `$queryRaw` is listed too: as a
 * tagged template it is parameterised and never reaches this rule, so matching
 * the name costs nothing and covers the day someone calls it as a function.
 */
const RAW_SQL_SINK = /^\$?(query|execute)Raw(Unsafe)?$/;
const SQL_RECEIVER = /\b(db|database|pool|client|conn|connection|knex|sequelize|prisma|sql|pg|mysql|sqlite)\b/i;
const SQL_KEYWORDS = /\b(select|insert|update|delete|drop|union|where|from|into|values)\b/i;

const EVAL_SINKS = new Set(["eval", "Function", "vm.runInNewContext", "vm.runInThisContext", "vm.compileFunction"]);

export const commandInjection: Rule = {
  id: "command-injection",
  category: "command_injection",
  describes: "caller-controlled data reaching a process-spawning call",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);
      for (const call of collect(fn, ts.isCallExpression)) {
        const spawn = spawnTargetOf(context, call);
        if (!spawn) continue;
        const { tail, sink } = spawn;

        const commandArgument = call.arguments[0];
        if (!commandArgument) continue;

        const shellEnabled = call.arguments.some(
          (argument) =>
            ts.isObjectLiteralExpression(argument) &&
            argument.properties.some(
              (property) =>
                ts.isPropertyAssignment(property) &&
                property.name.getText(context.file.source) === "shell" &&
                property.initializer.kind === ts.SyntaxKind.TrueKeyword
            )
        );

        const commandOrigin = taintOrigin(commandArgument, scope);
        const argumentList = ARGUMENT_SAFE_SINKS.has(tail) && !shellEnabled ? argvArray(call) : undefined;

        // A fixed executable invoked with an argument array cannot be turned into
        // a different command. What the caller can still do is take over an
        // *option* of the program being run, and that is a different, smaller
        // finding — reported only where the evidence supports it.
        if (!commandOrigin && argumentList) {
          const slot = injectableArgv(argumentList, scope);
          if (!slot) continue;
          context.report({
            ruleId: "command-injection-argument",
            category: "argument_injection",
            title: `Caller-controlled value occupies an argument slot of ${sink}`,
            severity: "medium",
            verification: "needs_review",
            summary: `A value derived from ${slot.origin} is passed to ${sink} as a positional argument, and the caller controls its first character. Option parsing is not terminated with \`--\` before it and it is not the value of a named option, so a value beginning with a dash is read by the program as an option rather than as data. The executable is fixed and no shell is involved, so this is argument injection rather than command injection.`,
            impact:
              "Depending on the program invoked, a crafted leading-dash argument changes what it reads, writes, or executes — ripgrep's --pre runs a program of the attacker's choosing, curl's -o writes a file, and most tools have an equivalent. The blast radius is that program's own option surface, which is frequently enough to read or write arbitrary files.",
            remediation:
              "Terminate option parsing with a literal `--` before the caller's value, or pass it as the value of an explicit option such as `--regexp`. Reject a value starting with a dash where neither is possible.",
            verificationPlan:
              "Send the value prefixed with a dash and one of the program's own long options and confirm the request is refused, or that the program treats the whole value as data.",
            taxonomy: ["CWE-88", "OWASP-A03"],
            location: locationOf(context, slot.node),
            ...routeOf(context, call),
            evidence: [
              sourceEvidence(context, slot.node, `${sink} receives this value in a positional argument slot.`),
              taintEvidence(slot.origin, describeSink(call))
            ],
            reasoning: `Taint from ${slot.origin} reaches argv[${slot.index}] of ${sink}; no \`--\` separator precedes it, the preceding element is not an option expecting a value, and the caller controls the value's first character.`
          });
          continue;
        }

        const argumentOrigin = call.arguments
          .slice(1)
          .map((argument) => taintOrigin(argument, scope))
          .find(Boolean);

        // A fixed command string with fixed arguments is exactly the safe
        // pattern the decoys use; it must never be reported.
        if (!commandOrigin && !argumentOrigin) continue;
        if (!commandOrigin && argumentOrigin && ARGUMENT_SAFE_SINKS.has(tail) && !shellEnabled) continue;

        const origin = commandOrigin ?? argumentOrigin!;
        const shellNote = shellEnabled ? " The call also sets `shell: true`, so the argument is interpreted by a shell." : "";
        context.report({
          ruleId: "command-injection",
          category: "command_injection",
          title: `Caller-controlled data is executed as a shell command via ${sink}`,
          severity: "critical",
          verification: "strong_evidence",
          summary: `A value derived from ${origin} is composed into the command passed to ${sink} without validation.${shellNote} The caller therefore controls part of a string that the operating system will interpret as a command.`,
          impact:
            "An attacker who can reach this route executes arbitrary commands as the application user, which is a full compromise of the host and everything its credentials reach.",
          remediation:
            "Do not build a shell command from caller input. Use execFile or spawn with a fixed executable and an argument array, and validate each argument against the shape it is allowed to take. If a shell is genuinely required, select the whole command from a fixed allowlist.",
          verificationPlan:
            "Send a value containing a shell metacharacter such as a semicolon and confirm the process is never spawned and the request is refused.",
          taxonomy: ["CWE-78", "OWASP-A03"],
          location: locationOf(context, call),
          ...routeOf(context, call),
          evidence: [
            sourceEvidence(context, call, `${sink} is called with a command string built from caller-controlled data.`),
            taintEvidence(origin, describeSink(call))
          ],
          reasoning: `Taint from ${origin} reaches the command argument of ${sink}${shellEnabled ? " with shell:true" : ""}.`
        });
      }
    }
  }
};

export const sqlInjection: Rule = {
  id: "sql-injection",
  category: "sql_injection",
  describes: "caller-controlled data concatenated into a query string",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);
      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        if (!SQL_SINKS.has(tail) && !RAW_SQL_SINK.test(tail)) continue;
        const receiver = calleeName(call);
        if (!SQL_RECEIVER.test(receiver)) continue;

        const queryArgument = call.arguments[0];
        if (!queryArgument) continue;

        // Follow an alias to what it was built from. A rule that reads only the
        // argument text sees the identifier `sql` and concludes there is no query.
        const resolved = resolveExpression(queryArgument, scope);

        // A constant query is the parameterized form whether or not a parameter
        // array is present. That is the safe decoy and must not be reported.
        if (isConstantString(resolved)) continue;

        const text = resolved.getText(context.file.source);
        if (!SQL_KEYWORDS.test(text)) continue;

        const origin = taintOrigin(queryArgument, scope) ?? taintOrigin(resolved, scope);
        if (!origin) continue;

        context.report({
          ruleId: "sql-injection",
          category: "sql_injection",
          title: `Caller-controlled data is concatenated into a query passed to ${receiver}`,
          severity: "critical",
          verification: "strong_evidence",
          summary: `A value derived from ${origin} is interpolated directly into the query string given to ${receiver}. The caller therefore controls the structure of the statement, not only its values.`,
          impact:
            "An attacker can read, modify, or delete any data the database user can reach, and in many deployments escalate to command execution on the database host.",
          remediation:
            "Pass the value as a bound parameter instead of interpolating it. Every driver in use here supports either a parameter array or a tagged template; use the one the surrounding code already uses elsewhere.",
          verificationPlan:
            "Send a value containing a quote and a boolean tautology and confirm the row count is unchanged and no database error is returned.",
          taxonomy: ["CWE-89", "OWASP-A03"],
          location: locationOf(context, call),
          ...routeOf(context, call),
          evidence: [
            sourceEvidence(context, call, "The query string is built by interpolation rather than parameter binding."),
            taintEvidence(origin, describeSink(call))
          ],
          reasoning: `Taint from ${origin} reaches a SQL-shaped first argument of ${receiver} with no parameter array.`
        });
      }
    }
  }
};

export const codeInjection: Rule = {
  id: "code-injection",
  category: "code_injection",
  describes: "caller-controlled data evaluated as code",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);

      for (const call of collect(fn, ts.isCallExpression)) {
        const name = calleeName(call);
        if (!EVAL_SINKS.has(name) && !EVAL_SINKS.has(calleeTail(call))) continue;
        const origin = call.arguments.map((argument) => taintOrigin(argument, scope)).find(Boolean);
        if (!origin) continue;
        report(context, call, name, origin);
      }

      for (const expression of collect(fn, ts.isNewExpression)) {
        if (expression.expression.getText(context.file.source) !== "Function") continue;
        const origin = (expression.arguments ?? []).map((argument) => taintOrigin(argument, scope)).find(Boolean);
        if (!origin) continue;
        report(context, expression, "new Function", origin);
      }
    }
  }
};

function report(context: RuleContext, node: ts.Node, sink: string, origin: string): void {
  context.report({
    ruleId: "code-injection",
    category: "code_injection",
    title: `Caller-controlled data is evaluated as code by ${sink}`,
    severity: "critical",
    verification: "strong_evidence",
    summary: `A value derived from ${origin} is passed to ${sink}, which compiles and runs it. The caller therefore supplies code that executes inside the application process.`,
    impact:
      "This is arbitrary code execution in the server process: the attacker gains everything the application can do, including its database credentials and its filesystem.",
    remediation:
      "Remove the dynamic evaluation. Express the behaviour as data the application interprets — a lookup table, a parsed filter object, or a query builder — so caller input can never become executable code.",
    verificationPlan:
      "Send a payload that would change the expression's meaning and confirm it is treated as an opaque value rather than evaluated.",
    taxonomy: ["CWE-95", "CWE-94", "OWASP-A03"],
    location: locationOf(context, node),
    ...routeOf(context, node),
    evidence: [
      sourceEvidence(context, node, `${sink} receives caller-controlled input.`),
      taintEvidence(origin, sink)
    ],
    reasoning: `Taint from ${origin} reaches ${sink}.`
  });
}

/** Is this call actually spawning a process, rather than a same-named method? */
function isProcessSpawn(context: RuleContext, call: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) {
    // `const { exec } = require("child_process")` then `exec(cmd)` is the most
    // common shape of all, so a bare call counts whenever this file pulls in
    // child_process. Requiring a receiver would lose most real findings.
    return importsChildProcess(context);
  }
  const receiver = call.expression.expression;
  // A regular expression receiver is never a process.
  if (ts.isRegularExpressionLiteral(receiver)) return false;
  const receiverText = receiver.getText(context.file.source);
  if (/^\/.*\/[gimsuy]*$/.test(receiverText)) return false;
  if (/regex|pattern|matcher/i.test(receiverText)) return false;
  // Resolve the receiver: a constant holding a regular expression is a regular
  // expression however it is named. Falling back to "this file imports
  // child_process somewhere" made every `SOME_PATTERN.exec(path)` in a file that
  // also spawns a process into a critical command-injection finding.
  if (ts.isIdentifier(receiver) && resolvesToRegularExpression(context, receiver.text)) return false;
  // The receiver must plausibly be the child_process module or a binding taken from
  // it, not merely a file that imports it.
  if (/child_process|childProcess|\bcp\b|\bproc\b|\bexecutor\b|shell|util\.promisify/i.test(receiverText)) return true;
  return ts.isIdentifier(receiver) && bindsChildProcess(context, receiver.text);
}

/** Is this name bound to a regular expression somewhere in the file? */
function resolvesToRegularExpression(context: RuleContext, name: string): boolean {
  for (const declaration of collect(context.file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
    const initializer = declaration.initializer;
    if (!initializer) continue;
    if (ts.isRegularExpressionLiteral(initializer)) return true;
    if (ts.isNewExpression(initializer) && initializer.expression.getText(context.file.source) === "RegExp") return true;
    if (ts.isCallExpression(initializer) && initializer.expression.getText(context.file.source) === "RegExp") return true;
  }
  return false;
}

/** Is this name bound to the child_process module itself? */
function bindsChildProcess(context: RuleContext, name: string): boolean {
  for (const statement of context.file.source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier)) continue;
    if (!/child_process/.test(statement.moduleSpecifier.text)) continue;
    const clause = statement.importClause;
    if (!clause) continue;
    if (clause.name?.text === name) return true;
    if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings) && clause.namedBindings.name.text === name) {
      return true;
    }
  }
  for (const declaration of collect(context.file.source, ts.isVariableDeclaration)) {
    const initializer = declaration.initializer;
    if (!initializer || !ts.isCallExpression(initializer)) continue;
    if (initializer.expression.getText(context.file.source) !== "require") continue;
    const specifier = initializer.arguments[0];
    if (!specifier || !ts.isStringLiteralLike(specifier) || !/child_process/.test(specifier.text)) continue;
    if (ts.isIdentifier(declaration.name) && declaration.name.text === name) return true;
  }
  return false;
}

/** Does this file import child_process at all? */
function importsChildProcess(context: RuleContext): boolean {
  for (const statement of context.file.source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      if (/child_process/.test(statement.moduleSpecifier.text)) return true;
    }
  }
  return /require\(["']node:child_process["']\)|require\(["']child_process["']\)/.test(context.file.text);
}

/* ------------------------------------------------------------------ *
 * Process spawning
 * ------------------------------------------------------------------ */

interface SpawnTarget {
  /** The child_process function that ultimately runs, for example `exec`. */
  tail: string;
  /** How it is named in the report. */
  sink: string;
}

const promisifiedCache = new WeakMap<ts.SourceFile, Map<string, string>>();

/**
 * Local names that stand for a child_process function.
 *
 * `const run = promisify(exec)` is how almost every async handler spawns a
 * process, and the call site is then `run(...)` — a name that matches nothing.
 * The distinction the alias carries is the whole finding: `promisify(exec)`
 * runs a shell, `promisify(execFile)` does not, and the two are written one
 * character apart.
 */
function promisifiedSpawns(context: RuleContext): Map<string, string> {
  const source = context.file.source;
  const cached = promisifiedCache.get(source);
  if (cached) return cached;

  const aliases = new Map<string, string>();
  if (importsChildProcess(context)) {
    for (const declaration of collect(source, ts.isVariableDeclaration)) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const initializer = declaration.initializer;
      if (!ts.isCallExpression(initializer)) continue;
      if (calleeTail(initializer) !== "promisify") continue;
      const wrapped = initializer.arguments[0];
      if (!wrapped) continue;
      const wrappedTail = ts.isPropertyAccessExpression(wrapped)
        ? wrapped.name.text
        : ts.isIdentifier(wrapped)
          ? wrapped.text
          : "";
      if (!COMMAND_SINKS.has(wrappedTail)) continue;
      aliases.set(declaration.name.text, wrappedTail);
    }
  }

  promisifiedCache.set(source, aliases);
  return aliases;
}

/** Which child_process function this call reaches, if any. */
function spawnTargetOf(context: RuleContext, call: ts.CallExpression): SpawnTarget | null {
  const tail = calleeTail(call);
  const direct = COMMAND_SINKS.get(tail);
  // `exec` is also a RegExp method. A regular expression matching a cookie is
  // not a process spawn, and reporting it as critical command injection is
  // exactly the kind of name-collision false positive that makes a scanner
  // untrustworthy.
  if (direct && isProcessSpawn(context, call)) return { tail, sink: direct };

  if (!ts.isIdentifier(call.expression)) return null;
  const aliased = promisifiedSpawns(context).get(call.expression.text);
  if (!aliased) return null;
  return { tail: aliased, sink: `child_process.${aliased} (via ${call.expression.text})` };
}

/** The argv array handed to a fixed-executable spawn. */
function argvArray(call: ts.CallExpression): ts.ArrayLiteralExpression | undefined {
  for (const argument of call.arguments.slice(1)) {
    if (ts.isArrayLiteralExpression(argument)) return argument;
  }
  return undefined;
}

/** Is this literal an option that expects its value in the next slot? */
function isValueTakingOption(node: ts.Expression | undefined): boolean {
  if (!node) return false;
  const text = literalTextOf(node);
  // `--max-count=${limit}` carries its own value and does not consume the next
  // slot, so only a plain literal without `=` shields what follows it.
  return Boolean(text && text.startsWith("-") && !text.includes("="));
}

/**
 * The first argv slot a caller can turn into an option.
 *
 * Three things have to be true, and each of them is a real defence a careful
 * author uses: option parsing has not been terminated with `--`, the value is
 * not being consumed as a named option's argument, and the caller controls the
 * value's *first character* — a path built on a fixed root can never start with
 * a dash, however attacker-influenced its tail is.
 */
function injectableArgv(
  argv: ts.ArrayLiteralExpression,
  scope: TaintScope
): { node: ts.Expression; origin: string; index: number } | null {
  for (let index = 0; index < argv.elements.length; index += 1) {
    const element = argv.elements[index]!;
    if (ts.isOmittedExpression(element)) continue;
    if (literalTextOf(element) === "--") return null;

    const origin = taintOrigin(element, scope);
    if (!origin) continue;
    if (isValueTakingOption(argv.elements[index - 1])) continue;
    if (!callerControlsPrefix(element, scope)) continue;
    return { node: element, origin, index };
  }
  return null;
}

/** Calls that keep the caller's leading characters intact. */
const PREFIX_PRESERVING = new Set([
  "String",
  "trim",
  "trimStart",
  "toString",
  "toLowerCase",
  "toUpperCase",
  "normalize",
  "decodeURIComponent",
  "decodeURI",
  "valueOf"
]);

/** Calls that put a fixed prefix in front of whatever the caller sent. */
const PREFIXING_CALLS = new Set(["join", "resolve", "relative", "format"]);

/**
 * Does the caller decide this value's first character?
 *
 * Conservative by construction: an expression shape this cannot read returns
 * false, so an unrecognised builder costs a finding rather than producing one.
 */
function callerControlsPrefix(node: ts.Node, scope: TaintScope, depth = 0): boolean {
  if (depth > 6) return false;

  if (ts.isIdentifier(node)) {
    const initializer = scope.initializers.get(node.text);
    return initializer ? callerControlsPrefix(initializer, scope, depth + 1) : false;
  }
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return false;
  if (ts.isTemplateExpression(node)) {
    if (node.head.text.length > 0) return false;
    const first = node.templateSpans[0]?.expression;
    return first ? callerControlsPrefix(first, scope, depth + 1) : false;
  }
  if (ts.isBinaryExpression(node)) {
    if (node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return callerControlsPrefix(node.left, scope, depth + 1);
    }
    // `a ?? b` and `a || b` both yield one of their operands whole.
    return (
      callerControlsPrefix(node.left, scope, depth + 1) || callerControlsPrefix(node.right, scope, depth + 1)
    );
  }
  if (ts.isConditionalExpression(node)) {
    return (
      callerControlsPrefix(node.whenTrue, scope, depth + 1) ||
      callerControlsPrefix(node.whenFalse, scope, depth + 1)
    );
  }
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAwaitExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node)
  ) {
    return callerControlsPrefix(node.expression, scope, depth + 1);
  }
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) return true;
  if (ts.isCallExpression(node)) {
    const tail = calleeTail(node);
    const name = calleeName(node);
    if (PREFIXING_CALLS.has(tail)) {
      const first = node.arguments[0];
      return first ? callerControlsPrefix(first, scope, depth + 1) : false;
    }
    if (PREFIX_PRESERVING.has(name) || PREFIX_PRESERVING.has(tail)) {
      const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : undefined;
      if (receiver && callerControlsPrefix(receiver, scope, depth + 1)) return true;
      const first = node.arguments[0];
      return first ? callerControlsPrefix(first, scope, depth + 1) : false;
    }
    // A reader of caller data — `searchParams.get("q")`, `req.header("x")` —
    // hands back the value whole.
    if (tail === "get" || tail === "getAll" || tail === "header" || tail === "param" || tail === "at") return true;
    return false;
  }
  return false;
}
