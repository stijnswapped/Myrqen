import ts from "typescript";
import {
  calleeName,
  calleeTail,
  collect,
  dynamicParts,
  expressionName,
  isConstantString,
  literalTextOf,
  walk, isAbortCall } from "../ast/helpers.js";
import {
  analyzeFunction,
  functionsIn,
  expandedText,
  resolveExpression,
  rootOf,
  taintOrigin,
  type TaintScope
} from "../ast/taint.js";
import type { ParsedFile } from "../ast/parse.js";
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

/**
 * Process APIs that belong to the runtime rather than to a module.
 *
 * Neither Deno nor Bun has a `child_process` to import, so a rule that decides
 * a call spawns a process by looking for that import is blind to every service
 * written for either of them — and both are used precisely where a small HTTP
 * handler shells out to a tool. The spellings differ; the finding does not.
 */
const RUNTIME_SPAWNS = new Set(["Deno.Command", "Deno.run", "Bun.spawn", "Bun.spawnSync"]);

/** Programs whose whole purpose is to interpret a command string. */
const SHELL_PROGRAM = /(^|\/)(sh|bash|dash|zsh|ksh|csh|tcsh|fish|cmd|powershell|pwsh)(\.exe)?$/i;

/** Interpreters that will evaluate a program handed to them on the command line. */
const CODE_INTERPRETER = /(^|\/)(node|deno|bun|python|python3|perl|ruby|php)(\.exe)?$/i;

/**
 * The switch that says "what follows is a program to run, not a file to read".
 *
 * Requiring it is what keeps this precise. `new Deno.Command("node", { args: [
 * "render.js", name ] })` runs a fixed script and the caller's value is an
 * argument to it; the same call with `-e` in front hands the caller's value to
 * the interpreter. Only the second is command injection, and the switch is the
 * only thing in the call that distinguishes them.
 */
const COMMAND_SWITCH = /^(-c|-ec|-lc|--command|\/c|\/k|-e|--eval|-p|--print)$/i;

/*
 * `rawQuery` is Adonis/Lucid's spelling and was missing. The list already carried
 * `raw` (Knex, Drizzle) and `RAW_SQL_SINK` below matches Prisma's `queryRaw` /
 * `executeRaw`, but nothing matched the words the other way round — so an Adonis
 * application composing a statement into `db.rawQuery(...)` had no SQL sink at all.
 */
const SQL_SINKS = new Set(["query", "execute", "raw", "rawQuery", "unsafe", "exec", "all", "get", "run", "prepare"]);

/**
 * Calls that carry text somewhere other than a database.
 *
 * A statement interpolated into a log line is a real problem and is not this one, so
 * naming it `sql_injection` would send a reader to fix the wrong thing. Kept small and
 * specific: this list only has to be right about the handful of places a developer
 * deliberately passes a whole statement without executing it.
 */
const NOT_A_QUERY_SINK = /^(log|info|warn|error|debug|trace|print|write|writeln|send|emit|push|assert|expect|format|inspect|explain|describe|comment|annotate|span|setAttribute|addBreadcrumb)$/i;

/**
 * Does any argument read as a complete SQL statement?
 *
 * A concatenation counts, and it is the case that matters: the statement most likely to
 * be a defect is the one assembled with `+`, and its keywords sit in the literal pieces
 * of the expression rather than in any single literal node. So the whole expression's
 * text is read for those two shapes — the alternative is recognising the safe spelling
 * and missing the dangerous one.
 */
function carriesStatement(context: RuleContext, call: ts.CallExpression): boolean {
  for (const argument of call.arguments) {
    const inner = ts.isAsExpression(argument) || ts.isParenthesizedExpression(argument) ? argument.expression : argument;
    const text =
      literalTextOf(inner) ??
      (ts.isTemplateExpression(inner) || ts.isBinaryExpression(inner) ? inner.getText(context.file.source) : null);
    if (text && text.length <= 4000 && SQL_STATEMENT_SHAPE.test(text)) return true;
  }
  return false;
}

/**
 * Query methods that name the shape of the rows they hand back.
 *
 * A whole runtime can be invisible to a rule that only knows the word `query`.
 * Deno's Postgres client has no `query` method at all: it is `queryObject` for
 * row objects and `queryArray` for tuples, and the same naming convention turns
 * up wherever a client or a hand-written wrapper wants the result shape in the
 * call — `queryOne`, `queryRows`, `queryFirst`, `executeQuery`. Every one of them
 * takes the statement in the same place `query` does, so the shape of the finding
 * is identical and only the spelling differs.
 *
 * `querySelector` is refused by name rather than left to the receiver test: a CSS
 * selector is not a statement, and one written as `select[name="…"]` spells a SQL
 * keyword loudly enough to pass every other check in this rule.
 */
const SHAPED_QUERY_SINK = /^(?!querySelector)(query|execute)[A-Z]\w*$/;

/**
 * Property names a driver reads the statement text out of when the call takes a
 * descriptor object rather than a string.
 *
 * `queryObject({ text, args })` in Deno's Postgres client and `execute({ sql,
 * args })` in libSQL are the same call written with its arguments named. Reading
 * only the first argument finds an object literal, no string, and nothing to
 * judge — which is silence on precisely the shape whose separate `args` field is
 * the parameterisation people forget to use.
 */
const QUERY_TEXT_PROPERTIES = new Set(["text", "sql", "query", "statement"]);

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

/**
 * A string that is a SQL statement rather than merely mentioning SQL words.
 *
 * The clause pairing is what makes it evidence: `SELECT` followed by `FROM`,
 * `INSERT INTO`, `UPDATE` followed by `SET`, `DELETE FROM`. A log line reading
 * "could not select from the report" satisfies none of them.
 */
const SQL_STATEMENT_SHAPE =
  /\bselect\b[\s\S]*\bfrom\b|\binsert\s+into\b|\bupdate\b[\s\S]*\bset\b|\bdelete\s+from\b|\bwith\b[\s\S]*\bas\s*\(/i;

/** Names that say the receiver of a call is the database itself. */
const SQL_RECEIVER = /\b(db|database|pool|client|conn|connection|knex|sequelize|prisma|sql|pg|mysql|sqlite)\b/i;

/**
 * Names that say the receiver is a handle *opened from* a database rather than
 * the database itself.
 *
 * A handler that has to write more than one row atomically opens a transaction
 * first and then runs every statement on the handle, so without these names the
 * most consequential requests an application serves — the ones whose author was
 * careful enough to reach for a transaction — are the ones this rule cannot see.
 * They are kept apart from the names above because they are weaker evidence:
 * `transaction` and `tx` are the words a document store and a blockchain client
 * use too, which is why a match here is not enough on its own.
 */
const SQL_HANDLE = /\b(tx|trx|transaction|cursor)\b/i;

/**
 * Query methods whose own name says the argument is a statement.
 *
 * `get`, `all` and `run` are the words `better-sqlite3` and D1 use, and they are
 * also the words every other library in the ecosystem uses for something else. A
 * handle called `transaction` calling `get` on a query builder is a Firestore
 * read, and reporting that as SQL injection is exactly the noise that gets a
 * whole class switched off — so a weakly named receiver has to be paired with a
 * method that names a statement before this rule will judge the call.
 */
const STATEMENT_SINK = new Set(["query", "execute", "raw", "rawQuery", "unsafe", "prepare"]);
const SQL_KEYWORDS = /\b(select|insert|update|delete|drop|union|where|from|into|values)\b/i;

/**
 * Fields a driver reads the bound values out of.
 *
 * Whether the call binds anything at all changes what the finding means rather
 * than whether there is one, and it changes the sentence a reader is owed: a
 * statement with a parameter array is a statement whose author knew how to
 * parameterise and wrote one fragment the other way, which is a sharper tell
 * than an absent array and the opposite of what "no parameter array" says.
 */
const BOUND_VALUE_PROPERTIES = new Set(["args", "values", "params", "parameters", "bindings"]);

const EVAL_SINKS = new Set(["eval", "Function", "vm.runInNewContext", "vm.runInThisContext", "vm.compileFunction"]);

export const commandInjection: Rule = {
  id: "command-injection",
  category: "command_injection",
  describes: "caller-controlled data reaching a process-spawning call",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = scopeFor(context, fn);

      // A runtime process API is written `new Deno.Command(...)` as often as it
      // is written as a plain call, so both node kinds have to be walked or half
      // the shape is missed.
      for (const node of collect(fn, ts.isNewExpression)) reportRuntimeSpawn(context, node, scope);

      for (const call of collect(fn, ts.isCallExpression)) {
        if (reportRuntimeSpawn(context, call, scope)) continue;
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
          reportArgumentSlot(context, { node: call, sink, callSite: describeSink(call) }, slot);
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
        reportShellExecution(
          context,
          { node: call, sink, callSite: describeSink(call) },
          origin,
          shellNote,
          shellEnabled ? " with shell:true" : ""
        );
      }
    }
  }
};

interface SpawnSite {
  /** The node the finding points at. */
  node: ts.Node;
  /** How the report names the API, for example `child_process.exec`. */
  sink: string;
  /** How the call is written here, used in the data-flow sentence. */
  callSite: string;
}

/**
 * Report a value the operating system is going to interpret as a command.
 *
 * Shared by every spawning API so that the same shape written for a different
 * runtime produces the same sentence: a reader comparing two findings should not
 * have to work out whether the difference in wording means a difference in what
 * happened.
 */
function reportShellExecution(
  context: RuleContext,
  site: SpawnSite,
  origin: string,
  note: string,
  reasoningNote: string
): void {
  context.report({
    ruleId: "command-injection",
    category: "command_injection",
    title: `Caller-controlled data is executed as a shell command via ${site.sink}`,
    severity: "critical",
    verification: "strong_evidence",
    summary: `A value derived from ${origin} is composed into the command passed to ${site.sink} without validation.${note} The caller therefore controls part of a string that the operating system will interpret as a command.`,
    impact:
      "An attacker who can reach this route executes arbitrary commands as the application user, which is a full compromise of the host and everything its credentials reach.",
    remediation:
      "Do not build a shell command from caller input. Use execFile or spawn with a fixed executable and an argument array, and validate each argument against the shape it is allowed to take. If a shell is genuinely required, select the whole command from a fixed allowlist.",
    verificationPlan:
      "Send a value containing a shell metacharacter such as a semicolon and confirm the process is never spawned and the request is refused.",
    taxonomy: ["CWE-78", "OWASP-A03"],
    location: locationOf(context, site.node),
    ...routeOf(context, site.node),
    evidence: [
      sourceEvidence(context, site.node, `${site.sink} is called with a command string built from caller-controlled data.`),
      taintEvidence(origin, site.callSite)
    ],
    reasoning: `Taint from ${origin} reaches the command argument of ${site.sink}${reasoningNote}.`
  });
}

/** Report a caller-controlled value sitting in an argument slot of a fixed program. */
function reportArgumentSlot(
  context: RuleContext,
  site: SpawnSite,
  slot: { node: ts.Expression; origin: string; index: number }
): void {
  context.report({
    ruleId: "command-injection-argument",
    category: "argument_injection",
    title: `Caller-controlled value occupies an argument slot of ${site.sink}`,
    // The executable is fixed, so this is not the critical "run any command"
    // case — but every general-purpose program the shape occurs with (git, curl,
    // rsync, tar, ssh, psql, ffmpeg) has an option that reads a file, writes a
    // file, or runs a helper program, so the realistic outcome is the same class
    // of loss as a path traversal.
    severity: "high",
    verification: "needs_review",
    summary: `A value derived from ${slot.origin} is passed to ${site.sink} as a positional argument, and the caller controls its first character. Option parsing is not terminated with \`--\` before it and it is not the value of a named option, so a value beginning with a dash is read by the program as an option rather than as data. The executable is fixed and no shell is involved, so this is argument injection rather than command injection.`,
    impact:
      "Depending on the program invoked, a crafted leading-dash argument changes what it reads, writes, or executes — ripgrep's --pre runs a program of the attacker's choosing, curl's -o writes a file, and most tools have an equivalent. The blast radius is that program's own option surface, which is frequently enough to read or write arbitrary files.",
    remediation:
      "Terminate option parsing with a literal `--` before the caller's value, or pass it as the value of an explicit option such as `--regexp`. Reject a value starting with a dash where neither is possible.",
    verificationPlan:
      "Send the value prefixed with a dash and one of the program's own long options and confirm the request is refused, or that the program treats the whole value as data.",
    taxonomy: ["CWE-88", "OWASP-A03"],
    location: locationOf(context, slot.node),
    ...routeOf(context, site.node),
    evidence: [
      sourceEvidence(context, slot.node, `${site.sink} receives this value in a positional argument slot.`),
      taintEvidence(slot.origin, site.callSite)
    ],
    reasoning: `Taint from ${slot.origin} reaches argv[${slot.index}] of ${site.sink}; no \`--\` separator precedes it, the preceding element is not an option expecting a value, and the caller controls the value's first character.`
  });
}

/* ------------------------------------------------------------------ *
 * Deno and Bun process APIs
 *
 * Three spellings, one idea. `new Deno.Command(exe, { args })` names the
 * program and its arguments separately; `Bun.spawn([exe, ...args])` and
 * `Deno.run({ cmd })` put both in one array with the program in slot zero. Once
 * the two parts are separated the judgement is the one this rule already makes
 * for `child_process`: a caller who picks the program has arbitrary execution, a
 * caller who fills the argument of an interpreter has the same, and a caller who
 * fills an argument slot of a fixed program has an option-injection problem at
 * most.
 * ------------------------------------------------------------------ */

interface RuntimeSpawn {
  sink: string;
  /** The expression naming the program that will run. */
  executable: ts.Expression | undefined;
  /** The argument list, when it is written as an array literal this can read. */
  argv: ts.ArrayLiteralExpression | undefined;
}

/**
 * Judge one Deno or Bun spawn, and say whether this node was one.
 *
 * Returning `false` for anything it does not recognise is what lets the caller
 * use it as a filter in front of the `child_process` logic without the two
 * paths ever both reporting the same call.
 */
function reportRuntimeSpawn(
  context: RuleContext,
  node: ts.CallExpression | ts.NewExpression,
  scope: TaintScope
): boolean {
  const spawn = runtimeSpawnOf(node);
  if (!spawn) return false;
  const { sink, executable, argv } = spawn;
  if (!executable) return true;

  const site: SpawnSite = { node, sink, callSite: sink };

  // A caller who chooses the program has already won, and nothing about the
  // arguments changes that.
  const executableOrigin = taintOrigin(executable, scope);
  if (executableOrigin) {
    reportShellExecution(context, site, executableOrigin, " The name of the program to run is itself derived from caller input.", "");
    return true;
  }

  const interpreter = interpretedProgram(executable, argv);
  if (interpreter) {
    const origin = (argv?.elements ?? []).map((element) => taintOrigin(element, scope)).find(Boolean);
    if (origin) {
      reportShellExecution(
        context,
        site,
        origin,
        ` The program invoked is \`${interpreter}\`, given a switch that makes the argument after it a command to interpret rather than data to read.`,
        ` as an argument of \`${interpreter}\``
      );
    }
    return true;
  }

  // A fixed program with a fixed argument list is the shape a careful author
  // reaches for and must never be reported. What is left is the smaller
  // option-injection case, judged by exactly the rules `spawn` is judged by.
  if (!argv) return true;
  const slot = injectableArgv(argv, scope);
  if (slot) reportArgumentSlot(context, site, slot);
  return true;
}

/** The program and argument list of a runtime spawn, however the call spells them. */
function runtimeSpawnOf(node: ts.CallExpression | ts.NewExpression): RuntimeSpawn | null {
  const name = expressionName(node.expression);
  if (!RUNTIME_SPAWNS.has(name)) return null;
  const sink = ts.isNewExpression(node) ? `new ${name}()` : `${name}()`;
  const passed = Array.from(node.arguments ?? []);
  const first = passed[0];
  if (!first) return { sink, executable: undefined, argv: undefined };

  // One array carrying the program and its arguments together.
  const combined = arrayLiteralOf(first) ?? propertyArrayOf(first, "cmd") ?? propertyArrayOf(first, "args");
  if (combined) {
    const executable = combined.elements.find((element) => !ts.isOmittedExpression(element));
    return { sink, executable, argv: combined };
  }

  // The program named on its own, with its arguments in the options object.
  const argv = passed.slice(1).map((argument) => propertyArrayOf(argument, "args")).find(Boolean);
  return { sink, executable: first, argv };
}

/**
 * The interpreter this call hands a command string to, if it does.
 *
 * Both halves are required: a program that reads a command string, and the
 * switch that tells it to. `bash script.sh ${name}` passes an argument to a
 * fixed script; `bash -c "…${name}…"` passes a program to bash.
 */
function interpretedProgram(executable: ts.Expression, argv: ts.ArrayLiteralExpression | undefined): string | null {
  const program = literalTextOf(executable);
  if (!program) return null;
  if (!SHELL_PROGRAM.test(program) && !CODE_INTERPRETER.test(program)) return null;
  const switched = (argv?.elements ?? []).some((element) => {
    const text = literalTextOf(element);
    return Boolean(text && COMMAND_SWITCH.test(text));
  });
  return switched ? program : null;
}

/** An array literal, through the wrappers a typed codebase puts around one. */
function arrayLiteralOf(node: ts.Expression): ts.ArrayLiteralExpression | undefined {
  if (ts.isArrayLiteralExpression(node)) return node;
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) {
    return arrayLiteralOf(node.expression);
  }
  return undefined;
}

/** The array literal held by one named property of an options object. */
function propertyArrayOf(node: ts.Expression, key: string): ts.ArrayLiteralExpression | undefined {
  const literal = objectLiteralOf(node);
  if (!literal) return undefined;
  for (const property of literal.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const name =
      ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : null;
    if (name === key) return arrayLiteralOf(property.initializer);
  }
  return undefined;
}

/**
 * The line a reviewer would put the comment on, when the composition and the sink
 * are not the same statement.
 *
 * `pool.query(sql, params)` is a *parameterised* call. It is not the defect, and a
 * developer sent there reads correct-looking code and learns nothing. The defect
 * is wherever the tainted value was written into the statement text — one clause
 * among several whose siblings all bound their values properly:
 *
 *     if (filter.status) {
 *       conditions.push(`po.status = $${params.length + 1}`);   // correct
 *       params.push(filter.status);
 *     }
 *     if (filter.search) {
 *       conditions.push(`s.name ilike '%${filter.search}%'`);   // the finding
 *     }
 *     ...
 *     const { rows } = await pool.query(sql, params);           // reported here before
 *
 * Reporting the sink is reporting the only innocent line in the flow.
 *
 * The search starts from the query *text* and follows only what reaches it, which
 * is the whole difficulty. A first attempt took the narrowest tainted composition
 * anywhere in the function and landed on
 *
 *     values.push(`%${subject}%`);
 *
 * — a tainted template that goes into the **bound parameter array**, so it is the
 * correct half of the same handler. Pointing a reader at the parameterisation and
 * calling it SQL injection is worse than pointing at the sink.
 */
function taintedCompositionSite(
  fn: ts.Node,
  scope: TaintScope,
  file: ParsedFile,
  queryExpression: ts.Node
): ts.Node | null {
  const partsOf = (node: ts.Node): ts.Expression[] => {
    if (ts.isTemplateExpression(node)) return node.templateSpans.map((span) => span.expression);
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return [node.left, node.right];
    }
    return [];
  };

  /** `clauses.join(" AND ")` and a bare `clauses` both drain the collection. */
  const drainedCollection = (node: ts.Node): string | null => {
    if (ts.isIdentifier(node)) return node.text;
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      if (node.expression.name.text !== "join") return null;
      return rootOf(node.expression.expression);
    }
    return null;
  };

  const resolved = resolveExpression(queryExpression, scope);
  const candidates: ts.Node[] = [];

  for (const part of partsOf(resolved)) {
    /*
     * The drain check comes first, and the order is the whole correctness of this
     * function. `taintOrigin` answers *true* for `conditions.join(" and ")` — the
     * collection carries taint, so the join that reads it out does too. Testing
     * direct taint first therefore lands on the join, which is one line above the
     * sink and just as innocent. What a reader needs is the push.
     */
    const collection = drainedCollection(part);
    if (collection && scope.taintedCollections.has(collection)) {
      walk(fn, (node) => {
        if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
        if (node.expression.name.text !== "push" && node.expression.name.text !== "unshift") return;
        if (rootOf(node.expression.expression) !== collection) return;
        for (const argument of node.arguments) {
          if (taintOrigin(argument, scope) !== null) candidates.push(argument);
        }
      });
      continue;
    }
    // Interpolated straight into the statement text.
    if (taintOrigin(part, scope) !== null) candidates.push(part);
  }

  if (candidates.length === 0) return null;

  // Narrowest wins: the most specific expression is the one a reader can act on.
  let best = candidates[0]!;
  for (const candidate of candidates) {
    if (candidate.getEnd() - candidate.getStart(file.source) < best.getEnd() - best.getStart(file.source)) {
      best = candidate;
    }
  }
  return best;
}

export const sqlInjection: Rule = {
  id: "sql-injection",
  category: "sql_injection",
  describes: "caller-controlled data concatenated into a query string",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = scopeFor(context, fn);
      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        /*
         * A complete SQL statement in the first argument admits the call whatever it is
         * called.
         *
         * The three name tests cover every spelling a *library* uses. They do not cover
         * the spelling a project uses for its own data layer — `rows.one(sql)`,
         * `sql.first(text)`, `store.fetchAll(statement)` — and a data-access module
         * exporting two or three well-named helpers is the ordinary way to write one.
         * `records-origin.isStoreCall` already judges the same call by its argument for
         * exactly this reason, and the two modules disagreeing meant a statement was a
         * store read for the authorization rules and not a query for the injection rule.
         *
         * `NOT_A_QUERY_SINK` keeps the obvious confusion out: a statement passed to a
         * logger or a formatter is a different finding, and this rule claiming it would
         * name the wrong defect and prescribe the wrong fix.
         */
        const named = SQL_SINKS.has(tail) || RAW_SQL_SINK.test(tail) || SHAPED_QUERY_SINK.test(tail);
        if (!named && !(carriesStatement(context, call) && !NOT_A_QUERY_SINK.test(tail))) continue;
        const receiver = calleeName(call);
        const evidence = handleEvidence(context, call, receiver, scope);
        if (evidence === "none") continue;

        // A receiver identified only by a two-letter name or by the line it was
        // opened on is half an argument. The other half has to come from the
        // method: `handle.queryObject` and `handle.raw` name a statement, while
        // `handle.get` names nothing in particular and turns up on every client
        // in the ecosystem.
        const namesStatement = STATEMENT_SINK.has(tail) || RAW_SQL_SINK.test(tail) || SHAPED_QUERY_SINK.test(tail);
        if (evidence === "opened-from-a-database" && !namesStatement) continue;

        // A tagged template — `sql`select … ${id}`` — never arrives here, because it
        // is not a call expression. That is deliberate and worth stating: in every
        // client that offers the form it is the *parameterised* one, the client
        // turning each interpolation into a bound placeholder, and teaching this
        // rule to read tagged templates would report the safe way to write a query.
        const queryArgument = queryTextOf(call);
        if (!queryArgument) continue;

        // Follow an alias to what it was built from. A rule that reads only the
        // argument text sees the identifier `sql` and concludes there is no query.
        const resolved = resolveExpression(queryArgument, scope);

        // A constant query is the parameterized form whether or not a parameter
        // array is present. That is the safe decoy and must not be reported.
        if (isConstantString(resolved)) continue;

        // The keyword test reads the constants the expression names as well as
        // the expression itself, because a query assembled from a module-level
        // prologue plus per-request clauses spells none of its own keywords.
        if (!SQL_KEYWORDS.test(expandedText(resolved, context.file.source))) continue;

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
          location: locationOf(context, taintedCompositionSite(fn, scope, context.file, queryArgument) ?? call),
          ...routeOf(context, call),
          evidence: [
            sourceEvidence(context, call, "The query string is built by interpolation rather than parameter binding."),
            taintEvidence(origin, describeSink(call))
          ],
          reasoning: `Taint from ${origin} reaches a SQL-shaped first argument of ${receiver}${
            bindsParameters(call)
              ? ", which also passes a parameter array — the tainted fragment is part of the statement text rather than one of the bound values"
              : " with no parameter array"
          }.`
        });
      }
    }
  }
};

/**
 * The expression holding the statement this call is going to run.
 *
 * Almost every client takes it as the first argument. The exceptions take a
 * descriptor object — `{ text, args }`, `{ sql, args }` — where the statement is
 * one named field and the bound values are another, and the first argument is
 * then an object literal with no statement in sight. Returning nothing for an
 * object that names no statement is the conservative half: a call this cannot
 * read is a call this rule stays quiet about.
 */
function queryTextOf(call: ts.CallExpression): ts.Expression | undefined {
  const first = call.arguments[0];
  if (!first) return undefined;
  const descriptor = objectLiteralOf(first);
  if (!descriptor) return first;
  for (const property of descriptor.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const name =
      ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : null;
    if (name && QUERY_TEXT_PROPERTIES.has(name)) return property.initializer;
  }
  return undefined;
}

/**
 * How well this call's receiver is established as a database.
 *
 * The receiver's name is the first evidence and usually the only evidence there
 * is. When the name says nothing, what the handle was opened from does: `const
 * handle = await pool.connect()` names a pool one line above the statement, and
 * a rule that refuses to read that line loses every statement in the function to
 * a two-letter variable name. The lookup is the taint scope's own initialiser
 * map, so it only ever follows a binding declared in this function or a module
 * constant — never a guess about a value that arrived from somewhere else.
 *
 * The two answers are kept distinct because they carry different weight, and the
 * caller pairs the weaker one with a second piece of evidence before reporting.
 */
type HandleEvidence = "a-database" | "opened-from-a-database" | "none";

function handleEvidence(
  context: RuleContext,
  call: ts.CallExpression,
  receiver: string,
  scope: TaintScope
): HandleEvidence {
  if (SQL_RECEIVER.test(receiver)) return "a-database";
  if (SQL_HANDLE.test(receiver)) return "opened-from-a-database";
  /*
   * A project's own `query(...)` helper, judged by the statement rather than by a
   * receiver it does not have.
   *
   *     import { query } from "../db/pool.js";
   *     await query(`SELECT … FROM settlement_report_rows ORDER BY ${orderBy}`);
   *
   * Exporting one function that owns the pool is the ordinary way to write a data
   * layer, and it leaves the call with a bare identifier where this rule looks for
   * `pool` or `db`. So it reported nothing at all — not a weaker finding, nothing —
   * for every query in such an application.
   *
   * The evidence is the argument: a string whose shape is a SQL statement. That is
   * what separates this from `query("#grid")` against the DOM and
   * `query("{ user { id } }")` against GraphQL, neither of which can satisfy
   * `SELECT … FROM`. Named `a-database` rather than the weaker verdict because a
   * complete statement is stronger evidence than a receiver called `client`.
   */
  /*
   * The argument answers it whatever the callee looks like.
   *
   * This test used to require the callee to be a *bare identifier*, which limited it to
   * a project's own exported `query(...)`. Every other way a data layer spells the same
   * thing has a receiver, and the receiver is exactly what this function has already
   * failed to recognise by the time it gets here:
   *
   *     em.getConnection().execute(`select … where id = ${id}`)   // MikroORM
   *     ctx.db.session.run(`… ${filter}`)                          // anything hand-rolled
   *
   * `getConnection` does not contain the word `conn` at a word boundary, so `SQL_RECEIVER`
   * says no, and the statement-shape evidence was structurally unreachable. Run 7 missed
   * three SQL injections on a corpus with SQL in it for this reason.
   *
   * Widening it costs nothing in precision because the *method name* is already gated by
   * the caller: only `SQL_SINKS`, `RAW_SQL_SINK` or `SHAPED_QUERY_SINK` tails reach here,
   * so a `console.log` carrying a statement cannot. A complete statement is stronger
   * evidence than any receiver name, which is what "a-database" means.
   */
  if (carriesStatement(context, call)) return "a-database";
  if (!ts.isPropertyAccessExpression(call.expression)) return "none";
  const opened = resolveExpression(call.expression.expression, scope);
  return SQL_RECEIVER.test(opened.getText(context.file.source)) ? "opened-from-a-database" : "none";
}

/**
 * Does this call bind values as well as carrying statement text?
 *
 * Read only to describe the finding accurately, never to decide whether it
 * exists: a bound parameter array protects the values it holds and does nothing
 * for a fragment that was concatenated into the statement instead.
 */
function bindsParameters(call: ts.CallExpression): boolean {
  const first = call.arguments[0];
  const descriptor = first ? objectLiteralOf(first) : undefined;
  if (descriptor) {
    return descriptor.properties.some((property) => {
      if (!ts.isPropertyAssignment(property)) return false;
      const name =
        ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : null;
      return Boolean(name && BOUND_VALUE_PROPERTIES.has(name));
    });
  }
  const second = call.arguments[1];
  if (!second) return false;
  // A completion callback is the other thing a driver takes in second position,
  // and it binds nothing.
  return !ts.isArrowFunction(second) && !ts.isFunctionExpression(second);
}

export const codeInjection: Rule = {
  id: "code-injection",
  category: "code_injection",
  describes: "caller-controlled data evaluated as code",
  run(context: RuleContext) {
    for (const fn of functionsIn(context.file.source)) {
      const scope = scopeFor(context, fn);

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
 * Four things have to be true, and each of them is a real defence a careful
 * author uses: option parsing has not been terminated with `--`, the value is
 * not being consumed as a named option's argument, the caller controls the
 * value's *first character* — a path built on a fixed root can never start with
 * a dash, however attacker-influenced its tail is — and nothing in the enclosing
 * function has already refused a value that begins with one.
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
    if (leadingDashRejected(element, scope)) continue;
    return { node: element, origin, index };
  }
  return null;
}

/* ------------------------------------------------------------------ *
 * The leading-dash defence
 *
 * A program that parses options cannot tell an operand from an option once the
 * operand starts with a dash, so the whole class turns on one character. There
 * are three honest ways to close it and this recognises two of them — the third,
 * a literal `--` in the argument list, is already handled above.
 * ------------------------------------------------------------------ */

/**
 * Has the enclosing function refused a value beginning with a dash?
 *
 * Only a check whose failing branch actually stops the function counts: a
 * warning logged and execution continued leaves the value in argv exactly as the
 * caller sent it. Without this the rule reports code that is already correct,
 * and an argument check is precisely the fix the finding asks for — reporting it
 * anyway is the fastest way to teach a reader to ignore the rule.
 */
function leadingDashRejected(element: ts.Expression, scope: TaintScope): boolean {
  const name = rootOf(element);
  if (!name) return false;
  const body = (scope.fn as ts.FunctionLikeDeclaration).body;
  if (!body) return false;

  let rejected = false;
  walk(body, (node) => {
    if (rejected || !ts.isIfStatement(node)) return;
    if (!branchStops(node.thenStatement) && !(node.elseStatement && branchStops(node.elseStatement))) return;
    if (conditionRejectsLeadingDash(node.expression, name, scope)) rejected = true;
  });
  return rejected;
}

/** Does this branch stop the function, so a failed check cannot fall through? */
function branchStops(statement: ts.Statement): boolean {
  let stops = false;
  walk(statement, (node) => {
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node) || isAbortCall(node)) stops = true;
  });
  return stops;
}

/**
 * Does this condition, when the guarded branch stops the function, prove that
 * `name` cannot begin with a dash?
 *
 * Two shapes, negated or not, because both are written in real code: an explicit
 * `value.startsWith("-")` rejection, and an anchored allowlist pattern whose
 * first atom cannot match a dash.
 */
function conditionRejectsLeadingDash(condition: ts.Expression, name: string, scope: TaintScope): boolean {
  const negated = ts.isPrefixUnaryExpression(condition) && condition.operator === ts.SyntaxKind.ExclamationToken;
  const inner = negated ? (condition as ts.PrefixUnaryExpression).operand : condition;

  // `a && b` and `a || b`: either half can carry the check, and each half is
  // judged with its own polarity.
  if (ts.isBinaryExpression(inner) && !negated) {
    const kind = inner.operatorToken.kind;
    if (kind === ts.SyntaxKind.AmpersandAmpersandToken || kind === ts.SyntaxKind.BarBarToken) {
      return (
        conditionRejectsLeadingDash(inner.left, name, scope) ||
        conditionRejectsLeadingDash(inner.right, name, scope)
      );
    }
  }
  if (ts.isParenthesizedExpression(inner)) return conditionRejectsLeadingDash(inner.expression, name, scope);
  if (!ts.isCallExpression(inner)) return false;

  const tail = calleeTail(inner);

  // `if (value.startsWith("-")) throw` — the direct refusal, so the *unnegated*
  // form is the one that stops a dash.
  if (tail === "startsWith" && !negated) {
    const receiver = ts.isPropertyAccessExpression(inner.expression) ? inner.expression.expression : undefined;
    if (!receiver || rootOf(receiver) !== name) return false;
    const prefix = inner.arguments[0];
    return Boolean(prefix && literalTextOf(prefix) === "-");
  }

  // `if (!SHAPE.test(value)) throw` — an allowlist, so the *negated* form is the
  // one that stops a dash, and only when the pattern's first atom cannot match
  // one. `/^[a-z0-9-]+$/` is anchored and still permits a leading dash, which is
  // exactly the near-miss this has to keep reporting.
  if (tail === "test" && ts.isPropertyAccessExpression(inner.expression)) {
    const subject = inner.arguments[0];
    if (!subject || rootOf(subject) !== name) return false;
    const pattern = regularExpressionTextOf(inner.expression.expression);
    if (!pattern) return false;
    return negated ? patternExcludesLeadingDash(pattern) : patternRequiresLeadingDash(pattern);
  }

  return false;
}

/** The source of a regular expression written inline or held by a constant. */
function regularExpressionTextOf(node: ts.Node): string | null {
  if (ts.isRegularExpressionLiteral(node)) return node.text;
  if (!ts.isIdentifier(node)) return null;
  const source = node.getSourceFile();
  if (!source) return null;
  for (const declaration of collect(source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== node.text) continue;
    const initializer = declaration.initializer;
    if (initializer && ts.isRegularExpressionLiteral(initializer)) return initializer.text;
  }
  return null;
}

/** `/^-/` and friends: a pattern that matches only what starts with a dash. */
function patternRequiresLeadingDash(literal: string): boolean {
  const body = patternBody(literal);
  return body.startsWith("^-") || body.startsWith("^\\-");
}

/**
 * Can this pattern still match a string whose first character is a dash?
 *
 * Answered only when the answer is certain. An unanchored pattern, a negated
 * character class, or a first atom this cannot read all mean "unknown", and
 * unknown has to mean "not proven safe" or a rule that reports missing
 * validation would fall silent the moment it saw any regular expression at all.
 */
function patternExcludesLeadingDash(literal: string): boolean {
  const body = patternBody(literal);
  if (!body.startsWith("^")) return false;
  const rest = body.slice(1);
  if (rest.length === 0) return false;

  if (rest.startsWith("[")) {
    const end = characterClassEnd(rest);
    if (end < 0) return false;
    const contents = rest.slice(1, end);
    // A negated class says what is forbidden, and reading it backwards is how a
    // check like `[^/]` would be mistaken for one that excludes a dash.
    if (contents.startsWith("^")) return false;
    return !characterClassMatchesDash(contents);
  }

  if (rest.startsWith("\\")) {
    // `\w`, `\d` and `\s` match no dash; anything else, including `\-` and
    // `\S`, either matches one or cannot be read here.
    return ["w", "d", "s"].includes(rest[1] ?? "");
  }

  // A plain first character stands for itself, unless it is syntax.
  const first = rest[0]!;
  if ("(.*+?|){}$[]\\".includes(first)) return false;
  return first !== "-";
}

/** The pattern text without its delimiters and flags. */
function patternBody(literal: string): string {
  const match = /^\/(.*)\/[a-z]*$/s.exec(literal);
  return match ? match[1]! : literal;
}

/** The index of the `]` that closes a character class starting at position 0. */
function characterClassEnd(text: string): number {
  for (let index = 1; index < text.length; index += 1) {
    if (text[index] === "\\") {
      index += 1;
      continue;
    }
    // A `]` in the first position of a class is a literal, not the terminator.
    if (text[index] === "]" && index > 1) return index;
  }
  return -1;
}

/**
 * Does a positive character class match a literal dash?
 *
 * A dash inside a class is a range separator except at the very start, at the
 * very end, or when escaped — those three positions are the ones that let a
 * caller's value begin with one. A range that happens to span the dash character
 * is not read; the effect is that such a pattern counts as validation, which
 * costs a finding rather than inventing one.
 */
function characterClassMatchesDash(contents: string): boolean {
  for (let index = 0; index < contents.length; index += 1) {
    if (contents[index] === "\\") {
      if (contents[index + 1] === "-") return true;
      index += 1;
      continue;
    }
    if (contents[index] !== "-") continue;
    if (index === 0 || index === contents.length - 1) return true;
  }
  return false;
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
    if (initializer) return callerControlsPrefix(initializer, scope, depth + 1);
    const destructured = destructuringSource(node.text, scope);
    if (destructured) return callerControlsPrefix(destructured, scope, depth + 1);
    // Nothing in this body builds the binding: it is a parameter, a seed the
    // entry point declared, or a value assigned from somewhere the model already
    // called caller-controlled. Those arrive whole, first character included.
    // Treating them as prefix-safe was silently exempting the most direct shape
    // of all — the caller's own string handed straight to the program.
    return scope.roots.has(node.text) && !scope.cleared.has(node.text);
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

/* ------------------------------------------------------------------ *
 * Taint that arrives through a parameter
 *
 * Data-flow analysis in this engine stops at a function boundary, which is the
 * right default: following a value into an arbitrary callee invents flows that
 * do not exist. The cost of that default is a specific and very common shape —
 * a handler that reads its input and immediately hands it to a small named
 * helper, with every sink living in the helper. The helper's parameter has no
 * origin, so the sink is judged against an empty taint picture and the whole
 * file goes quiet. Splitting a handler into a helper is how this code is
 * ordinarily written, and a program is not less exposed for having done it.
 *
 * One hop, and the conditions are what keep it honest: the callee is named and
 * called in this same file, the argument in that parameter's own position is
 * caller-controlled where the call is written, and the caller's own scope is
 * *not* widened in turn, so a chain of helpers ends rather than being guessed
 * at.
 * ------------------------------------------------------------------ */

interface ScopeEntry {
  fn: ts.Node;
  scope: TaintScope;
  span: number;
}

const baseScopeCache = new WeakMap<ts.SourceFile, ScopeEntry[]>();
const widenedScopeCache = new WeakMap<ts.Node, TaintScope>();
const fileCallCache = new WeakMap<ts.SourceFile, ts.CallExpression[]>();

/** Every function in the file with its own taint picture, innermost first. */
function baseScopes(context: RuleContext): ScopeEntry[] {
  const cached = baseScopeCache.get(context.file.source);
  if (cached) return cached;
  const entries = functionsIn(context.file.source).map((fn) => ({
    fn,
    scope: analyzeFunction(context.file, fn),
    span: fn.end - fn.pos
  }));
  entries.sort((a, b) => a.span - b.span);
  baseScopeCache.set(context.file.source, entries);
  return entries;
}

/**
 * Every call in the file, memoised.
 *
 * Finding the call sites of a helper is a whole-file question asked once per
 * function that has parameters, and rewalking the tree for each of them makes a
 * large file quadratic for nothing — the tree does not change during a scan.
 */
function callsInFile(source: ts.SourceFile): ts.CallExpression[] {
  const cached = fileCallCache.get(source);
  if (cached) return cached;
  const calls = collect(source, ts.isCallExpression);
  fileCallCache.set(source, calls);
  return calls;
}

function containsNode(outer: ts.Node, inner: ts.Node): boolean {
  return inner.pos >= outer.pos && inner.end <= outer.end;
}

/**
 * The taint picture a rule in this file should judge a sink against: the
 * function's own, plus whatever its callers hand it through its parameters.
 */
function scopeFor(context: RuleContext, fn: ts.Node): TaintScope {
  const cached = widenedScopeCache.get(fn);
  if (cached) return cached;

  const base = baseScopes(context).find((entry) => entry.fn === fn)?.scope ?? analyzeFunction(context.file, fn);
  const seeds = parameterSeeds(context, fn);

  let scope = base;
  if (seeds.size > 0) {
    const roots = new Map(base.roots);
    for (const [name, origin] of seeds) {
      // A parameter the callee itself already sanitised, or one the model
      // already has a better origin for, is left exactly as it was.
      if (roots.has(name) || base.cleared.has(name)) continue;
      roots.set(name, { name, origin, declaration: fn });
    }
    scope = { ...base, roots };
  }

  widenedScopeCache.set(fn, scope);
  return scope;
}

/** Bindings this function's parameters hold because a caller in this file put caller data there. */
function parameterSeeds(context: RuleContext, fn: ts.Node): Map<string, string> {
  const seeds = new Map<string, string>();
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters;
  if (!parameters || parameters.length === 0) return seeds;

  // A function nothing in this file can name is a function whose callers are
  // invisible, and guessing at an invisible caller is exactly the over-reach
  // this hop must not become.
  const callee = localCallee(fn);
  if (!callee) return seeds;

  for (const call of callsInFile(context.file.source)) {
    // A recursive call proves nothing about where the value came from: the
    // function is handing its own parameter back to itself.
    if (containsNode(fn, call)) continue;
    if (!callsFunction(call, callee)) continue;

    const callerScope = baseScopes(context).find((entry) => containsNode(entry.fn, call))?.scope;
    if (!callerScope) continue;

    parameters.forEach((parameter, index) => {
      const argument = call.arguments[index];
      if (!argument) return;
      bindParameter(parameter.name, argument, callerScope, callee.name, seeds);
    });
  }
  return seeds;
}

interface LocalCallee {
  name: string;
  /** A method is only reached through a receiver, so a bare call is someone else's. */
  requiresThis: boolean;
}

/**
 * The name a call site in this file would use to reach this function.
 *
 * Only the two declarations whose call shape is unambiguous are accepted: a
 * function declaration and a function held by a variable, both of which a bare
 * `name(...)` reaches, and a method, which needs a receiver. A function stored
 * as a property of an object literal is deliberately left out — matching it by
 * its key would let an unrelated free function of the same name donate taint to
 * a body it never calls.
 */
function localCallee(fn: ts.Node): LocalCallee | null {
  if (ts.isFunctionDeclaration(fn) && fn.name) return { name: fn.name.text, requiresThis: false };
  if (ts.isMethodDeclaration(fn) && ts.isIdentifier(fn.name)) return { name: fn.name.text, requiresThis: true };
  const parent = fn.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return { name: parent.name.text, requiresThis: false };
  }
  return null;
}

/** Is this call a call of that locally declared function? */
function callsFunction(call: ts.CallExpression, callee: LocalCallee): boolean {
  const expression = call.expression;
  if (ts.isIdentifier(expression)) return !callee.requiresThis && expression.text === callee.name;
  // `this.render(...)`; any other receiver is a different object's method that
  // merely shares a name.
  return (
    ts.isPropertyAccessExpression(expression) &&
    expression.name.text === callee.name &&
    expression.expression.kind === ts.SyntaxKind.ThisKeyword
  );
}

/**
 * Record what one argument makes of one parameter.
 *
 * A destructuring parameter is handled property by property when the call site
 * writes an object literal, because that is the shape where precision is
 * available and worth having: `render({ theme: options.theme, rows })` gives one
 * field the caller's value and leaves the rest alone, and tainting the whole
 * binding list would report the wrong line. When the argument is not a literal —
 * `mirror(options)` — the object as a whole is caller data, so every field
 * destructured out of it is too.
 */
function bindParameter(
  pattern: ts.BindingName,
  argument: ts.Expression,
  callerScope: TaintScope,
  callee: string,
  into: Map<string, string>
): void {
  if (ts.isIdentifier(pattern)) {
    const origin = observedOrigin(argument, callerScope);
    if (origin) into.set(pattern.text, handedOver(origin, callee, pattern.text));
    return;
  }

  const literal = ts.isObjectBindingPattern(pattern) ? objectLiteralOf(argument) : undefined;
  if (literal) {
    for (const element of (pattern as ts.ObjectBindingPattern).elements) {
      const key = bindingKeyOf(element);
      const value = key ? literalPropertyValue(literal, key) : undefined;
      if (!value) continue;
      const origin = observedOrigin(value, callerScope);
      if (!origin) continue;
      for (const bound of patternNames(element.name)) into.set(bound, handedOver(origin, callee, bound));
    }
    return;
  }

  const origin = observedOrigin(argument, callerScope);
  if (!origin) return;
  for (const bound of patternNames(pattern)) into.set(bound, handedOver(origin, callee, bound));
}

/**
 * Why this argument is the caller's — but only when the model can point at the
 * read rather than having assumed it.
 *
 * The taint model deliberately assumes that an unknown function handed caller
 * data returns something influenced by it. That assumption is right far more
 * often than it is wrong and it is what keeps ordinary handlers visible. It is
 * still an assumption, and carrying it across a second function boundary stacks
 * two of them: a project helper that validates its argument and returns
 * something entirely different — a resolved executable path, a database row, a
 * parsed identifier — then arrives in the callee wearing the request's name, and
 * every sink it touches becomes a finding on code that is correct. So the hop
 * carries what was observed: a request binding, a field of one, a string built
 * from one, or a value read back off one. Everything else stops here, which
 * costs findings in helpers-of-helpers and invents none.
 */
function observedOrigin(node: ts.Expression, scope: TaintScope): string | null {
  const origin = taintOrigin(node, scope);
  if (!origin) return null;
  return observedCallerValue(node, scope) ? origin : null;
}

/** Standard transformations that hand the value they were given straight back. */
const TRANSPARENT_CALLS = new Set([
  "String",
  "decodeURI",
  "decodeURIComponent",
  "encodeURI",
  "encodeURIComponent",
  "JSON.parse",
  "trim",
  "trimStart",
  "trimEnd",
  "toString",
  "toLowerCase",
  "toUpperCase",
  "normalize",
  "slice",
  "substring",
  "substr",
  "replace",
  "replaceAll",
  "split",
  "join",
  "at",
  "concat",
  "padStart",
  "padEnd"
]);

function observedCallerValue(node: ts.Node, scope: TaintScope, depth = 0): boolean {
  if (depth > 6) return false;

  if (ts.isIdentifier(node)) {
    const initializer = scope.initializers.get(node.text);
    if (initializer) return observedCallerValue(initializer, scope, depth + 1);
    const destructured = destructuringSource(node.text, scope);
    if (destructured) return observedCallerValue(destructured, scope, depth + 1);
    return scope.roots.has(node.text) && !scope.cleared.has(node.text);
  }
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    // A field of a request object, which the model reads rather than infers.
    return taintOrigin(node, scope) !== null;
  }
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isAwaitExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node)
  ) {
    return observedCallerValue(node.expression, scope, depth + 1);
  }
  if (ts.isTemplateExpression(node) || ts.isBinaryExpression(node)) {
    return dynamicParts(node).some((part) => observedCallerValue(part, scope, depth + 1));
  }
  if (ts.isConditionalExpression(node)) {
    return (
      observedCallerValue(node.whenTrue, scope, depth + 1) || observedCallerValue(node.whenFalse, scope, depth + 1)
    );
  }
  if (ts.isCallExpression(node)) {
    const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : undefined;
    // `body.trim()`, `req.header("x")`, `searchParams.get("q")` — a method
    // called on something already known to be the caller's hands it back.
    if (receiver && observedCallerValue(receiver, scope, depth + 1)) return true;
    // A free accessor the entry point itself declared, such as h3's
    // `readBody(event)`: the adapter states that this call *is* the read.
    if (ts.isIdentifier(node.expression) && scope.accessors.has(node.expression.text)) {
      return node.arguments.some((argument) => observedCallerValue(argument, scope, depth + 1));
    }
    if (TRANSPARENT_CALLS.has(calleeName(node)) || TRANSPARENT_CALLS.has(calleeTail(node))) {
      return node.arguments.some((argument) => observedCallerValue(argument, scope, depth + 1));
    }
    return false;
  }
  return false;
}

function handedOver(origin: string, callee: string, bound: string): string {
  return `${origin}, handed to \`${callee}\` as \`${bound}\``;
}

/** The object literal an argument is, seen through the wrappers that keep it one. */
function objectLiteralOf(node: ts.Expression): ts.ObjectLiteralExpression | undefined {
  if (ts.isObjectLiteralExpression(node)) return node;
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) {
    return objectLiteralOf(node.expression);
  }
  return undefined;
}

/** The property a binding element reads, following a rename such as `{ q: term }`. */
function bindingKeyOf(element: ts.BindingElement): string | null {
  if (element.propertyName) {
    if (ts.isIdentifier(element.propertyName) || ts.isStringLiteralLike(element.propertyName)) {
      return element.propertyName.text;
    }
    return null;
  }
  return ts.isIdentifier(element.name) ? element.name.text : null;
}

/** What an object literal puts under a key, spreads included. */
function literalPropertyValue(literal: ts.ObjectLiteralExpression, key: string): ts.Expression | undefined {
  for (const property of literal.properties) {
    if (ts.isPropertyAssignment(property) && property.name.getText() === key) return property.initializer;
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === key) return property.name;
    // `{ ...options }` puts everything the spread object holds under its own
    // names, so the field is whatever that object's field is.
    if (ts.isSpreadAssignment(property)) return property.expression;
  }
  return undefined;
}

/** Every name a binding pattern introduces, renames and nesting included. */
function patternNames(pattern: ts.BindingName): string[] {
  if (ts.isIdentifier(pattern)) return [pattern.text];
  const names: string[] = [];
  for (const element of pattern.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...patternNames(element.name));
  }
  return names;
}

/**
 * The expression a name was destructured out of, when it was.
 *
 * `const { source } = options` records no initialiser for `source`, so a
 * question about the value's *shape* — does the caller choose its first
 * character — has nothing to look at unless the declaration is found again.
 * Reading the object it came from answers it correctly in both directions: a
 * field of the caller's own object is the caller's whole value, and a field of
 * something a helper returned is not.
 */
function destructuringSource(name: string, scope: TaintScope): ts.Expression | undefined {
  const body = (scope.fn as ts.FunctionLikeDeclaration).body;
  if (!body) return undefined;
  let found: ts.Expression | undefined;
  walk(body, (node) => {
    if (found) return;
    if (!ts.isVariableDeclaration(node) || !node.initializer) return;
    if (ts.isIdentifier(node.name)) return;
    if (!patternNames(node.name).includes(name)) return;
    found = node.initializer;
  });
  return found;
}
