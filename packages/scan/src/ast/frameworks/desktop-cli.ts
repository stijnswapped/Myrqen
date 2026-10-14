import path from "node:path";
import ts from "typescript";
import { calleeTail, collect, expressionName, literalTextOf, walk } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";
import {
  functionOf,
  importsFrom,
  stringArgument,
  type EntryPoint,
  type FrameworkAdapter,
  type TaintSeed
} from "../entrypoints.js";

/**
 * Entry points of programs that run on somebody's own machine.
 *
 * Two families live in one file because they share a premise the rest of the
 * engine does not make: a process with no listening socket still has an attack
 * surface. An Electron main process is the privileged half of a browser, and the
 * renderer that calls it runs whatever page, extension, or injected script it
 * happened to load — every value crossing that boundary is chosen by the least
 * trusted part of the application. A command-line program is invoked by CI, by a
 * wrapper script, by a shell alias, and by whatever passes arguments to those;
 * "the developer typed it" is an assumption, not a fact.
 *
 * Without an adapter here, neither family produces an entry point, and with no
 * entry point there is no request parameter, no taint, and no data-flow rule that
 * can say anything at all about a file full of `exec`, `readFile` and `eval`.
 */

const ADAPTER_ID = "desktop-cli";

/* ------------------------------------------------------------------------- *
 * Shared plumbing
 * ------------------------------------------------------------------------- */

/** The last segment of a dotted name: `electron.ipcMain` is still `ipcMain`. */
function lastSegment(name: string): string {
  const index = name.lastIndexOf(".");
  return index === -1 ? name : name.slice(index + 1);
}

/** The receiver a method call hangs off, as a dotted name, or "" for a bare call. */
function receiverName(call: ts.CallExpression): string {
  if (!ts.isPropertyAccessExpression(call.expression)) return "";
  return expressionName(call.expression.expression);
}

/** The identifier a property, call, or index chain ultimately starts from. */
function rootIdentifier(node: ts.Node): string {
  let current: ts.Node = node;
  for (let depth = 0; depth < 32; depth += 1) {
    if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isCallExpression(current) || ts.isNewExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isParenthesizedExpression(current) || ts.isNonNullExpression(current) || ts.isAwaitExpression(current)) {
      current = current.expression;
      continue;
    }
    break;
  }
  return ts.isIdentifier(current) ? current.text : "";
}

/** Every identifier a binding pattern introduces, rest elements included. */
function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const names: string[] = [];
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

/**
 * The parameters a caller actually fills in.
 *
 * A TypeScript `this` parameter occupies the first slot in the AST and no slot at
 * the call site. Counting it would shift every position by one, which in this
 * file means promoting an Electron `event` from trusted to attacker-controlled —
 * exactly the mistake the whole adapter exists to avoid.
 */
function callerParameters(fn: ts.Node | undefined): readonly ts.ParameterDeclaration[] {
  const parameters = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters ?? [];
  const first = parameters[0];
  if (first && ts.isIdentifier(first.name) && first.name.text === "this") return parameters.slice(1);
  return parameters;
}

/** The initializer of a variable declared in this file under `name`, if any. */
function localInitializer(file: ParsedFile, name: string): ts.Expression | undefined {
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
    if (declaration.initializer) return declaration.initializer;
  }
  return undefined;
}

/**
 * The function a handler argument denotes.
 *
 * `ipcMain.handle("save", saveDocument)` is as common as an inline arrow, and
 * a named handler is where the interesting code usually lives. Only declarations
 * in this same file are resolved: an imported name could be anything, and a seed
 * bound to the wrong function is worse than no seed at all.
 */
function handlerOf(file: ParsedFile, argument: ts.Node | undefined): ts.Node | undefined {
  const direct = functionOf(argument);
  if (direct) return direct;
  if (!argument || !ts.isIdentifier(argument)) return undefined;
  for (const declaration of collect(file.source, ts.isFunctionDeclaration)) {
    if (declaration.name?.text === argument.text) return declaration;
  }
  const initializer = localInitializer(file, argument.text);
  return functionOf(initializer);
}

/** Two adapters, or two shapes in one adapter, can describe the same handler. */
function dedupe(entries: EntryPoint[]): EntryPoint[] {
  const seen = new Set<string>();
  const out: EntryPoint[] = [];
  for (const entry of entries) {
    const key = `${entry.kind}|${entry.method}|${entry.path}|${entry.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(entry);
  }
  return out;
}

/* ------------------------------------------------------------------------- *
 * A. Electron IPC
 * ------------------------------------------------------------------------- */

/**
 * `ipcMain` registrations. `handle` answers `ipcRenderer.invoke`, `on` answers
 * `send`, and the `Once` variants differ only in how long they stay registered —
 * a channel that can be called once can still be called once by an attacker.
 */
const IPC_REGISTRATIONS = new Set(["handle", "handleOnce", "on", "once", "addListener"]);

/**
 * Custom scheme handlers. `protocol.handle` is the modern form; the `register*`
 * family is the one still deployed in most shipped applications, and it is where
 * path traversal out of the packaged app directory habitually lives.
 */
const PROTOCOL_REGISTRATIONS = new Set([
  "handle",
  "registerFileProtocol",
  "registerStringProtocol",
  "registerBufferProtocol",
  "registerStreamProtocol",
  "registerHttpProtocol"
]);

/** Does this file work with Electron's main-process IPC surface at all? */
function usesElectron(file: ParsedFile): boolean {
  return /\bipcMain\b/.test(file.text) || importsFrom(file, /^electron$/);
}

/**
 * One `ipcMain` registration.
 *
 * The parameter positions here are the single easiest thing in this adapter to
 * get backwards, and getting them backwards is expensive in both directions. The
 * first parameter is an `IpcMainInvokeEvent`: the runtime constructs it, it
 * carries `sender` and `senderFrame`, and the renderer chooses none of it. It is
 * conventionally called `event`, which the generic model already treats as
 * inbound request data — so it has to be named as trusted explicitly, or every
 * `event.sender` read becomes an invented attacker-controlled flow. Everything
 * from the second parameter on is precisely what the renderer passed.
 */
function ipcEntry(file: ParsedFile, call: ts.CallExpression): EntryPoint {
  const channel = stringArgument(call, 0);
  const handler = handlerOf(file, call.arguments[1]);
  const parameters = callerParameters(handler);
  const [runtimeEvent, ...payload] = parameters;

  const trustedParameters = runtimeEvent ? boundNames(runtimeEvent.name) : [];
  const seeds: TaintSeed[] = [];
  for (const parameter of payload) {
    // A destructured payload seeds each bound name: `(event, { path, contents })`
    // hands the renderer's two values over under two local names, and a seed on
    // an object that never exists as a binding would reach nothing.
    for (const name of boundNames(parameter.name)) {
      seeds.push({ name, origin: `${name} (argument supplied by the renderer process)` });
    }
  }

  return {
    framework: ADAPTER_ID,
    kind: "ipc",
    method: "INVOKE",
    // A computed channel name is still a channel. Reporting `ipc` says "this is
    // reachable from the renderer and we could not read the address", which is
    // honest, where inventing a name would not be.
    path: channel ?? "ipc",
    line: lineOf(file, call),
    ...(handler ? { node: handler } : {}),
    ...(trustedParameters.length > 0 ? { trustedParameters } : {}),
    ...(seeds.length > 0 ? { seeds } : {})
  };
}

/**
 * A custom protocol handler.
 *
 * The first parameter is a `Request` whose URL the renderer chose by navigating
 * or fetching the scheme, so it is caller data in full. The second parameter of
 * the legacy `register*` forms is the completion callback — the handler's way of
 * answering, not a value anybody supplied — and it is deliberately not seeded.
 */
function protocolEntry(file: ParsedFile, call: ts.CallExpression): EntryPoint | null {
  const handler = handlerOf(file, call.arguments[1]);
  if (!handler) return null;
  const scheme = stringArgument(call, 0);
  const request = callerParameters(handler)[0];
  const seeds: TaintSeed[] = request
    ? boundNames(request.name).map((name) => ({
        name,
        origin: `${name} (request to a custom protocol handler)`
      }))
    : [];

  return {
    framework: ADAPTER_ID,
    kind: "ipc",
    method: "INVOKE",
    path: scheme ?? "protocol",
    line: lineOf(file, call),
    node: handler,
    ...(seeds.length > 0 ? { seeds } : {})
  };
}

function electronEntryPoints(file: ParsedFile): EntryPoint[] {
  const entries: EntryPoint[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    const method = calleeTail(call);
    const receiver = lastSegment(receiverName(call));
    if (receiver === "ipcMain" && IPC_REGISTRATIONS.has(method)) {
      entries.push(ipcEntry(file, call));
      continue;
    }
    if (receiver === "protocol" && PROTOCOL_REGISTRATIONS.has(method)) {
      const entry = protocolEntry(file, call);
      if (entry) entries.push(entry);
    }
  }
  return entries;
}

/* ------------------------------------------------------------------------- *
 * B. Command-line entry points
 * ------------------------------------------------------------------------- */

const CLI_MODULE = /^(commander|yargs|cac|sade|@oclif)(\/|$)/;

/** Calls that build a command before `.action()` closes the chain. */
const BUILDER_CALLS = new Set([
  "command",
  "argument",
  "arguments",
  "option",
  "requiredOption",
  "addOption",
  "alias",
  "describe",
  "description",
  "summary",
  "usage",
  "example",
  "version",
  "positional",
  "hook",
  "allowUnknownOption"
]);

/** Constructors and factories whose result is a program object. */
const PROGRAM_FACTORIES = /^(Command|createCommand|program|cac|sade|yargs)$/;

/** Calls that hand back the parsed command line rather than the program. */
const PARSED_ARGUMENT_CALLS = new Set(["opts", "optsWithGlobals", "parse", "parseSync", "parseAsync"]);

/**
 * The trailing parameter commander appends to every action handler.
 *
 * It is the `Command` object — a handle on the parser itself, not something the
 * invoker typed. Seeding it would make `command.opts()` and `command.name()`
 * look like attacker data in every commander program in existence.
 */
const PARSER_HANDLE = /^(command|program|cmd)$/;

function readsProcessArgv(file: ParsedFile): boolean {
  if (!/process\s*\.\s*argv/.test(file.text)) return false;
  return collect(file.source, ts.isPropertyAccessExpression).some(
    (access) => access.name.text === "argv" && ts.isIdentifier(access.expression) && access.expression.text === "process"
  );
}

/**
 * Is this file a command-line program?
 *
 * Requiring a real dependency on a parser, or a real read of `process.argv`,
 * is what keeps this family from claiming every file that happens to declare a
 * function called `action` — a name half the Redux and Vuex code in the world
 * uses for something entirely unrelated.
 */
function usesCommandLine(file: ParsedFile): boolean {
  return importsFrom(file, CLI_MODULE) || readsProcessArgv(file);
}

/**
 * Local names that hold a command-line program object.
 *
 * Collected so that a split chain still resolves: real programs are written as
 * `const build = program.command("build")` on one line and `build.action(...)`
 * twenty lines later, and a check that only understands one long fluent chain
 * sees neither of them.
 */
function programBindings(file: ParsedFile): Set<string> {
  const names = new Set<string>();

  for (const statement of file.source.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    if (!ts.isStringLiteralLike(statement.moduleSpecifier)) continue;
    if (!CLI_MODULE.test(statement.moduleSpecifier.text)) continue;
    const clause = statement.importClause;
    if (clause?.name) names.add(clause.name.text);
    const bindings = clause?.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) names.add(bindings.name.text);
    if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) names.add(element.name.text);
    }
  }

  // Declarations are visited in source order, so a binding derived from an
  // earlier one — `const cli = cac()`, then `const build = cli.command("build")` —
  // is recognised by the time the later declaration is read.
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    const initializer = declaration.initializer;
    if (!initializer) continue;

    const isRequire =
      ts.isCallExpression(initializer) &&
      expressionName(initializer.expression) === "require" &&
      (() => {
        const first = initializer.arguments[0];
        return Boolean(first && ts.isStringLiteralLike(first) && CLI_MODULE.test(first.text));
      })();

    const isFactory =
      (ts.isCallExpression(initializer) || ts.isNewExpression(initializer)) &&
      PROGRAM_FACTORIES.test(lastSegment(expressionName(initializer.expression)));

    const derivesFromProgram = names.has(rootIdentifier(initializer));

    if (isRequire || isFactory || derivesFromProgram) {
      for (const name of boundNames(declaration.name)) names.add(name);
    }
  }

  return names;
}

/** The file's own name, which is the program's name when no command declares one. */
function programName(file: ParsedFile): string {
  const base = path.basename(file.relativePath).replace(/\.[cm]?[jt]sx?$/i, "");
  return base.length > 0 ? base : "cli";
}

/** `"build <src> [dest]"` names the command `build`; the rest is its arguments. */
function commandName(literal: string | null, file: ParsedFile): string {
  if (!literal) return programName(file);
  const first = literal.trim().split(/\s+/)[0];
  // yargs writes its default command as `$0` or `*`, meaning "this program".
  if (!first || first === "$0" || first === "*") return programName(file);
  return first;
}

/**
 * The command literal an expression belongs to.
 *
 * Follows the fluent chain down, and then one hop further through a local
 * variable, because `program.command("deploy")` is routinely stored before the
 * options and the action are attached to it.
 */
function commandLiteralFor(file: ParsedFile, expression: ts.Node, depth = 0): string | null {
  if (depth > 3) return null;
  let current: ts.Node = expression;
  for (let step = 0; step < 32; step += 1) {
    if (ts.isCallExpression(current)) {
      if (calleeTail(current) === "command") {
        const literal = stringArgument(current, 0);
        if (literal) return literal;
      }
      current = current.expression;
      continue;
    }
    if (ts.isPropertyAccessExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isParenthesizedExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    break;
  }
  if (ts.isIdentifier(current)) {
    const initializer = localInitializer(file, current.text);
    if (initializer) return commandLiteralFor(file, initializer, depth + 1);
  }
  return null;
}

/** Every call in the fluent chain a call hangs off. */
function chainCalls(call: ts.CallExpression): ts.CallExpression[] {
  const calls: ts.CallExpression[] = [];
  let current: ts.Node = call.expression;
  for (let step = 0; step < 32; step += 1) {
    if (ts.isCallExpression(current)) {
      calls.push(current);
      current = current.expression;
      continue;
    }
    if (ts.isPropertyAccessExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isParenthesizedExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    break;
  }
  return calls;
}

/**
 * The bindings a command handler receives from the command line.
 *
 * Every parameter counts — a declared `.argument("<file>")` arrives as its own
 * positional parameter, and the options object is as caller-chosen as the
 * positionals are. The one exception is the parser handle commander appends
 * last, which is the library's own object rather than anything typed.
 */
function commandLineSeeds(fn: ts.Node | undefined): TaintSeed[] {
  const parameters = callerParameters(fn);
  const seeds: TaintSeed[] = [];
  parameters.forEach((parameter, index) => {
    // Only ever the *last of several*: commander passes the parsed options first
    // and the Command object after it, so a handler with a single parameter is
    // holding data whatever it called it — `.argument("<cmd>").action(cmd => ...)`
    // names a value the invoker typed, and dropping it would lose the flow.
    const isParserHandle =
      index > 0 &&
      index === parameters.length - 1 &&
      ts.isIdentifier(parameter.name) &&
      PARSER_HANDLE.test(parameter.name.text);
    if (isParserHandle) return;
    for (const name of boundNames(parameter.name)) {
      seeds.push({ name, origin: `${name} (command-line argument)` });
    }
  });
  return seeds;
}

function commandEntry(file: ParsedFile, call: ts.CallExpression, name: string, handler: ts.Node): EntryPoint {
  const seeds = commandLineSeeds(handler);
  return {
    framework: ADAPTER_ID,
    kind: "cli",
    method: "RUN",
    path: name,
    line: lineOf(file, call),
    node: handler,
    ...(seeds.length > 0 ? { seeds } : {})
  };
}

/**
 * `.action(handler)` — commander, cac and sade all close a command this way.
 *
 * The chain has to look like a command builder, or the receiver has to be a name
 * this file already established as a program. Without that test a Redux
 * `store.action(...)` in a repository that merely reads `process.argv` somewhere
 * would be reported as a command, and its parameters seeded as user input.
 */
function actionEntries(file: ParsedFile, bindings: Set<string>): EntryPoint[] {
  const entries: EntryPoint[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeTail(call) !== "action") continue;
    const handler = handlerOf(file, call.arguments[0]);
    if (!handler) continue;
    const looksLikeBuilder = chainCalls(call).some((link) => BUILDER_CALLS.has(calleeTail(link)));
    if (!looksLikeBuilder && !bindings.has(rootIdentifier(call.expression))) continue;
    entries.push(commandEntry(file, call, commandName(commandLiteralFor(file, call.expression), file), handler));
  }
  return entries;
}

/** The function held by a named property of an object literal, however written. */
function propertyFunction(file: ParsedFile, object: ts.ObjectLiteralExpression, key: string): ts.Node | undefined {
  for (const property of object.properties) {
    const name = property.name ? property.name.getText(file.source).replace(/["']/g, "") : "";
    if (name !== key) continue;
    if (ts.isMethodDeclaration(property)) return property;
    if (ts.isPropertyAssignment(property)) return handlerOf(file, property.initializer);
    if (ts.isShorthandPropertyAssignment(property)) return handlerOf(file, property.name);
  }
  return undefined;
}

function propertyLiteral(file: ParsedFile, object: ts.ObjectLiteralExpression, key: string): string | null {
  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    if (property.name.getText(file.source).replace(/["']/g, "") !== key) continue;
    return literalTextOf(property.initializer);
  }
  return null;
}

/**
 * yargs commands, which carry their handler as the fourth argument or as the
 * `handler` property of a module object. The handler's `argv` is the whole
 * parsed command line, so it is seeded whatever it is called and however it is
 * destructured — `({ file, force })` names two command-line arguments.
 */
function yargsEntries(file: ParsedFile): EntryPoint[] {
  const entries: EntryPoint[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeTail(call) !== "command") continue;
    const first = call.arguments[0];
    if (!first) continue;

    if (ts.isObjectLiteralExpression(first)) {
      const handler = propertyFunction(file, first, "handler");
      if (!handler) continue;
      entries.push(commandEntry(file, call, commandName(propertyLiteral(file, first, "command"), file), handler));
      continue;
    }

    // Positional form: (command, description, builder, handler). Only the fourth
    // slot is the handler — the third is the builder, which receives the yargs
    // instance and not the user's arguments, and seeding it would be a lie.
    const handler = handlerOf(file, call.arguments[3]);
    if (!handler) continue;
    entries.push(commandEntry(file, call, commandName(stringArgument(call, 0), file), handler));
  }
  return entries;
}

/**
 * oclif commands, whose `run` method is the entry point and whose arguments
 * arrive through `this.parse(...)` rather than through a parameter. The
 * destructured `{ args, flags }` is the parsed command line exactly.
 */
function oclifEntries(file: ParsedFile): EntryPoint[] {
  if (!importsFrom(file, /^@oclif(\/|$)/)) return [];
  const entries: EntryPoint[] = [];
  for (const method of collect(file.source, ts.isMethodDeclaration)) {
    if (!ts.isIdentifier(method.name) || method.name.text !== "run") continue;

    const seeds = commandLineSeeds(method);
    if (method.body) {
      walk(method.body, (node) => {
        if (!ts.isVariableDeclaration(node) || !node.initializer) return;
        let parsesArguments = false;
        walk(node.initializer, (inner) => {
          if (!ts.isCallExpression(inner)) return;
          if (!ts.isPropertyAccessExpression(inner.expression)) return;
          if (inner.expression.expression.kind !== ts.SyntaxKind.ThisKeyword) return;
          if (inner.expression.name.text === "parse") parsesArguments = true;
        });
        if (!parsesArguments) return;
        for (const name of boundNames(node.name)) {
          seeds.push({ name, origin: `${name} (command-line argument)` });
        }
      });
    }

    const declaringClass = method.parent && ts.isClassLike(method.parent) ? method.parent : undefined;
    entries.push({
      framework: ADAPTER_ID,
      kind: "cli",
      method: "RUN",
      path: staticIdOf(file, declaringClass) ?? programName(file),
      line: lineOf(file, method),
      node: method,
      ...(seeds.length > 0 ? { seeds } : {})
    });
  }
  return entries;
}

/** `static id = "db:migrate"` is the name this command answers to. */
function staticIdOf(file: ParsedFile, declaringClass: ts.ClassLikeDeclaration | undefined): string | null {
  if (!declaringClass) return null;
  for (const member of declaringClass.members) {
    if (!ts.isPropertyDeclaration(member) || !member.initializer) continue;
    if (!member.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.StaticKeyword)) continue;
    if (member.name.getText(file.source) !== "id") continue;
    return literalTextOf(member.initializer);
  }
  return null;
}

/** Does this expression read the command line rather than merely mention it? */
function readsCommandLine(expression: ts.Node, bindings: Set<string>): boolean {
  let found = false;
  walk(expression, (node) => {
    if (found) return;
    if (ts.isPropertyAccessExpression(node) && node.name.text === "argv") {
      if (ts.isIdentifier(node.expression) && node.expression.text === "process") found = true;
      else if (bindings.has(rootIdentifier(node.expression))) found = true;
      return;
    }
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    // `hideBin(process.argv)` is yargs's own name for the same read, and it is
    // how nearly every yargs program written since v17 gets its arguments.
    if (tail === "hideBin") found = true;
    else if (PARSED_ARGUMENT_CALLS.has(tail) && bindings.has(rootIdentifier(node.expression))) found = true;
  });
  return found;
}

/**
 * The program itself, for arguments read outside any command handler.
 *
 * `const [, , target] = process.argv` at the top of a script binds attacker
 * influence to `target` with no handler anywhere in sight, and the module body is
 * where that binding lives — so the module body is the node this entry point
 * points at. When commands were already found and there is nothing extra to seed,
 * the file's own name adds an address and no information, so it is left out.
 */
function programEntry(file: ParsedFile, bindings: Set<string>, hasCommands: boolean): EntryPoint | null {
  const seeds: TaintSeed[] = [];
  let line = 0;

  for (const statement of file.source.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!declaration.initializer) continue;
      if (!readsCommandLine(declaration.initializer, bindings)) continue;
      if (line === 0) line = lineOf(file, declaration);
      for (const name of boundNames(declaration.name)) {
        seeds.push({ name, origin: `${name} (command-line argument)` });
      }
    }
  }

  if (seeds.length > 0) {
    return {
      framework: ADAPTER_ID,
      kind: "cli",
      method: "RUN",
      path: programName(file),
      line,
      node: file.source,
      seeds
    };
  }

  if (hasCommands) return null;

  // No seeds and no commands: the file can still be the executable itself. A
  // shebang or a `parse()` call is the only evidence available here — package.json
  // `bin` is not visible to a single-file analyser — and recording the address
  // is what lets a finding in this file say where it is reachable from.
  const shebang = file.text.startsWith("#!");
  const parseCall = collect(file.source, ts.isCallExpression).find(
    (call) => PARSED_ARGUMENT_CALLS.has(calleeTail(call)) && bindings.has(rootIdentifier(call.expression))
  );
  if (!shebang && !parseCall) return null;

  return {
    framework: ADAPTER_ID,
    kind: "cli",
    method: "RUN",
    path: programName(file),
    line: parseCall ? lineOf(file, parseCall) : 1
  };
}

function commandLineEntryPoints(file: ParsedFile): EntryPoint[] {
  const bindings = programBindings(file);
  const entries = [...actionEntries(file, bindings), ...yargsEntries(file), ...oclifEntries(file)];
  const program = programEntry(file, bindings, entries.length > 0);
  if (program) entries.push(program);
  return entries;
}

/* ------------------------------------------------------------------------- *
 * The adapter
 * ------------------------------------------------------------------------- */

/** Cheap enough to run over every file before either family walks an AST. */
const MENTIONS_A_LOCAL_PROGRAM = /ipcMain|electron|commander|yargs|\bcac\b|\bsade\b|@oclif|process\.argv/;

export const desktopCliAdapter: FrameworkAdapter = {
  id: ADAPTER_ID,
  applies(file: ParsedFile): boolean {
    if (!MENTIONS_A_LOCAL_PROGRAM.test(file.text)) return false;
    return usesElectron(file) || usesCommandLine(file);
  },
  detect(file: ParsedFile): EntryPoint[] {
    // Each family re-checks its own evidence: `applies` is an either-or, and a
    // command-line tool that never touches Electron must not have `protocol.handle`
    // read out of some unrelated object called `protocol`.
    const entries: EntryPoint[] = [];
    if (usesElectron(file)) entries.push(...electronEntryPoints(file));
    if (usesCommandLine(file)) entries.push(...commandLineEntryPoints(file));
    return dedupe(entries);
  }
};
