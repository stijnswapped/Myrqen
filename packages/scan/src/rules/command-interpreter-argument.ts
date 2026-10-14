import ts from "typescript";
import { calleeName, calleeTail, collect, dynamicParts, walk } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, rootOf, taintOrigin } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { parameterIndex, taintThroughCallers } from "./caller-taint.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * A shell or interpreter started with a fixed name and handed caller text as its program.
 *
 * `command-injection` treats `spawn(file, [args])` as the safe form, and it is — for
 * an ordinary program. It is not when the program *is* an interpreter and the
 * argument is the script it runs: `spawn("sh", ["-c", userText])`,
 * `execFile("node", ["-e", code])`, `spawnSync("powershell", ["-Command", text])`.
 * The argument array is the shell command line by another route, and the other rule
 * reads `-c` as an option that takes a value and stops there, so this shape was
 * reported by nothing. Deno and Bun already have this check; this is the
 * `child_process` half.
 *
 * Also covered, because they share the shape: execa's `execaCommand(text)`, which
 * splits a string into a program and its arguments, and `execa(program, …)` where the
 * caller chooses the program. execa's tagged template (`` $`…` ``) escapes its
 * interpolations and is deliberately not a sink.
 */
const INTERPRETER = /^(?:(?:\/usr)?(?:\/local)?\/bin\/)?(?:sh|bash|zsh|dash|ksh|fish|cmd|cmd\.exe|powershell|powershell\.exe|pwsh|node|nodejs|python|python3|perl|ruby|php|osascript)$/i;
const SCRIPT_SWITCH = /^(?:-c|-e|--eval|-p|--print|-r|\/c|\/k|-Command|-command|-EncodedCommand|-lc|-ic|-ec)$/;
const ARGV_SINKS = new Set(["spawn", "spawnSync", "execFile", "execFileSync"]);
const CHILD_PROCESS = /["'`](?:node:)?child_process["'`]/;
const EXECA = /["'`]execa["'`]/;

export const commandInterpreterArgument: Rule = {
  id: "command-interpreter-argument",
  category: "command_injection",
  describes: "caller text passed as the script of a shell or interpreter started by name",
  run(context: RuleContext) {
    const usesChildProcess = CHILD_PROCESS.test(context.file.text);
    const usesExeca = EXECA.test(context.file.text);
    if (!usesChildProcess && !usesExeca) return;
    const reported = new Set<number>();

    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);
      const originOf = (expression: ts.Expression): { origin: string; caller?: ts.CallExpression } | null => {
        const own = taintOrigin(expression, scope);
        if (own) return { origin: own };
        for (const part of [expression, ...dynamicParts(expression)]) {
          const root = rootOf(part);
          if (!root) continue;
          const index = parameterIndex(fn, root);
          if (index < 0) continue;
          const through = taintThroughCallers(context, fn, index);
          if (through) return { origin: through.origin, caller: through.call };
        }
        return null;
      };

      const report = (call: ts.CallExpression, origin: string, how: string, caller?: ts.CallExpression): void => {
        const location = locationOf(context, call);
        if (reported.has(location.line)) return;
        reported.add(location.line);
        context.report({
          ruleId: "command-interpreter-argument",
          category: "command_injection",
          title: `Caller-controlled text is run as a program by ${calleeName(call)}()`,
          severity: "critical",
          verification: "strong_evidence",
          summary: `${how} The text comes from ${origin}, so the caller writes the commands the server executes, with the server's privileges.`,
          impact:
            "Arbitrary command execution on the server: reading secrets and source, pivoting to internal services, and persisting access. Every other control in the application is moot once this is reachable.",
          remediation:
            "Do not pass request data as a script. Run the specific program you need directly with a fixed executable and an argument array, validate each argument against an allowlist, and put `--` before any positional argument the caller influences. If a shell feature is genuinely needed, the command text must be a constant.",
          verificationPlan:
            "In a local instance only, send a value that would append a harmless command — `; echo myrqen-probe > /tmp/myrqen-probe` for a POSIX shell, `require('fs').writeFileSync('/tmp/myrqen-probe','')` for `node -e` — and confirm no file appears. Never send a destructive or network command.",
          taxonomy: ["CWE-78", "CWE-94", "OWASP-A03"],
          location,
          ...routeOf(context, caller ?? call),
          evidence: [
            sourceEvidence(context, call, how),
            ...(caller ? [sourceEvidence(context, caller, `The value is supplied here, from ${origin}.`)] : []),
            { kind: "source", description: `Data flow: ${origin} becomes program text for ${calleeName(call)}().` }
          ],
          reasoning: `${origin} reaches the script position of an interpreter invocation. command-injection treats an argument array as safe and does not read this slot.`
        });
      };

      for (const call of collect(fn, ts.isCallExpression)) {
        if (innermost(call) !== fn) continue;
        const tail = calleeTail(call);
        const name = calleeName(call);

        if (usesChildProcess && ARGV_SINKS.has(tail)) {
          const program = call.arguments[0];
          const argv = call.arguments[1];
          if (!program || !ts.isStringLiteralLike(program) || !INTERPRETER.test(program.text)) continue;
          if (!argv || !ts.isArrayLiteralExpression(argv)) continue;
          const elements = argv.elements;
          for (let index = 0; index < elements.length - 1; index += 1) {
            const flag = elements[index]!;
            if (!ts.isStringLiteralLike(flag) || !SCRIPT_SWITCH.test(flag.text)) continue;
            const script = elements[index + 1]!;
            if (ts.isSpreadElement(script)) continue;
            const found = originOf(script);
            if (!found) continue;
            report(call, found.origin, `\`${program.text} ${flag.text}\` runs its next argument as a ${/node|python|perl|ruby|php/.test(program.text) ? "program" : "shell command line"}, and that argument carries caller text.`, found.caller);
            break;
          }
          continue;
        }

        if (usesExeca && /^(?:execaCommand|execaCommandSync)$/.test(tail) && call.arguments[0]) {
          const found = originOf(call.arguments[0]);
          if (found) report(call, found.origin, `\`${tail}\` splits its string into a program and arguments, and the string carries caller text.`, found.caller);
          continue;
        }
        if (usesExeca && /^(?:execa|execaSync)$/.test(name) && call.arguments[0]) {
          const first = call.arguments[0];
          const found = originOf(first);
          if (found) {
            report(call, found.origin, "The program execa starts is chosen by the caller.", found.caller);
            continue;
          }
          if (shellOption(call) && call.arguments[1]) {
            const args = call.arguments[1];
            const argOrigin = ts.isArrayLiteralExpression(args)
              ? args.elements.map((element) => (ts.isSpreadElement(element) ? null : originOf(element))).find(Boolean)
              : originOf(args);
            if (argOrigin) report(call, argOrigin.origin, "execa is called with `shell: true`, so its arguments are joined and interpreted by a shell, and one of them carries caller text.", argOrigin.caller);
          }
        }
      }
    }
  }
};

function shellOption(call: ts.CallExpression): boolean {
  let enabled = false;
  for (const argument of call.arguments) {
    if (!ts.isObjectLiteralExpression(argument)) continue;
    walk(argument, (node) => {
      if (ts.isPropertyAssignment(node) && node.name.getText() === "shell" && node.initializer.kind !== ts.SyntaxKind.FalseKeyword) enabled = true;
    });
  }
  return enabled;
}

function innermost(node: ts.Node): ts.Node {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) || ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
      return current;
    }
    if (ts.isSourceFile(current)) return current;
    current = current.parent;
  }
  return node.getSourceFile();
}
