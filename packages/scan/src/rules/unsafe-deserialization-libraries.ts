import ts from "typescript";
import { calleeName, calleeTail, collect } from "../ast/helpers.js";
import { analyzeFunction, functionsIn, taintOrigin } from "../ast/taint.js";
import { routeOf } from "./attribution.js";
import { locationOf, sourceEvidence, type Rule, type RuleContext } from "./context.js";

/**
 * Deserialisers that rebuild functions, in the libraries `unsafe-deserialization-parser`
 * does not name.
 *
 * That rule owns `node-serialize`'s `unserialize`, js-yaml's `load` without a safe
 * schema and its `unsafeLoad`, `v8.deserialize`, and an evaluating `JSON.parse`
 * reviver. Four more reconstruct executable code from their input and are just as
 * direct a route from a request to code execution:
 *
 *  - `funcster.deepDeserialize` — revives serialised functions by evaluating them;
 *  - `cryo.parse` — restores functions and prototypes, and is the documented RCE;
 *  - js-yaml's `unsafeLoadAll`, the multi-document twin of `unsafeLoad`;
 *  - BSON `deserialize(…, { evalFunctions: true })`, which evaluates stored code.
 *
 * Reported only when the input is caller-controlled within the function, like the
 * rule it complements; a deserialiser over the application's own file is a different
 * and much smaller question.
 */
export const unsafeDeserializationLibraries: Rule = {
  id: "unsafe-deserialization-library",
  category: "unsafe_deserialization",
  describes: "caller data reconstructed by funcster, cryo, js-yaml unsafeLoadAll, or BSON with evalFunctions",
  run(context: RuleContext) {
    if (!/funcster|cryo|unsafeLoadAll|evalFunctions/.test(context.file.text)) return;
    const reported = new Set<number>();
    for (const fn of functionsIn(context.file.source)) {
      const scope = analyzeFunction(context.file, fn);
      for (const call of collect(fn, ts.isCallExpression)) {
        const sink = sinkOf(context, call);
        if (!sink || !call.arguments[0]) continue;
        const origin = taintOrigin(call.arguments[0], scope);
        if (!origin) continue;
        const location = locationOf(context, call);
        if (reported.has(location.line)) continue;
        reported.add(location.line);
        context.report({
          ruleId: "unsafe-deserialization-library",
          category: "unsafe_deserialization",
          title: `Caller-controlled data is deserialised by ${sink}, which can rebuild executable code`,
          severity: "critical",
          verification: "strong_evidence",
          summary: `${sink} reconstructs functions or prototypes from its input, and the input here is derived from ${origin}. A payload crafted for this format runs code in the server process when it is parsed.`,
          impact: "Arbitrary code execution in the server process at the moment the request is parsed, before any application logic can inspect the result.",
          remediation:
            "Use a data-only format for anything a caller can send — `JSON.parse`, or js-yaml's `load` with the default schema in v4 — and validate the result against a schema. Keep function-reviving serialisers for data the application wrote and signed itself.",
          verificationPlan:
            "In a local instance only, send a payload in this format whose revived function writes a marker file such as `/tmp/myrqen-probe`, and confirm no file appears. Never send a payload with any other effect.",
          taxonomy: ["CWE-502", "CWE-94", "OWASP-A08"],
          location,
          ...routeOf(context, call),
          evidence: [
            sourceEvidence(context, call, `${sink} is given caller-controlled input.`),
            { kind: "source", description: `Data flow: ${origin} reaches ${sink} in the same function.` }
          ],
          reasoning: `Taint from ${origin} reaches ${sink}, a deserialiser that reconstructs code.`
        });
      }
    }
  }
};

function sinkOf(context: RuleContext, call: ts.CallExpression): string | null {
  const name = calleeName(call);
  const tail = calleeTail(call);
  if (tail === "deepDeserialize" && /funcster/.test(context.file.text)) return `${name}()`;
  if (/^(?:cryo|Cryo)\.parse$/.test(name)) return `${name}()`;
  if (tail === "unsafeLoadAll") return `${name}()`;
  if (tail === "deserialize" && call.arguments.slice(1).some((argument) => /evalFunctions\s*:\s*true/.test(argument.getText(context.file.source)))) {
    return `${name}() with evalFunctions`;
  }
  return null;
}
