import { test } from "node:test";
import assert from "node:assert/strict";
import { commandInterpreterArgument } from "../dist/rules/command-interpreter-argument.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("sh -c with caller text is reported; a fixed program with an argument array is not", async () => {
  const found = await run(commandInterpreterArgument, `
    const { spawn, execFile } = require("node:child_process");
    module.exports = (app) => {
      app.post("/diagnostics", (req, res) => {
        const child = spawn("sh", ["-c", \`ping -c 1 \${req.body.host}\`]);
        child.on("close", (code) => res.json({ code }));
      });
      app.post("/lookup", (req, res) => {
        execFile("dig", ["+short", "--", req.body.host], (error, stdout) => res.json({ stdout }));
      });
    };
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, "critical");
  assert.equal(found[0].category, "command_injection");
});

test("node -e with a body field through a helper is reported", async () => {
  const found = await run(commandInterpreterArgument, `
    import { execFileSync } from "child_process";
    function evaluate(expression) {
      return execFileSync("node", ["-e", "console.log(" + expression + ")"]).toString();
    }
    export function calculator(req, res) {
      res.send(evaluate(req.body.expression));
    }
  `);
  assert.equal(found.length, 1);
});

test("execaCommand of a query value is reported; execa's template tag is not a sink", async () => {
  const found = await run(commandInterpreterArgument, `
    import { execa, execaCommand, $ } from "execa";
    export async function run(req, res) {
      const { stdout } = await execaCommand(req.query.cmd);
      res.send(stdout);
    }
    export async function safe(req, res) {
      const { stdout } = await $\`git log --oneline -- \${req.query.file}\`;
      res.send(stdout);
    }
  `);
  assert.equal(found.length, 1);
});
