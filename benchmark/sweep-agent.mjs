/**
 * Drive the paired agent sweep across an exhausted free tier.
 *
 * `score-agent.mjs` measures one arm per invocation. This runs both arms for one case back to
 * back, which is what makes the comparison paired: an interrupted sweep still yields cases
 * measured under both conditions, and a paired test resolves a difference that two independent
 * proportions cannot at these sample sizes (ruling U7).
 *
 * The ordering matters twice over. Cases alternate vulnerable and safe, so an early stop leaves
 * a balanced set rather than nineteen vulnerable cases and no measure of false positives. Arms
 * alternate within a case, so quota running out mid-sweep costs a case rather than an arm.
 *
 * Everything is resumable through `score-agent.mjs`'s own cache — only answered runs are
 * cached, so a refused run is retried on the next pass and a completed one is never repeated.
 * Re-run this as many times as it takes; it converges.
 *
 * Usage:
 *   node benchmark/sweep-agent.mjs --model opencode/nemotron-3-ultra-free --budget 3000
 */
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";

import { splitOf } from "./split.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");

function flag(name, fallback) {
  const hit = process.argv.indexOf(`--${name}`);
  if (hit === -1) return fallback;
  const next = process.argv[hit + 1];
  return next === undefined || next.startsWith("--") ? true : next;
}

const MODEL = String(flag("model", "opencode/nemotron-3-ultra-free"));
const CORPUS = String(flag("corpus", "benchmark/reference"));
const SPLIT = String(flag("split", "dev"));
const RUNS = String(flag("runs", 1));
const TIMEOUT = String(flag("timeout", 280));
/** Wall-clock ceiling in seconds. A sweep against a depleted quota must be interruptible. */
const BUDGET_MS = Number(flag("budget", 3000)) * 1000;
const ARMS = ["alone", "skill"];

/** Dev-half cases, vulnerable and safe interleaved so an early stop stays balanced. */
async function orderedCases() {
  const corpusDir = path.resolve(ROOT, CORPUS);
  const families = (await fs.readdir(corpusDir, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter((family) => splitOf(family) === SPLIT);

  const cases = [];
  for (const family of families) {
    const raw = JSON.parse(await fs.readFile(path.join(corpusDir, family, "cases.json"), "utf8"));
    for (const entry of Array.isArray(raw) ? raw : (raw.cases ?? [])) cases.push(entry);
  }

  const vulnerable = cases.filter((entry) => entry.kind === "vulnerable");
  const safe = cases.filter((entry) => entry.kind !== "vulnerable");
  const order = [];
  for (let i = 0; i < Math.max(vulnerable.length, safe.length); i += 1) {
    if (vulnerable[i]) order.push(vulnerable[i].id);
    if (safe[i]) order.push(safe[i].id);
  }
  return order;
}

function cacheSize() {
  return fs
    .readdir(path.join(ROOT, "benchmark", ".agent-cache"))
    .then((entries) => entries.length)
    .catch(() => 0);
}

async function measure(arm, id) {
  const args = [
    path.join(ROOT, "benchmark", "score-agent.mjs"),
    "--corpus", CORPUS,
    "--split", SPLIT,
    "--runs", RUNS,
    "--arm", arm,
    "--model", MODEL,
    "--timeout", TIMEOUT,
    "--pace", "1",
    "--only", id
  ];
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (chunk) => {
      out += chunk;
    });
    child.stderr.on("data", () => undefined);
    child.on("close", () => {
      const line = out.split("\n").find((row) => /run \d/.test(row)) ?? "";
      resolve(line.trim());
    });
  });
}

const started = Date.now();
const order = await orderedCases();
process.stdout.write(
  `\npaired agent sweep\nmodel: ${MODEL}\ncorpus: ${CORPUS} --split ${SPLIT}\n` +
    `${order.length} case(s) x ${ARMS.length} arm(s), budget ${Math.round(BUDGET_MS / 1000)}s\n` +
    `cache: ${await cacheSize()} answered run(s) already\n\n`
);

let done = 0;
const spent = () => Date.now() - started;
outer: for (const id of order) {
  for (const arm of ARMS) {
    /*
     * Checked between arms, not only between cases. A single run can take the full timeout, so
     * a budget honoured only at case boundaries overshoots by two runs — which on a depleted
     * quota is the difference between a bounded chunk and a hang.
     */
    if (spent() > BUDGET_MS) {
      process.stdout.write(`\nbudget reached after ${done} complete case(s). Re-run to continue.\n`);
      break outer;
    }
    const line = await measure(arm, id);
    process.stdout.write(`  [${arm.padEnd(5)}] ${line || `${id}: no line`}\n`);
  }
  done += 1;
}

process.stdout.write(`\ncache: ${await cacheSize()} answered run(s)\n`);
process.stdout.write(
  "Score with:\n" +
    `  node benchmark/score-agent.mjs --corpus ${CORPUS} --split ${SPLIT} --arm alone --model ${MODEL} --cached-only\n` +
    `  node benchmark/score-agent.mjs --corpus ${CORPUS} --split ${SPLIT} --arm skill --model ${MODEL} --cached-only\n`
);
