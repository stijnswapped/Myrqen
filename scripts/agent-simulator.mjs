#!/usr/bin/env node
/**
 * Plays the host agent's role against an already-started Myrqen session.
 *
 * In the product your coding agent does this work. This script exists so the
 * local walkthrough produces real, validated findings without wiring up an agent
 * first. It uses the same CLI contract the skill uses: nothing is written to
 * session state except through `myrqen`.
 *
 *   myrqen auto                                   # start a session, answer the sync prompt
 *   node scripts/agent-simulator.mjs --project fixtures/vuln-shop --target http://127.0.0.1:4010
 *   myrqen session finish
 */
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { analyze, UNSAFE_PROBES } from "../benchmark/analyzer.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const CLI = process.env.MYRQEN_CLI ?? path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");
const argv = process.argv.slice(2);

function option(name, fallback = null) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return fallback;
  const value = argv[index + 1];
  return value && !value.startsWith("--") ? value : true;
}

const projectDir = path.resolve(option("project", "fixtures/vuln-shop"));
const target = option("target", "http://127.0.0.1:4010");
const identitiesFile = option("ground-truth", path.join(projectDir, "ground-truth.json"));

function run(args, input) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: projectDir,
      env: { ...process.env, MYRQEN_NO_COLOR: "1" },
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    if (input !== undefined) child.stdin.end(input);
  });
}

async function json(args, input) {
  const result = await run(["--json", ...args], input);
  const start = result.stdout.indexOf("{");
  if (start === -1) {
    throw new Error(`no JSON from "${args.join(" ")}":\n${result.stdout}${result.stderr}`);
  }
  return JSON.parse(result.stdout.slice(start));
}

function log(message) {
  process.stdout.write(`${message}\n`);
}

const context = await json(["session", "context"]).catch(() => null);
if (!context) {
  process.stderr.write(
    `No active Myrqen session in ${projectDir}.\nStart one first, for example:\n  cd ${projectDir} && myrqen auto\n`
  );
  process.exit(1);
}

log(`Session ${context.localReportId} · effort ${context.effort.resolved} · cloud ${context.cloud.state}`);

let groundTruth;
try {
  groundTruth = JSON.parse(await fs.readFile(identitiesFile, "utf8"));
} catch {
  groundTruth = { identities: [] };
}

await run(["session", "agent", "--name", "agent-simulator", "--model", "deterministic-analyzer"]);

for (const phase of ["scope", "discovery", "source_review"]) {
  await run(["phase", "start", phase]);
}
log("Mapping application and reviewing source...");

// Prove the safety gate refuses destructive plans before doing anything else.
let blocked = 0;
for (const probe of UNSAFE_PROBES) {
  const args = ["action", "check", "--intent", probe.intent];
  if (probe.description) args.push("--description", probe.description);
  if (probe.method) args.push("--method", probe.method);
  if (probe.repeatCount) args.push("--repeat", String(probe.repeatCount));
  const decision = await json(args).catch(() => ({ allowed: true }));
  if (!decision.allowed) blocked += 1;
}
log(`Safety policy refused ${blocked}/${UNSAFE_PROBES.length} deliberately unsafe plans.`);

for (const origin of groundTruth.promptInjection?.mustNotAuthorize ?? []) {
  const decision = await json(["target", "authorize", origin]).catch(() => ({ decision: "denied" }));
  log(`Authorization for ${origin}: ${decision.decision}`);
}

for (const phase of ["runtime_validation", "access_control"]) {
  await run(["phase", "start", phase]);
}
log(`Validating candidates against ${target}...`);

const analysis = await analyze({
  repoRoot: projectDir,
  baseUrl: target,
  identities: groundTruth.identities ?? []
});

await run(["phase", "start", "validation"]);

let created = 0;
let merged = 0;
let rejected = 0;
for (const finding of analysis.findings) {
  const result = await json(["finding", "submit"], JSON.stringify(finding));
  if (!result.accepted) rejected += 1;
  else if (result.action === "merged_as_corroboration") merged += 1;
  else created += 1;
}

// A second pass reaching the same root cause becomes corroboration, not a duplicate.
if (analysis.findings.length > 0) {
  const duplicate = {
    ...analysis.findings[0],
    evidence: [
      {
        kind: "source",
        description: "A second review pass reached the same root cause from the source path rather than the differential test."
      }
    ]
  };
  const result = await json(["finding", "submit"], JSON.stringify(duplicate));
  if (result.action === "merged_as_corroboration") merged += 1;
}

log(`Findings: ${created} recorded, ${merged} merged as corroboration, ${rejected} rejected.`);

for (const note of analysis.notes.coverage) await run(["note", "coverage", note]);
for (const note of analysis.notes.limitations) await run(["note", "limitation", note]);
await run(["metrics", "token", "--source", "estimated", "--count", "412000", "--estimator", "transcript-v1"]);

for (const phase of ["scope", "discovery", "source_review", "runtime_validation", "access_control", "validation"]) {
  await run(["phase", "complete", phase]);
}

log("");
log("Assessment complete. Finish the session to generate the report:");
log(`  cd ${projectDir} && myrqen session finish`);
