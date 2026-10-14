#!/usr/bin/env node
/**
 * Every detection number this project has, in one place, each labelled with what
 * it cannot say.
 *
 * There are two measurements and they answer different questions. Quoting one as
 * the other is the easiest mistake to make about this product and the most
 * damaging, because the two differ by an entire component:
 *
 *   benchmark/score-corpus.mjs   the static pass, each case scanned alone in an
 *                                empty directory, no agent involved
 *   benchmark/run.mjs            the whole product path — static pass, agent
 *                                validation, dedupe, report — against two fixture
 *                                applications the rules were developed on
 *
 * The first cannot say what the agent adds. The second cannot say anything about
 * generalisation. Neither is "the detection rate", and a sentence that gives one
 * number without its caveat is wrong however accurate the number is.
 *
 *   node scripts/detection-report.mjs          read the last recorded runs
 *   node scripts/detection-report.mjs --run    re-measure everything first
 *
 * Reading by default is deliberate: re-measuring takes minutes, and a stale number
 * with its date attached is more useful than an impatient person skipping the
 * report entirely. Every figure is printed with the time it was produced.
 */
import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..");
const REFRESH = process.argv.includes("--run");

const bold = (text) => (process.env.NO_COLOR ? text : `[1m${text}[0m`);
const dim = (text) => (process.env.NO_COLOR ? text : `[2m${text}[0m`);
const say = (line = "") => process.stdout.write(`${line}\n`);

/** Corpora present on disk, development first, then held-out in order. */
async function corpora() {
  const entries = await readdir(path.join(ROOT, "benchmark"), { withFileTypes: true });
  const names = entries
    .filter((entry) => entry.isDirectory() && (entry.name === "corpus" || entry.name.startsWith("holdout")))
    .map((entry) => entry.name)
    .sort((a, b) => (a === "corpus" ? -1 : b === "corpus" ? 1 : a.localeCompare(b)));
  return names;
}

async function readJson(file) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch {
    return null;
  }
}

function age(iso) {
  if (!iso) return "never measured";
  const when = new Date(iso);
  const hours = (Date.now() - when.getTime()) / 3_600_000;
  const stamp = when.toISOString().replace("T", " ").slice(0, 16);
  if (hours < 1) return `${stamp} (just now)`;
  if (hours < 48) return `${stamp} (${Math.round(hours)}h ago)`;
  return `${stamp} (${Math.round(hours / 24)}d ago)`;
}

const show = (value) => (value === null || value === undefined ? "  n/a" : value.toFixed(3));

async function main() {
  const names = await corpora();

  if (REFRESH) {
    say(dim("re-measuring; this takes a few minutes"));
    for (const name of names) {
      process.stdout.write(dim(`  ${name} … `));
      try {
        await run("node", ["benchmark/score-corpus.mjs", "--corpus", `benchmark/${name}`], {
          cwd: ROOT,
          maxBuffer: 64 * 1024 * 1024
        });
        say(dim("done"));
      } catch {
        // A failed gate exits non-zero and still writes its run file, which is the
        // point: a corpus below its gate is exactly what this report exists to show.
        say(dim("done (below gate)"));
      }
    }
    process.stdout.write(dim("  fixture applications … "));
    try {
      await run("node", ["benchmark/run.mjs"], { cwd: ROOT, maxBuffer: 64 * 1024 * 1024 });
      say(dim("done"));
    } catch {
      say(dim("done (below gate)"));
    }
    say();
  }

  /* ---------- half one: the static pass ---------- */

  say(bold("The static pass, scanned per case in isolation"));
  say(dim("  No agent is involved and each case is scanned alone in an empty directory."));
  say(dim("  This cannot say what the host agent adds on top."));
  say();
  say(
    `  ${"corpus".padEnd(20)}${"recall".padStart(7)}${"crit/hi".padStart(9)}${"prec".padStart(8)}${"safeFP".padStart(8)}` +
      `${"excl".padStart(6)}  measured`
  );

  let gates = null;
  for (const name of names) {
    const record = await readJson(path.join(ROOT, "benchmark", `${name}-last-run.json`));
    if (!record) {
      say(`  ${name.padEnd(20)}${"—".padStart(7)}${"—".padStart(9)}${"—".padStart(8)}${"—".padStart(8)}${"—".padStart(6)}  never measured`);
      continue;
    }
    gates ??= record.gates;
    const t = record.totals ?? {};
    const excluded = (t.unsupported ?? 0) + (t.outOfScope ?? 0);
    say(
      `  ${name.padEnd(20)}${show(t.recall).padStart(7)}${show(t.criticalHighRecall).padStart(9)}` +
        `${show(t.precision).padStart(8)}${show(t.falsePositiveRate).padStart(8)}${String(excluded).padStart(6)}  ${age(record.generatedAt)}`
    );
    if (t.outOfScope > 0) {
      say(
        dim(
          `  ${"".padEnd(20)}${String(t.outOfScope).padStart(7)} case(s) outside what the static pass claims,` +
            ` recall on them ${show(t.outOfScopeRecall)}`
        )
      );
    }
  }

  if (gates) {
    say();
    say(
      dim(
        `  gate: recall ${gates.overallRecall} · crit/high ${gates.criticalHighRecall} · precision ${gates.precision}` +
          ` · safe-case FP ${gates.safeFalsePositiveRate}`
      )
    );
    say(dim("  Only a corpus nobody tuned against says anything about generalisation."));
    say(dim("  docs/12-release/HOLDOUT-PROTOCOL.md records which of these are burned, and why."));
  }

  /* ---------- half two: the whole product path ---------- */

  const fixtures = await readJson(path.join(ROOT, "benchmark", "last-run.json"));
  say();
  say(bold("The whole product path, against fixture applications"));
  say(dim("  Static pass, then agent validation, then dedupe and report — the path a user gets."));
  say(dim("  The rules were developed against these fixtures, so this cannot say"));
  say(dim("  anything about generalisation. It is a regression gate, not evidence."));
  say();

  if (!fixtures) {
    say("  never measured — run: node benchmark/run.mjs");
  } else {
    say(
      `  ${"fixture".padEnd(20)}${"recall".padStart(7)}${"prec".padStart(8)}${"static".padStart(8)}${"verified".padStart(10)}  measured`
    );
    for (const result of fixtures.results ?? []) {
      const recorded = result.reported ?? {};
      say(
        `  ${String(result.fixture).padEnd(20)}${show(result.recall ?? null).padStart(7)}` +
          `${show(result.precision ?? null).padStart(8)}` +
          `${String(result.staticPass?.candidatesRecorded ?? "—").padStart(8)}` +
          `${String(recorded.verified ?? result.validation?.verified ?? "—").padStart(10)}  ${age(fixtures.generatedAt)}`
      );
    }
  }

  /* ---------- what neither of them says ---------- */

  say();
  say(bold("What no number above measures"));
  say("  · what the host agent finds that the static pass does not, on code nobody tuned against.");
  say("    The corpus cases are isolated files with no application to exercise, and the");
  say("    deterministic stand-in agent needs a running one, so no harness scores this yet.");
  say("  · languages the engine does not parse at all — Python, Java, Ruby, Go. Cases in them");
  say("    are excluded above and named in each corpus report.");
  say("  · data flow the engine cannot connect — event emitters, queues, stored callbacks, dynamic");
  say("    dispatch, unresolved calls — which the product gives to the host agent and the engine");
  say("    states in its own coverage output on every scan.");
  say();
  say(dim("  The honest sentence is the long one. A single detection number, quoted without"));
  say(dim("  which half it came from and what it excluded, is wrong however accurate it is."));
}

await main();
