/**
 * Is the agent better at detecting than the static pass, and does the skill help?
 *
 * Two questions, two different comparisons, and they need different tests.
 *
 * **Agent against the static pass** is unpaired in the statistical sense that matters — the
 * two are different instruments, and the interesting quantity is the gap, so both figures get
 * Wilson intervals and the reader is told whether they overlap.
 *
 * **Arm against arm is paired**, because both arms saw the same cases. McNemar uses only the
 * cases where the arms disagreed; the ones both got, or both missed, carry no information
 * about which is better. Two independent proportions would throw that pairing away and spend
 * their power on which case is hard, which at these sample sizes is the difference between
 * resolving an effect and not (ruling U7).
 *
 * Reads the run files the two arms wrote. Produce them without spending quota with:
 *   node benchmark/score-agent.mjs --corpus <c> --split dev --arm alone --model <m> --cached-only
 *   node benchmark/score-agent.mjs --corpus <c> --split dev --arm skill --model <m> --cached-only
 */
import fs from "node:fs/promises";
import path from "node:path";

import { intervalOf, mcnemar, wilson } from "./stats.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");

function flag(name, fallback) {
  const hit = process.argv.indexOf(`--${name}`);
  if (hit === -1) return fallback;
  const next = process.argv[hit + 1];
  return next === undefined || next.startsWith("--") ? true : next;
}

const CORPUS = String(flag("corpus", "reference"));
const SPLIT = String(flag("split", "dev"));

async function readRun(suffix) {
  const file = path.join(ROOT, "benchmark", `agent-${CORPUS}-${SPLIT}${suffix}-last-run.json`);
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8"));
    if (parsed.retracted) {
      process.stderr.write(`${path.basename(file)} is retracted; re-measure before comparing.\n`);
      return null;
    }
    return parsed;
  } catch {
    process.stderr.write(`missing ${path.basename(file)} — score that arm with --cached-only first\n`);
    return null;
  }
}

const alone = await readRun("");
const skill = await readRun("-skill");
if (!alone || !skill) process.exit(1);

/** A case counts as measured in an arm only if some run of it produced an answer. */
function measured(outcome) {
  return (outcome.runs ?? []).some((run) => run.status === "answered");
}

const byId = (run) => new Map((run.outcomes ?? []).map((outcome) => [outcome.id, outcome]));
const A = byId(alone);
const B = byId(skill);

/*
 * Only cases measured in *both* arms. A case one arm could not measure is not evidence about
 * the other, and including it would let a provider failure in one arm read as a win for the
 * other — the same conflation that once turned a 12-of-12 result into a published 0.632.
 */
const paired = [...A.keys()].filter((id) => B.has(id) && measured(A.get(id)) && measured(B.get(id)));

const vulnerable = paired.filter((id) => A.get(id).kind === "vulnerable");
const safe = paired.filter((id) => A.get(id).kind !== "vulnerable");

const found = (outcome) => (outcome.detectedRuns ?? 0) > 0;
/* On a safe case any finding at all is a false positive, so "detected" reads as "was wrong". */
const flagged = (outcome) => (outcome.runs ?? []).some((run) => (run.findings ?? 0) > 0);

function table(ids, hit) {
  const both = ids.filter((id) => hit(A.get(id)) && hit(B.get(id))).length;
  const onlyAlone = ids.filter((id) => hit(A.get(id)) && !hit(B.get(id))).length;
  const onlySkill = ids.filter((id) => !hit(A.get(id)) && hit(B.get(id))).length;
  const neither = ids.length - both - onlyAlone - onlySkill;
  return { both, onlyAlone, onlySkill, neither, n: ids.length };
}

function line(label, count, total) {
  const w = wilson(count, total);
  const bounds = intervalOf(w);
  return `${label.padEnd(22)}${w ? w.point.toFixed(3) : "n/a"} (${count}/${total})${bounds ? `  [${bounds[0].toFixed(3)}, ${bounds[1].toFixed(3)}]` : ""}`;
}

process.stdout.write(
  `\nagent arms compared, paired\n` +
    `model: ${alone.model}${skill.model === alone.model ? "" : ` vs ${skill.model} — NOT COMPARABLE`}\n` +
    `corpus: ${CORPUS} --split ${SPLIT}\n` +
    `${paired.length} case(s) measured in both arms (${vulnerable.length} vulnerable, ${safe.length} safe)\n\n`
);

if (paired.length === 0) {
  process.stdout.write("nothing measured in both arms yet.\n");
  process.exit(0);
}

process.stdout.write("detection on vulnerable cases\n");
process.stdout.write(`  ${line("agent alone", vulnerable.filter((id) => found(A.get(id))).length, vulnerable.length)}\n`);
process.stdout.write(`  ${line("agent + skill", vulnerable.filter((id) => found(B.get(id))).length, vulnerable.length)}\n`);

const recall = table(vulnerable, found);
const recallTest = mcnemar(recall.onlyAlone, recall.onlySkill);
process.stdout.write(
  `  paired: both ${recall.both}, alone only ${recall.onlyAlone}, skill only ${recall.onlySkill}, neither ${recall.neither}\n` +
    `  McNemar p=${recallTest.p} — ${recallTest.distinguishable ? "distinguishable" : "NOT distinguishable"} at 95%\n\n`
);

process.stdout.write("false positives on safe cases\n");
process.stdout.write(`  ${line("agent alone", safe.filter((id) => flagged(A.get(id))).length, safe.length)}\n`);
process.stdout.write(`  ${line("agent + skill", safe.filter((id) => flagged(B.get(id))).length, safe.length)}\n`);

const fp = table(safe, flagged);
const fpTest = mcnemar(fp.onlyAlone, fp.onlySkill);
process.stdout.write(
  `  paired: both wrong ${fp.both}, alone only ${fp.onlyAlone}, skill only ${fp.onlySkill}, both clean ${fp.neither}\n` +
    `  McNemar p=${fpTest.p} — ${fpTest.distinguishable ? "distinguishable" : "NOT distinguishable"} at 95%\n\n`
);

process.stdout.write(
  `A discordant count this small resolves little: McNemar cannot reach p<0.05 below 6 disagreements\n` +
    `however lopsided they are. Read a non-significant result as "not yet measured", not as "no effect".\n`
);
