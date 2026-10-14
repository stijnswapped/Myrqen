#!/usr/bin/env node
/**
 * Scores every corpus twice — as authored, and with every locally-bound identifier
 * renamed to an opaque token — and fails on a regression against the recorded
 * baseline.
 *
 * ## Why this gate exists
 *
 * Recall 1.000 on a corpus says a rule fires on that corpus. It does not say
 * whether it fired because of the *shape* of the code or because of the *words* in
 * it, and no corpus written in ordinary English variable names can tell those apart.
 * Measured on 2026-08-23: the development corpus reads 1.000 as authored and
 * **0.699** renamed, with 20 of 73 cases producing no candidate at all, and its
 * safe-case findings going from 0 to 4. That gap is the part of the score that was
 * vocabulary, and it was invisible to every other measurement in this repository.
 *
 * It matters most for what comes next. The remaining recall work is twelve rule
 * changes written from named held-out cases, which is exactly the circumstance in
 * which a lexical rule gets written by accident. This gate makes a rule that only
 * works on familiar names fail the build.
 *
 * ## Why it is a ratchet rather than a threshold
 *
 * An absolute bar — "mutated recall at least 0.85 of authored" — would fail on the
 * day it landed, and a gate that fails on day one is a gate somebody deletes. So the
 * baseline is the current measurement and the rule is *no worse*. Closing the gap is
 * separate, funded work; not widening it is free, and it is the part that has to be
 * enforced continuously.
 *
 * ## Why the comparison is route-blind
 *
 * Scored at "a candidate of the expected class inside the expected line range",
 * ignoring the route. On a tRPC procedure or a path parameter the identifier **is**
 * part of the route name, so renaming it legitimately changes the address: those
 * cases would read as engine failures when they are the mutant's doing. The
 * route-blind stage is the one where a difference can only mean the engine stopped
 * seeing the defect.
 *
 *   node benchmark/score-mutation.mjs
 *   node benchmark/score-mutation.mjs --update-baseline
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { mutateRename, mutateProperties } from "./mutate.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const argv = process.argv.slice(2);
const UPDATE = argv.includes("--update-baseline");
const BASELINE = path.join(ROOT, "benchmark", "mutation-baseline.json");

const ENGINE = (() => {
  const index = argv.indexOf("--engine");
  const value = index === -1 ? null : argv[index + 1];
  return value && !value.startsWith("--") ? value : path.join(ROOT, "packages/scan/dist/index.js");
})();
const { scan } = await import(ENGINE.startsWith(".") ? ENGINE : `file://${ENGINE}`);

/** Kept in step with `score-corpus.mjs`. */
const UNSUPPORTED = new Set(["python", "ruby", "go", "php", "java"]);
const CORPORA = ["corpus", "holdout", "holdout-2", "holdout-3"];

function scanPath(entry) {
  if (entry.scanAs) return entry.scanAs;
  if (entry.family.startsWith("nextjs")) return entry.file.split("/").slice(1).join("/");
  return path.join("src", path.basename(entry.file));
}

/*
 * Two kinds of name to be independent of, measured separately.
 *
 * "rename" renames locally-bound value identifiers. "properties" renames the data
 * property names the author chose — the column vocabulary — which `mutateRename`
 * preserves by design and therefore never tested. `OWNER_COLUMN` is the most
 * referenced constant in `packages/scan` and until this mode existed not one name in
 * it had ever been mutated, because a column lives in `where: { userId }` and in
 * `row.userId` and both are preserved.
 *
 * They are reported as separate columns rather than combined, because they fail for
 * different reasons and are fixed by different work.
 */
async function scanCase(corpusDir, entry, mode) {
  let source = await fs.readFile(path.join(corpusDir, entry.file), "utf8");
  const relative = scanPath(entry);
  const mutator = mode === "rename" ? mutateRename : mode === "properties" ? mutateProperties : null;
  if (mutator) {
    const result = mutator(source, relative);
    // A mutant that moved a line cannot be compared against a line range.
    if (result.source.split("\n").length === source.split("\n").length) source = result.source;
  }
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-mutation-"));
  try {
    const target = path.join(root, relative);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, source, "utf8");
    await fs.writeFile(
      path.join(root, "package.json"),
      `${JSON.stringify(entry.packageJson ?? { name: "case", version: "1.0.0", type: "module" }, null, 2)}\n`,
      "utf8"
    );
    for (const [relativeExtra, contents] of Object.entries(entry.extraFiles ?? {})) {
      const extra = path.join(root, relativeExtra);
      await fs.mkdir(path.dirname(extra), { recursive: true });
      await fs.writeFile(extra, contents, "utf8");
    }
    const { candidates } = await scan({ repoRoot: root });
    return candidates;
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

/** Route-blind: the expected class, inside the expected line range. */
function seesDefect(candidates, entry) {
  const [from, to] = entry.lineRange ?? [entry.line, entry.line];
  return candidates.some(
    (candidate) => candidate.category === entry.category && candidate.location.line >= from && candidate.location.line <= to
  );
}

async function measure(id, mode) {
  const dir = path.join(ROOT, "benchmark", id);
  const manifest = JSON.parse(await fs.readFile(path.join(dir, "manifest.json"), "utf8"));
  let vulnerable = 0;
  let seen = 0;
  let safe = 0;
  let safeWithFindings = 0;
  let safeWithAssertedFindings = 0;
  for (const entry of manifest.cases) {
    if (UNSUPPORTED.has(entry.language)) continue;
    const candidates = await scanCase(dir, entry, mode);
    if (entry.kind === "vulnerable") {
      vulnerable += 1;
      if (seesDefect(candidates, entry)) seen += 1;
    } else {
      safe += 1;
      if (candidates.length > 0) safeWithFindings += 1;
      /*
       * Asserted findings counted separately, for the same reason `score-corpus.mjs`
       * separates them: this gate exists to catch a guard recognised by its name rather
       * than by what it does, and that failure shows up as a rule *asserting* a defect
       * in correct code. A rule that asks for a look is a different thing, and counting
       * the two together would make the gate punish every deliberate candidate.
       */
      if (candidates.some((candidate) => candidate.verification !== "needs_review")) {
        safeWithAssertedFindings += 1;
        if (process.env.MYRQEN_DEBUG_MUTATION) {
          process.stderr.write(
            `[mut] ${id}/${mode} ${entry.id}: ${candidates
              .filter((candidate) => candidate.verification !== "needs_review")
              .map((candidate) => `${candidate.ruleId}@${candidate.location.line}`)
              .join(", ")}\n`
          );
        }
      }
    }
  }
  return {
    vulnerable,
    seen,
    recall: vulnerable === 0 ? null : Math.round((seen / vulnerable) * 1000) / 1000,
    safe,
    safeWithFindings,
    safeWithAssertedFindings
  };
}

const results = {};
for (const id of CORPORA) {
  results[id] = {
    authored: await measure(id, "authored"),
    mutated: await measure(id, "rename"),
    properties: await measure(id, "properties")
  };
}

const recorded = UPDATE ? null : await fs.readFile(BASELINE, "utf8").then(JSON.parse).catch(() => null);

process.stdout.write("\nvocabulary dependence — recall at class-in-range, route-blind\n\n");
process.stdout.write(
  `${"corpus".padEnd(12)}${"authored".padStart(10)}${"renamed".padStart(10)}${"delta".padStart(8)}` +
    `${"columns".padStart(10)}${"delta".padStart(8)}${"safe FP".padStart(9)}${"  baseline"}\n`
);

const failures = [];
for (const id of CORPORA) {
  const { authored, mutated, properties } = results[id];
  const delta = authored.recall === null || mutated.recall === null ? null : Math.round((mutated.recall - authored.recall) * 1000) / 1000;
  const columnDelta =
    authored.recall === null || properties.recall === null
      ? null
      : Math.round((properties.recall - authored.recall) * 1000) / 1000;
  const was = recorded?.[id];
  let note = was
    ? `${was.mutated.recall.toFixed(3)} / ${was.mutated.safeWithAssertedFindings ?? was.mutated.safeWithFindings} asserted`
    : "—";

  if (was) {
    if (mutated.recall < was.mutated.recall) {
      failures.push(
        `${id}: renamed recall ${mutated.recall.toFixed(3)} is below the recorded ${was.mutated.recall.toFixed(3)} — ` +
          `a change made the engine more dependent on identifier names`
      );
      note += "  REGRESSED";
    } else if (
      typeof was.mutated.safeWithAssertedFindings === "number" &&
      mutated.safeWithAssertedFindings > was.mutated.safeWithAssertedFindings
    ) {
      failures.push(
        `${id}: ${mutated.safeWithAssertedFindings} safe case(s) have a rule assert a defect when renamed, up from ${was.mutated.safeWithAssertedFindings} — ` +
          `a guard is being recognised by its name rather than by what it does`
      );
      note += "  REGRESSED";
    } else if (mutated.recall > was.mutated.recall || mutated.safeWithFindings < was.mutated.safeWithFindings) {
      note += "  improved — rerun with --update-baseline";
    }
    // The column vocabulary ratchets the same way, once a baseline carries it.
    if (typeof was.properties?.recall === "number" && properties.recall < was.properties.recall) {
      failures.push(
        `${id}: column-renamed recall ${properties.recall.toFixed(3)} is below the recorded ${was.properties.recall.toFixed(3)} — ` +
          `a change made the engine more dependent on the names of data fields`
      );
      note += "  REGRESSED (columns)";
    }
  }

  process.stdout.write(
    `${id.padEnd(12)}${(authored.recall ?? 0).toFixed(3).padStart(10)}${(mutated.recall ?? 0).toFixed(3).padStart(10)}` +
      `${(delta === null ? "—" : delta.toFixed(3)).padStart(8)}` +
      `${(properties.recall ?? 0).toFixed(3).padStart(10)}${(columnDelta === null ? "—" : columnDelta.toFixed(3)).padStart(8)}` +
      `${`${mutated.safeWithAssertedFindings}/${mutated.safe}`.padStart(9)}  ${note}\n`
  );
}

if (UPDATE) {
  await fs.writeFile(BASELINE, `${JSON.stringify(results, null, 2)}\n`, "utf8");
  process.stdout.write(`\nwrote ${path.relative(ROOT, BASELINE)}\n`);
  process.exit(0);
}

/*
 * A missing baseline is a failure, not a pass.
 *
 * This gate runs in CI, and its baseline was untracked for as long as it existed —
 * so on a fresh checkout the file was absent, this branch printed a note, exited 0,
 * and the ratchet reported success without comparing anything. A gate that cannot
 * verify must say so in its exit code; "I could not check" and "I checked and it
 * was fine" are not the same result, and only one of them should let a merge
 * through. `--update-baseline` is the way to create one deliberately.
 */
if (recorded === null) {
  process.stderr.write(
    "\nno mutation baseline recorded yet, so nothing was verified — run with --update-baseline to create one\n"
  );
  process.exit(1);
}

if (failures.length > 0) {
  process.stderr.write(`\nmutation gate failed:\n${failures.map((line) => `  - ${line}`).join("\n")}\n`);
  process.exit(1);
}
process.stdout.write("\nmutation gate passed: no new dependence on identifier names\n");
