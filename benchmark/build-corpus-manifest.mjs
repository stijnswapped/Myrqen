#!/usr/bin/env node
/**
 * Merges each family's `cases.json` into `benchmark/corpus/manifest.json`.
 *
 * Families are authored independently, so the merge is also the validation pass:
 * a case that names a file which does not exist, a line outside its own range, an
 * id used twice, a safe case pointing at a vulnerable case that was never written,
 * or a `scanAs` two cases would both claim are all mistakes that would quietly
 * distort a score. Every one of them fails here rather than reading as a miss
 * later.
 */
import fs from "node:fs/promises";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const CORPUS = path.join(ROOT, "benchmark", "corpus");

/**
 * Credential shapes that public secret scanners recognise.
 *
 * A corpus case that needs a committed credential must not use a real provider's
 * shape: GitHub's push protection blocks the whole repository over it, and so does
 * every downstream consumer's scanner. The class under test is "a credential
 * literal in source", which a high-entropy internal secret demonstrates just as
 * well without making the corpus unpublishable.
 */
const SCANNED_PROVIDER_SHAPES = [
  { id: "stripe", pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/ },
  { id: "aws", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: "github", pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { id: "google", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "slack", pattern: /\bxox[abprs]-[A-Za-z0-9-]{20,}\b/ },
  { id: "openai", pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { id: "private_key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ }
];

/** Words that must never appear in a case's own file name. */
const LEAKY_NAME = /(vulnerab|unsafe|insecure|injection|exploit|malicious|attacker|evil|pwn|fixture|sample)/i;

async function familyDirectories() {
  const entries = await fs.readdir(CORPUS, { withFileTypes: true });
  return entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
}

async function main() {
  // A family still being authored is not a corpus defect. Scoring a partial corpus
  // is how detection gaps get found early, so the missing family is reported and
  // the merge continues.
  const allowMissing = process.argv.includes("--allow-missing");
  const families = await familyDirectories();
  const cases = [];
  const problems = [];
  const seenIds = new Set();
  const seenScanAs = new Map();
  const familySummaries = [];

  for (const family of families) {
    const manifestPath = path.join(CORPUS, family, "cases.json");
    let manifest;
    try {
      manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
    } catch (error) {
      const message = `${family}: cases.json is missing or unreadable (${error.code ?? "parse error"})`;
      if (allowMissing && error.code === "ENOENT") process.stdout.write(`  ${family.padEnd(24)} not written yet\n`);
      else problems.push(message);
      continue;
    }
    if (!Array.isArray(manifest.cases)) {
      problems.push(`${family}: cases.json has no \`cases\` array`);
      continue;
    }

    const pairTargets = new Set();
    let vulnerable = 0;
    let safe = 0;

    for (const entry of manifest.cases) {
      const where = `${family}/${entry.id ?? "(no id)"}`;

      if (!entry.id) problems.push(`${where}: no id`);
      else if (seenIds.has(entry.id)) problems.push(`${where}: id is used more than once`);
      else seenIds.add(entry.id);

      if (entry.family !== family) {
        problems.push(`${where}: family is "${entry.family}" but the case lives in ${family}/`);
      }

      if (!entry.file) {
        problems.push(`${where}: no file`);
      } else {
        const absolute = path.join(CORPUS, entry.file);
        let text;
        try {
          text = await fs.readFile(absolute, "utf8");
        } catch {
          problems.push(`${where}: file ${entry.file} does not exist`);
        }
        if (text !== undefined) {
          const basename = path.basename(entry.file);
          if (LEAKY_NAME.test(basename)) {
            problems.push(`${where}: the file name ${basename} names the defect, which lets a scanner pass by reading it`);
          }
          for (const shape of SCANNED_PROVIDER_SHAPES) {
            if (shape.pattern.test(text)) {
              problems.push(
                `${where}: contains a ${shape.id}-shaped literal, which public secret scanners block. Use a high-entropy internal secret instead — the class under test is a committed credential, not a particular provider.`
              );
            }
          }

          const lineCount = text.split(/\r?\n/).length;
          if (entry.kind === "vulnerable") {
            if (typeof entry.line !== "number") {
              problems.push(`${where}: a vulnerable case must record the line a reviewer would comment on`);
            } else if (entry.line < 1 || entry.line > lineCount) {
              problems.push(`${where}: line ${entry.line} is outside the file (${lineCount} lines)`);
            }
            if (Array.isArray(entry.lineRange)) {
              const [from, to] = entry.lineRange;
              if (from > to) problems.push(`${where}: lineRange ${from}-${to} is inverted`);
              if (typeof entry.line === "number" && (entry.line < from || entry.line > to)) {
                problems.push(`${where}: line ${entry.line} is outside its own lineRange ${from}-${to}`);
              }
              if (to > lineCount) problems.push(`${where}: lineRange ends at ${to}, past the end of the file`);
            }
          }
        }
      }

      if (entry.kind === "vulnerable") {
        vulnerable += 1;
        if (!entry.category) problems.push(`${where}: a vulnerable case must name its category`);
        if (!Array.isArray(entry.severityBand) || entry.severityBand.length === 0) {
          problems.push(`${where}: a vulnerable case must state a severity band`);
        }
      } else if (entry.kind === "safe") {
        safe += 1;
        if (entry.category) problems.push(`${where}: a safe case must not name a category`);
        if (entry.pairedWith) pairTargets.add(entry.pairedWith);
      } else {
        problems.push(`${where}: kind must be "vulnerable" or "safe" (got "${entry.kind}")`);
      }

      if (!entry.why || entry.why.trim().length < 20) {
        problems.push(`${where}: \`why\` must explain the judgement in a sentence a reviewer would accept`);
      }

      if (entry.scanAs) {
        const existing = seenScanAs.get(entry.scanAs);
        if (existing) problems.push(`${where}: scanAs ${entry.scanAs} is already claimed by ${existing}`);
        else seenScanAs.set(entry.scanAs, entry.id);
      }

      cases.push(entry);
    }

    for (const target of pairTargets) {
      if (!manifest.cases.some((entry) => entry.id === target)) {
        problems.push(`${family}: a safe case is paired with ${target}, which is not in this family`);
      }
    }

    familySummaries.push({ family, architecture: manifest.architecture ?? null, vulnerable, safe });
  }

  const vulnerable = cases.filter((entry) => entry.kind === "vulnerable");
  const safe = cases.filter((entry) => entry.kind === "safe");
  const classes = [...new Set(vulnerable.map((entry) => entry.category))].sort();

  process.stdout.write(`families: ${families.length}\n`);
  for (const summary of familySummaries) {
    process.stdout.write(`  ${summary.family.padEnd(24)} ${summary.vulnerable} vulnerable, ${summary.safe} safe\n`);
  }
  process.stdout.write(`\ntotal: ${vulnerable.length} vulnerable, ${safe.length} safe, ${classes.length} distinct classes\n`);

  if (problems.length > 0) {
    process.stderr.write(`\n${problems.length} problem(s) in the corpus:\n${problems.map((p) => `  - ${p}`).join("\n")}\n`);
    process.exitCode = 1;
    return;
  }

  await fs.writeFile(
    path.join(CORPUS, "manifest.json"),
    `${JSON.stringify(
      {
        generatedBy: "benchmark/build-corpus-manifest.mjs",
        families: familySummaries,
        totals: { vulnerable: vulnerable.length, safe: safe.length, classes: classes.length },
        classes,
        cases
      },
      null,
      2
    )}\n`
  );
  process.stdout.write("\nwrote benchmark/corpus/manifest.json\n");
}

await main();
