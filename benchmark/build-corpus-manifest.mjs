#!/usr/bin/env node
/**
 * Merges each family's `cases.json` into that corpus's `manifest.json`.
 *
 *   node benchmark/build-corpus-manifest.mjs
 *   node benchmark/build-corpus-manifest.mjs --corpus benchmark/holdout-2
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

/**
 * Which corpus to assemble. Held-out corpora are authored the same way and
 * deserve the same validation; a builder that only knows one directory means the
 * corpus whose numbers matter most is the one nobody checks.
 */
const CORPUS = (() => {
  const index = process.argv.indexOf("--corpus");
  const value = index === -1 ? null : process.argv[index + 1];
  return path.resolve(ROOT, value && !value.startsWith("--") ? value : "benchmark/corpus");
})();
const CORPUS_LABEL = path.relative(ROOT, CORPUS).split(path.sep).join("/");

/*
 * Corpora held to the current rules in full: route reachability is checked and a missing
 * CWE fails the build.
 *
 * Named as a pattern rather than a list so a new corpus is strict by default. The four
 * oldest holdouts predate both rules and are deliberately excluded — retrofitting a CWE
 * onto a case whose author is no longer available would mean guessing the answer, which is
 * worse than the gap.
 */
/*
 * Two rules with two different starting points, kept separate because they were introduced at
 * different times and retro-applying either would mean guessing an absent author's intent.
 *
 * Unanchored on purpose: a corpus label is sometimes a variant such as `holdout-5-test`, and
 * anchoring these silently exempted every one of them.
 */
const ROUTES_CHECKED = /holdout-([4-9]|\d\d)|reference/;
const CWE_REQUIRED = /holdout-([5-9]|\d\d)|reference/;

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

/**
 * Reasons a case may be scored outside the gate. Must stay in step with
 * `benchmark/score-corpus.mjs`; a reason only one of the two files knows is a
 * case that silently counts as a miss or silently vanishes.
 */
const OUT_OF_SCOPE_REASONS = new Set(["cross_module"]);

/** Words that must never appear in a case's own file name. */
const LEAKY_NAME = /(vulnerab|unsafe|insecure|injection|exploit|malicious|attacker|evil|pwn|fixture|sample)/i;

/**
 * Words that must never appear in a case's own *identifiers*.
 *
 * The brief forbids naming a file or an identifier after its defect, and only the
 * file name was ever checked. An identifier called `vulnerableLookup` hands the
 * answer to any rule that reads names, and the corpus cannot detect that it did so.
 *
 * Deliberately narrower than `LEAKY_NAME`, because a source file is not a file name
 * and the wide list produces false alarms on correct code: `injection` is how
 * NestJS describes its own constructor wiring, `unsafe` prefixes real React APIs,
 * and `sample` appears in `sampleRate`. What is left is the set of words that only
 * ever appear when an author is labelling their own defect.
 */
const LEAKY_IDENTIFIER = /\b\w*(vulnerab|exploit|malicious|attacker|pwn|backdoor|owasp|cwe\d)\w*\b/i;

/**
 * Can this case's declared route ever be attributed?
 *
 * `benchmark/score-corpus.mjs` scans every case alone, deliberately, so a rule
 * cannot pass by recognising a neighbouring file. The cost is that a route
 * declared in a router the case does not ship cannot be discovered, and the case
 * then fails for a reason that has nothing to do with detection — four of
 * holdout-2's remaining misses were "detected at the right line, route absent
 * only in the harness", and one of holdout-3's still is.
 *
 * The route is reachable when the path is written in the case file itself, in a
 * module the case ships in `extraFiles`, or in the case's own location, which is
 * what file-based routing means.
 *
 * **An error from `holdout-4` onward, a warning before it.** It was a warning while
 * the corpora that trip it already existed and could not be edited without
 * retrofitting; a new corpus has no such excuse, and an unmeetable route is a case
 * that fails for a reason with nothing to do with detection. The corpus name decides
 * the severity because the decision is about which corpora were already written, not
 * about which check is right.
 */
function routeIsReachable(entry, text) {
  if (!entry.route) return true;
  const [, ...rest] = entry.route.split(" ");
  const path = rest.join(" ");
  if (!path || path === "/") return true;

  const literals = path
    .split("/")
    .filter((segment) => segment.length > 0 && !segment.startsWith(":") && !segment.startsWith("*"));
  if (literals.length === 0) return true;

  const where = entry.scanAs ?? entry.file ?? "";
  if (literals.every((segment) => where.includes(segment))) return true;

  const haystacks = [text ?? "", ...Object.values(entry.extraFiles ?? {})];
  return haystacks.some((body) => body.includes(path) || literals.every((segment) => body.includes(segment)));
}

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
  const unreachableRoutes = [];
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
    // Authors write either a bare array of cases or an object wrapping one.
    // Both are unambiguous, and rejecting one of them only costs an author an
    // hour of confusion for no benefit.
    const familyCases = Array.isArray(manifest) ? manifest : manifest.cases;
    if (!Array.isArray(familyCases)) {
      problems.push(`${family}: cases.json is neither an array of cases nor an object with a \`cases\` array`);
      continue;
    }

    const pairTargets = new Set();
    let vulnerable = 0;
    let safe = 0;

    for (const entry of familyCases) {
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
          // Comments are stripped first: a developer's comment may legitimately
          // discuss an attacker, and the rule under test never reads comments.
          const code = text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, " ");
          const leaked = code.match(LEAKY_IDENTIFIER);
          if (leaked) {
            problems.push(`${where}: the identifier "${leaked[0]}" names the defect, which lets a scanner pass by reading it`);
          }
          for (const shape of SCANNED_PROVIDER_SHAPES) {
            if (shape.pattern.test(text)) {
              problems.push(
                `${where}: contains a ${shape.id}-shaped literal, which public secret scanners block. Use a high-entropy internal secret instead — the class under test is a committed credential, not a particular provider.`
              );
            }
          }

          if (!routeIsReachable(entry, text)) {
            const message = `${where}: route "${entry.route}" is declared in neither the case file, its own path, nor any extraFiles module`;
            // Fatal from holdout-4 onward; see routeIsReachable for why the corpus
            // name decides this rather than a flag.
            if (ROUTES_CHECKED.test(CORPUS_LABEL)) problems.push(message);
            else unreachableRoutes.push(message);
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
        /*
         * Ruling S2: the class name an author invents cannot be the join with this
         * engine's taxonomy. Run 4 scored 0.033 on a corpus whose defects were being
         * found at the right lines, because five authors produced thirty names and
         * the scorer compared them by string equality. CWE is external to both
         * sides, so it is checked here rather than hoped for — an author who
         * believes no CWE fits records that reasoning in `cweNote` and the case is
         * scored class-blind only.
         */
        // Required from holdout-5 onward only. The four corpora that predate ruling
        // S2 have no CWE and are never going to: rewriting their ground truth to
        // satisfy a rule invented after they were scored is the retro-labelling §0
        // forbids, and the corpus name decides this for the same reason the route
        // rule uses it rather than a flag.
        if (CWE_REQUIRED.test(CORPUS_LABEL) && !entry.cwe && !entry.cweNote) {
          problems.push(`${where}: a vulnerable case must name a cwe, or give a cweNote saying why none fits`);
        }
        if (entry.cwe && !/^CWE-\d+$/.test(String(entry.cwe))) {
          problems.push(`${where}: cwe must read "CWE-<number>" (got "${entry.cwe}")`);
        }
      } else if (entry.kind === "safe") {
        safe += 1;
        if (entry.category) problems.push(`${where}: a safe case must not name a category`);
        if (entry.pairedWith) pairTargets.add(entry.pairedWith);
      } else {
        problems.push(`${where}: kind must be "vulnerable" or "safe" (got "${entry.kind}")`);
      }

      /*
       * `outOfScope` takes a case out of the gated population, so it is the one
       * field an author could use to make a number look better. Three guards: the
       * reason has to be one the scorer knows, only a vulnerable case can carry it
       * (a safe case has nothing to be out of scope *about*), and the `why` has to
       * actually describe the boundary it is claiming, so a reader can disagree.
       */
      if (entry.outOfScope !== undefined) {
        if (!OUT_OF_SCOPE_REASONS.has(entry.outOfScope)) {
          problems.push(
            `${where}: outOfScope "${entry.outOfScope}" is not a reason the scorer knows (${[...OUT_OF_SCOPE_REASONS].join(", ")})`
          );
        }
        if (entry.kind !== "vulnerable") {
          problems.push(`${where}: only a vulnerable case can be outOfScope; a safe case has nothing to be out of scope about`);
        }
        if (entry.outOfScope === "cross_module" && !/\b(module|file|import|another|elsewhere|caller|dispatch)/i.test(entry.why ?? "")) {
          problems.push(
            `${where}: outOfScope "cross_module" must be argued in \`why\` — name the module the value arrives from, so a reader can disagree with the claim`
          );
        }
      }

      if (!entry.why || entry.why.trim().length < 20) {
        problems.push(`${where}: \`why\` must explain the judgement in a sentence a reviewer would accept`);
      }

      if (entry.scanAs) {
        /*
         * Scoped to the family, because that is the only place a collision means
         * anything. `score-corpus.mjs` scans each case alone in its own `mkdtemp`
         * directory, so two families both writing `src/routes/statements.ts` never
         * coexist — and two blind authors independently choosing that path is a sign
         * the corpus is realistic, not a defect in it. Within one family it still
         * matters: one file serving two cases makes the ground truth ambiguous about
         * which defect is being asked for.
         *
         * The brief the authors were given says "unique across the family". This
         * check said across the corpus. The brief was right.
         */
        const scanAsKey = `${entry.family}::${entry.scanAs}`;
        const existing = seenScanAs.get(scanAsKey);
        if (existing) problems.push(`${where}: scanAs ${entry.scanAs} is already claimed by ${existing} in the same family`);
        else seenScanAs.set(scanAsKey, entry.id);
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

  if (unreachableRoutes.length > 0) {
    process.stdout.write(
      `\n${unreachableRoutes.length} case(s) declare a route the harness cannot attribute, so they can only ever score as misses:\n${unreachableRoutes
        .map((note) => `  - ${note}`)
        .join("\n")}\n`
    );
  }

  if (problems.length > 0) {
    process.stderr.write(`\n${problems.length} problem(s) in ${CORPUS_LABEL}:\n${problems.map((p) => `  - ${p}`).join("\n")}\n`);
    process.exitCode = 1;
    return;
  }

  await fs.writeFile(
    path.join(CORPUS, "manifest.json"),
    `${JSON.stringify(
      {
        generatedBy: `benchmark/build-corpus-manifest.mjs --corpus ${CORPUS_LABEL}`,
        families: familySummaries,
        totals: { vulnerable: vulnerable.length, safe: safe.length, classes: classes.length },
        classes,
        cases
      },
      null,
      2
    )}\n`
  );
  process.stdout.write(`\nwrote ${CORPUS_LABEL}/manifest.json\n`);
}

await main();
