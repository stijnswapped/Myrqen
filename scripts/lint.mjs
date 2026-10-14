#!/usr/bin/env node
/**
 * Repository consistency checks that matter for this product specifically:
 * no committed secrets, no scattered brand literals, no leftover TODO-only
 * scaffolding, no debug logging in product code, and no drift between
 * schemas/*.json and the generated contracts module.
 */
import fs from "node:fs/promises";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const IGNORED = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "dist-tsc",
  "build",
  ".turbo",
  "coverage",
  ".myrqen",
  ".data",
  "migrations",
  // Agent worktrees are separate checkouts of this repository. Linting them
  // reports every problem twice and attributes it to a path that does not exist
  // in the tree being reviewed.
  ".claude"
]);

const CODE_EXTENSIONS = new Set([".ts", ".tsx", ".mjs", ".js"]);

const SECRET_PATTERNS = [
  { id: "aws_key", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: "private_key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { id: "github_token", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/ },
  { id: "slack_token", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ }
];

/**
 * Brand strings belong in @myrqen/brand. Fixtures, docs, tests, and the brand
 * package itself are exempt, as are file paths that must be literal.
 */
const BRAND_EXEMPT_PREFIXES = [
  "packages/brand/",
  "fixtures/",
  "docs/",
  "tests/",
  "benchmark/",
  "scripts/",
  "packages/skill/"
];

const problems = [];

async function walk(directory, relative = "") {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (IGNORED.has(entry.name)) continue;
    const full = path.join(directory, entry.name);
    const rel = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await walk(full, rel);
      continue;
    }
    if (!entry.isFile()) continue;
    await inspect(full, rel);
  }
}

async function inspect(full, rel) {
  const extension = path.extname(rel);
  const isCode = CODE_EXTENSIONS.has(extension);
  // Benchmark corpora are sample applications written to be wrong on purpose.
  // They are held to the same exemption as `fixtures/`: a console.log or a fake
  // credential in a corpus case is the case, not a defect in the product.
  //
  // Matched by shape rather than by name. Listing the corpora one by one meant
  // every new held-out corpus failed the lint on the day it was written, for
  // exactly the content that makes it worth having.
  const isFixture = rel.startsWith("fixtures/") || /^benchmark\/(corpus|holdout[\w-]*)\//.test(rel);
  const isTest = rel.includes("/test/") || rel.endsWith(".test.mjs") || rel.startsWith("tests/");

  let content;
  try {
    content = await fs.readFile(full, "utf8");
  } catch {
    return;
  }

  for (const { id, pattern } of SECRET_PATTERNS) {
    // Fixtures deliberately contain fake credentials for redaction tests.
    if (isFixture || isTest) continue;
    if (pattern.test(content)) problems.push(`${rel}: possible committed secret (${id})`);
  }

  if (!isCode) return;

  // Operator tooling exists to print. The rule is about product code, where a
  // stray console.log leaks into a user's terminal or a browser console.
  const isScript = rel.startsWith("scripts/") || rel.startsWith("tools/");
  if (!isTest && !isFixture && !isScript && /^\s*console\.log\(/m.test(content)) {
    problems.push(`${rel}: console.log in product code; use the output module or a structured log`);
  }

  if (!isFixture && !isTest && /\bTODO implementation\b/.test(content)) {
    problems.push(`${rel}: TODO-only scaffolding remains`);
  }

  const isGenerated = content.startsWith("/* GENERATED FILE");
  const isExempt = isTest || isGenerated || BRAND_EXEMPT_PREFIXES.some((prefix) => rel.startsWith(prefix));
  if (!isExempt) {
    const lines = content.split("\n");
    lines.forEach((line, index) => {
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
      if (/["'`][^"'`]*\bMyrqen\b[^"'`]*["'`]/.test(line) && !line.includes("@myrqen/")) {
        problems.push(`${rel}:${index + 1}: hard-coded brand literal; import it from @myrqen/brand`);
      }
    });
  }
}

async function checkSchemaDrift() {
  const generated = await fs.readFile(path.join(ROOT, "packages/contracts/src/generated-schemas.ts"), "utf8");
  const names = {
    "report.schema.json": "REPORT_SCHEMA",
    "finding.schema.json": "FINDING_SCHEMA",
    "finding-submission.schema.json": "FINDING_SUBMISSION_SCHEMA",
    "scan-event.schema.json": "SCAN_EVENT_SCHEMA",
    "share-policy.schema.json": "SHARE_POLICY_SCHEMA",
    "project-binding.schema.json": "PROJECT_BINDING_SCHEMA",
    "update-manifest.schema.json": "UPDATE_MANIFEST_SCHEMA"
  };
  for (const [file, constant] of Object.entries(names)) {
    const schema = JSON.parse(await fs.readFile(path.join(ROOT, "schemas", file), "utf8"));
    const marker = `export const ${constant} = ${JSON.stringify(schema, null, 2)} as const;`;
    if (!generated.includes(marker)) {
      problems.push(
        `schemas/${file}: generated-schemas.ts is out of date; run "node scripts/generate-schema-module.mjs"`
      );
    }
  }
}

await walk(ROOT);
await checkSchemaDrift();

if (problems.length > 0) {
  for (const problem of problems) process.stderr.write(`${problem}\n`);
  process.stderr.write(`\n${problems.length} problem(s) found.\n`);
  process.exit(1);
}

process.stdout.write("lint: clean\n");
