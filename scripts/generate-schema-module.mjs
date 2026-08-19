#!/usr/bin/env node
/**
 * schemas/*.json are the language-neutral source of truth. This generates a
 * TypeScript module so runtime validators need no filesystem access, and a
 * drift test asserts the generated module still matches the JSON files.
 */
import fs from "node:fs/promises";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const SCHEMA_DIR = path.join(ROOT, "schemas");
const OUT = path.join(ROOT, "packages/contracts/src/generated-schemas.ts");

const NAMES = {
  "report.schema.json": "REPORT_SCHEMA",
  "finding.schema.json": "FINDING_SCHEMA",
  "finding-submission.schema.json": "FINDING_SUBMISSION_SCHEMA",
  "scan-event.schema.json": "SCAN_EVENT_SCHEMA",
  "share-policy.schema.json": "SHARE_POLICY_SCHEMA",
  "project-binding.schema.json": "PROJECT_BINDING_SCHEMA",
  "update-manifest.schema.json": "UPDATE_MANIFEST_SCHEMA"
};

const parts = [
  "/* GENERATED FILE - do not edit.",
  " * Source: schemas/*.json",
  " * Regenerate: node scripts/generate-schema-module.mjs",
  " */",
  ""
];

for (const [file, constName] of Object.entries(NAMES)) {
  const json = JSON.parse(await fs.readFile(path.join(SCHEMA_DIR, file), "utf8"));
  parts.push(`export const ${constName} = ${JSON.stringify(json, null, 2)} as const;`, "");
}

parts.push(
  "export const ALL_SCHEMAS = [",
  ...Object.values(NAMES).map((n) => `  ${n},`),
  "] as const;",
  ""
);

await fs.writeFile(OUT, parts.join("\n"), "utf8");
process.stdout.write(`generated ${path.relative(ROOT, OUT)}\n`);
