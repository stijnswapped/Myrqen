#!/usr/bin/env node
"use strict";

const { writeFile } = require("node:fs/promises");
const { Command } = require("commander");
const template = require("lodash.template");

const FETCH_TIMEOUT_MS = 10_000;

const SUMMARY_LINE = template("<%= count %> row(s) rendered for <%= tenant %> at <%= generatedAt %>");

async function fetchText(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`theme fetch failed: ${response.status}`);
  return response.text();
}

async function render({ themeUrl, tenant, rows, out }) {
  const layoutSource = await fetchText(new URL("layout.html", themeUrl));
  const layout = template(layoutSource, { variable: "report" });

  const html = layout({
    tenant,
    rows,
    count: rows.length,
    generatedAt: new Date().toISOString()
  });

  await writeFile(out, html, "utf8");
  process.stdout.write(`${SUMMARY_LINE({ count: rows.length, tenant, generatedAt: new Date().toISOString() })}\n`);
  return html;
}

const program = new Command();
program
  .requiredOption("--theme <url>", "theme package url, taken from the tenant's branding settings")
  .requiredOption("--tenant <slug>", "tenant the report belongs to")
  .requiredOption("--out <file>", "file to write the rendered report to")
  .action(async (options) => {
    const rows = JSON.parse(process.env.REPORT_ROWS || "[]");
    await render({ themeUrl: options.theme, tenant: options.tenant, rows, out: options.out });
  });

program.parseAsync(process.argv);
