#!/usr/bin/env node
"use strict";

const { writeFile } = require("node:fs/promises");
const { Command } = require("commander");
const template = require("lodash.template");

const FETCH_TIMEOUT_MS = 10_000;

const SUMMARY_LINE = template("<%= count %> row(s) rendered for <%= tenant %> at <%= generatedAt %>");

const LAYOUT = template(
  `<!doctype html>
<html data-accent="<%- report.accent %>">
  <head><title><%- report.title %></title></head>
  <body>
    <h1><%- report.heading %></h1>
    <ul><% report.rows.forEach(function (row) { %><li><%- row.label %></li><% }); %></ul>
    <footer><%- report.generatedAt %></footer>
  </body>
</html>`,
  { variable: "report" }
);

async function fetchJson(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`theme fetch failed: ${response.status}`);
  return response.json();
}

async function render({ themeUrl, tenant, rows, out }) {
  const branding = await fetchJson(new URL("theme.json", themeUrl));

  const html = LAYOUT({
    accent: String(branding.accent || "#1d4ed8"),
    title: String(branding.title || `${tenant} statement`),
    heading: String(branding.heading || "Statement"),
    rows,
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
