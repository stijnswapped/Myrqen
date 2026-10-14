#!/usr/bin/env node
"use strict";

const { execFile } = require("node:child_process");
const { mkdtemp } = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { promisify } = require("node:util");
const { Command } = require("commander");

const run = promisify(execFile);
const CLONE_TIMEOUT_MS = 120_000;
const REF_NAME = /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,100}$/;

async function mirror({ source, branch, target }) {
  if (!REF_NAME.test(branch)) throw new Error(`${branch} is not a usable ref name`);

  const workdir = await mkdtemp(path.join(os.tmpdir(), "mirror-"));
  const checkout = path.join(workdir, "checkout");

  await run("git", ["clone", "--depth", "1", "--branch", branch, source, checkout], {
    timeout: CLONE_TIMEOUT_MS
  });

  const { stdout } = await run("git", ["-C", checkout, "rev-parse", "HEAD"]);
  const head = stdout.trim();

  await run("git", ["-C", checkout, "remote", "set-url", "origin", target]);
  await run("git", ["-C", checkout, "push", "--force", "origin", `HEAD:refs/heads/${branch}`], {
    timeout: CLONE_TIMEOUT_MS
  });

  return { head, workdir };
}

const program = new Command();
program
  .requiredOption("--source <url>", "repository to mirror from, as configured per tenant in the console")
  .requiredOption("--target <url>", "internal repository to mirror into")
  .option("--branch <ref>", "branch to mirror", "main")
  .action(async (options) => {
    const { head } = await mirror(options);
    process.stdout.write(`mirrored ${options.branch} at ${head}\n`);
  });

program.parseAsync(process.argv);
