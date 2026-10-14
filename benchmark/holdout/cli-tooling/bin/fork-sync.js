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
const MIRROR_HOSTS = new Set(["github.com", "gitlab.com", "git.acme-suite.com"]);

function remoteUrl(candidate) {
  const parsed = new URL(candidate);
  if (parsed.protocol !== "https:") throw new Error("only https remotes are mirrored");
  if (!MIRROR_HOSTS.has(parsed.hostname)) throw new Error(`${parsed.hostname} is not a mirrored host`);
  if (parsed.username || parsed.password) throw new Error("remote urls must not carry credentials");
  return parsed.toString();
}

async function mirror({ source, branch, target }) {
  if (!REF_NAME.test(branch)) throw new Error(`${branch} is not a usable ref name`);
  const from = remoteUrl(source);
  const to = remoteUrl(target);

  const workdir = await mkdtemp(path.join(os.tmpdir(), "mirror-"));
  const checkout = path.join(workdir, "checkout");

  await run("git", ["clone", "--depth", "1", "--branch", branch, "--", from, checkout], {
    timeout: CLONE_TIMEOUT_MS
  });

  const { stdout } = await run("git", ["-C", checkout, "rev-parse", "HEAD"]);
  const head = stdout.trim();

  await run("git", ["-C", checkout, "remote", "set-url", "origin", to]);
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
