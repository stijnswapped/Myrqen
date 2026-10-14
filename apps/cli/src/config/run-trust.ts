import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { ProjectRunConfig } from "./project-config.js";
import { configDirectory } from "./paths.js";

/**
 * Which run settings this machine has written or confirmed.
 *
 * `.myrqen/config.json` is committed, so a start command in it may have been put
 * there by anyone with write access to the repository. The command is shown to
 * the agent as something to run, so it is only handed over as confirmed when this
 * machine wrote it or the user agreed to it here.
 *
 * The record is a digest of the run block per repository, kept in the user's
 * config directory — never inside the repository, where a committed copy could
 * vouch for itself. Any change to the command, the address, or the env names
 * changes the digest and needs confirming again.
 */

interface TrustFile {
  version: 1;
  repositories: Record<string, { digest: string; confirmedAt: string }>;
}

const MAX_REPOSITORIES = 500;

function trustFile(): string {
  return path.join(configDirectory(), "trusted-run-configs.json");
}

export function runConfigDigest(run: Pick<ProjectRunConfig, "command" | "url" | "port" | "env">): string {
  const canonical = JSON.stringify({ command: run.command, url: run.url, port: run.port, env: [...run.env] });
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

async function repositoryKey(repoRoot: string): Promise<string> {
  try {
    return await fs.realpath(repoRoot);
  } catch {
    return path.resolve(repoRoot);
  }
}

async function readTrust(): Promise<TrustFile> {
  try {
    const parsed = JSON.parse(await fs.readFile(trustFile(), "utf8")) as Partial<TrustFile>;
    if (parsed?.version === 1 && parsed.repositories && typeof parsed.repositories === "object") {
      return { version: 1, repositories: { ...parsed.repositories } };
    }
  } catch {
    // Missing or unreadable: nothing is trusted yet.
  }
  return { version: 1, repositories: {} };
}

export async function isRunConfigTrusted(repoRoot: string, run: ProjectRunConfig): Promise<boolean> {
  const entry = (await readTrust()).repositories[await repositoryKey(repoRoot)];
  return typeof entry?.digest === "string" && entry.digest === runConfigDigest(run);
}

export async function trustRunConfig(repoRoot: string, run: ProjectRunConfig, now = new Date()): Promise<void> {
  const current = await readTrust();
  const key = await repositoryKey(repoRoot);
  const others = Object.entries(current.repositories)
    .filter(([name]) => name !== key)
    .sort((a, b) => b[1].confirmedAt.localeCompare(a[1].confirmedAt))
    .slice(0, MAX_REPOSITORIES - 1);
  const next: TrustFile = {
    version: 1,
    repositories: { ...Object.fromEntries(others), [key]: { digest: runConfigDigest(run), confirmedAt: now.toISOString() } }
  };
  await fs.mkdir(configDirectory(), { recursive: true, mode: 0o700 });
  await fs.writeFile(trustFile(), `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
}
