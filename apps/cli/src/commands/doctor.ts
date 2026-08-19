import fs from "node:fs/promises";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import { readCredential } from "../config/credentials.js";
import { configDirectory, configFile } from "../config/paths.js";
import { readConfig } from "../config/store.js";
import { resolveClient } from "../api/client.js";
import { discoverProject, findRepoRoot } from "../discovery/project.js";
import { detectAgents } from "../install/skill.js";
import { resolveRepositoryBinding } from "@myrqen/policy";
import { blank, bullet, capabilityNote, field, heading, json, style, write } from "../ui/output.js";

interface Check {
  name: string;
  state: "ok" | "info" | "attention";
  detail: string;
}

/**
 * Doctor reports capability, not alarm. A missing convenience is `info`;
 * `attention` is reserved for something that actually blocks the product.
 */
export async function doctorCommand(options: { asJson?: boolean } = {}): Promise<Check[]> {
  const checks: Check[] = [];
  const repoRoot = await findRepoRoot(process.cwd());
  const config = await readConfig();

  checks.push({ name: "cli", state: "ok", detail: `${BRAND.displayName} ${CLI_VERSION} on ${process.platform}/${process.arch}` });
  checks.push({ name: "runtime", state: "ok", detail: `node ${process.versions.node}` });
  checks.push({ name: "config", state: "ok", detail: configDirectory() });

  if (config.account) {
    const credential = await readCredential(config.account.userId);
    if (credential) {
      checks.push({
        name: "account",
        state: "ok",
        detail: `${config.account.email} · device "${config.account.deviceName}" · credential in ${
          credential.backend === "file" ? "permission-restricted file (fallback)" : `OS keystore (${credential.backend})`
        }`
      });
    } else {
      checks.push({
        name: "account",
        state: "attention",
        detail: `Configured for ${config.account.email} but no device credential was found. Run "${BRAND.cliName} link".`
      });
    }
  } else {
    checks.push({
      name: "account",
      state: "info",
      detail: `Not linked. Scans still run locally. Run "${BRAND.cliName} link" to enable cloud reports and sharing.`
    });
  }

  const { client } = await resolveClient();
  if (client.authenticated) {
    try {
      const quota = await client.syncQuota();
      checks.push({
        name: "cloud",
        state: "ok",
        detail: `${client.url} reachable · quota ${quota.daily.used}/${quota.daily.limit} today, ${quota.weekly.used}/${quota.weekly.limit} this week`
      });
    } catch (error) {
      checks.push({
        name: "cloud",
        state: "info",
        detail: `${client.url} is not reachable right now (${error instanceof Error ? error.message : "network error"}). Local scanning is unaffected.`
      });
    }
  } else {
    checks.push({ name: "cloud", state: "info", detail: `${client.url} (not linked)` });
  }

  const agents = await detectAgents(repoRoot);
  const installed = agents.filter((agent) => agent.managed);
  const detected = agents.filter((agent) => agent.detected);
  checks.push({
    name: "agents",
    state: installed.length > 0 ? "ok" : "info",
    detail:
      installed.length > 0
        ? `Skill installed for: ${installed.map((agent) => agent.label).join(", ")}`
        : detected.length > 0
          ? `Detected ${detected.map((agent) => agent.label).join(", ")} but the skill is not installed yet. Run "${BRAND.cliName} install".`
          : `No agent installation detected. The universal "${BRAND.cliName} auto" command works from any agent with shell access.`
  });

  const binding = await resolveRepositoryBinding(repoRoot).catch(() => null);
  checks.push({
    name: "project",
    state: "ok",
    detail: binding
      ? `${repoRoot} bound to ${binding.workspaceKind} workspace (${binding.source === "team_committed" ? "committed" : "local"})`
      : `${repoRoot} is not bound to a workspace yet. The first scan will ask.`
  });

  const discovered = await discoverProject(repoRoot);
  checks.push({
    name: "stack",
    state: "ok",
    detail: `${discovered.stack.languages.join(", ") || "unknown language"}${
      discovered.stack.frameworks.length > 0 ? ` · ${discovered.stack.frameworks.join(", ")}` : ""
    } · ${discovered.sourceFiles} in-scope files`
  });
  checks.push({
    name: "local runtime",
    state: discovered.stack.services.length > 0 ? "ok" : "info",
    detail:
      discovered.stack.services.length > 0
        ? `Reachable: ${discovered.stack.services.join(", ")}`
        : discovered.localTargets.length > 0
          ? `Discovered ports ${discovered.localTargets.join(", ")} but nothing answered. Start the app for runtime validation.`
          : "No local service ports were discovered. Source, configuration, and dependency checks still run."
  });
  checks.push({
    name: "isolated runtime",
    state: discovered.signals.isolatedRuntimeAvailable ? "ok" : "info",
    detail: discovered.signals.isolatedRuntimeAvailable
      ? "Available. Isolated checks can run when a check needs them."
      : "Not available on this machine. Some isolated runtime checks will be skipped and the report will say so."
  });

  try {
    const stat = await fs.stat(configFile());
    const mode = stat.mode & 0o777;
    checks.push({
      name: "permissions",
      state: mode === 0o600 ? "ok" : "attention",
      detail: `${configFile()} mode ${mode.toString(8)}`
    });
  } catch {
    checks.push({ name: "permissions", state: "info", detail: "No local config file yet." });
  }

  if (options.asJson) {
    json({ checks });
    return checks;
  }

  heading("doctor");
  for (const check of checks) {
    const marker = check.state === "ok" ? style.ok("ok") : check.state === "info" ? style.dim("info") : style.warn("check");
    write(`${marker} ${style.dim(`${check.name}:`)} ${check.detail}`);
  }
  blank();
  const attention = checks.filter((check) => check.state === "attention");
  if (attention.length === 0) {
    write(`${style.bold("Ready.")} Run "${BRAND.cliName} auto" in a project you own.`);
  } else {
    write(style.bold("Needs attention"));
    for (const check of attention) bullet(check.detail);
  }
  void capabilityNote;
  void field;
  return checks;
}
