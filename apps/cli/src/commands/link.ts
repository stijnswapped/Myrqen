import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import { hashToken } from "@myrqen/auth";
import { ApiClient, ApiRequestError, defaultDeviceName } from "../api/client.js";
import { storeCredential } from "../config/credentials.js";
import { readConfig, updateConfig } from "../config/store.js";
import { findRepoRoot } from "../discovery/project.js";
import { detectAgents, installSkill, skillSourceDirectory } from "../install/skill.js";
import { blank, bullet, capabilityNote, field, heading, style, warn, write } from "../ui/output.js";
import { confirm, isInteractive, text } from "../ui/prompt.js";

const POLL_TIMEOUT_MS = 10 * 60 * 1000;

function openBrowser(url: string): void {
  const command =
    process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  execFile(command, args, () => {
    // Opening a browser is a convenience; the URL is always printed too.
  });
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export interface LinkOptions {
  apiBaseUrl?: string;
  deviceName?: string;
  skipSkillInstall?: boolean;
  open?: boolean;
}

/**
 * Installs the portable skill, then links this device through the browser. The
 * durable credential is minted only after an authenticated human approval and is
 * never placed in a URL.
 */
export async function linkCommand(options: LinkOptions = {}): Promise<void> {
  const config = await readConfig();
  const baseUrl = options.apiBaseUrl ?? config.apiBaseUrl;
  const repoRoot = await findRepoRoot(process.cwd());

  heading("link");

  if (!options.skipSkillInstall) {
    await installSkillsInteractively(repoRoot);
    blank();
  }

  const client = new ApiClient({ baseUrl });
  const verifier = crypto.randomBytes(32).toString("base64url");
  const deviceName = options.deviceName ?? (isInteractive() ? (await text(`Name for this device [${defaultDeviceName()}]:`)) ?? defaultDeviceName() : defaultDeviceName());

  let created;
  try {
    created = await client.createDeviceLink({
      deviceName,
      clientVersion: CLI_VERSION,
      osFamily: process.platform,
      arch: process.arch,
      verifierHash: hashToken(verifier)
    });
  } catch (error) {
    if (error instanceof ApiRequestError && error.code === "NETWORK") {
      throw new Error(
        `${error.message}\nSet the app URL with "${BRAND.cliName} config set-url <url>" if your deployment is elsewhere.`
      );
    }
    throw error;
  }

  field("Approve in browser", created.approvalUrl);
  capabilityNote(`This request expires at ${created.expiresAt.replace("T", " ").slice(0, 16)} UTC.`);
  if (options.open !== false) openBrowser(created.approvalUrl);
  blank();
  write("Waiting for approval...");

  const deadline = Date.now() + POLL_TIMEOUT_MS;
  let approved = false;
  while (Date.now() < deadline) {
    await sleep(created.pollIntervalMs);
    let status;
    try {
      status = await client.deviceLinkStatus(created.publicRequestId);
    } catch {
      continue;
    }
    if (status.state === "approved") {
      approved = true;
      break;
    }
    if (status.state === "expired") {
      throw new Error(`This link request expired. Run "${BRAND.cliName} link" again.`);
    }
    if (status.state === "consumed") {
      throw new Error("This link request was already completed on another process.");
    }
  }

  if (!approved) throw new Error(`No approval was received. Run "${BRAND.cliName} link" again when ready.`);

  const exchanged = await client.exchangeDeviceLink(created.publicRequestId, verifier);
  const backend = await storeCredential(exchanged.userId, exchanged.deviceToken);

  await updateConfig((current) => ({
    ...current,
    apiBaseUrl: baseUrl,
    account: {
      userId: exchanged.userId,
      email: exchanged.email,
      deviceId: exchanged.deviceId,
      deviceName: exchanged.deviceName,
      linkedAt: new Date().toISOString(),
      credentialBackend: backend
    }
  }));

  blank();
  write(`${style.ok("Linked")} ${exchanged.email}`);
  field("Device", exchanged.deviceName);
  field(
    "Credential storage",
    backend === "file"
      ? "permission-restricted file (fallback; no OS keystore available)"
      : `OS keystore (${backend})`
  );
  if (backend === "file") {
    capabilityNote(
      "The credential is stored with owner-only permissions. Revoke it any time from Settings, Devices in the app."
    );
  }
  blank();
  write(style.bold("Next"));
  bullet(`Run "${BRAND.cliName} auto" in a project you own, or "/${BRAND.skillId} auto" where slash commands are supported.`);
  bullet(`Run "${BRAND.cliName} doctor" to see what this machine can assess.`);
}

async function installSkillsInteractively(repoRoot: string): Promise<void> {
  let source: string;
  try {
    source = await skillSourceDirectory();
  } catch (error) {
    warn(error instanceof Error ? error.message : "The skill bundle was not found.");
    return;
  }

  const agents = await detectAgents(repoRoot);
  const detected = agents.filter((agent) => agent.detected);
  const targets = detected.length > 0 ? detected : agents.filter((agent) => agent.id === "portable");

  write(style.bold("Agent integration"));
  if (detected.length === 0) {
    capabilityNote(
      "No agent installation was detected. Installing the portable skill so any compatible agent can find it."
    );
  }

  for (const target of targets) {
    if (target.scope === "project" && isInteractive()) {
      const wants = await confirm(`Install the ${BRAND.displayName} skill into this project for ${target.label}?`);
      if (!wants) continue;
    }
    const result = await installSkill(target, source);
    const suffix =
      result.action === "unchanged"
        ? "already current"
        : result.action === "backed_up_and_installed"
          ? `installed, previous copy kept at ${result.backupLocation}`
          : result.action;
    bullet(`${target.label}: ${suffix} (${result.location})`);
    if (target.slashInvocation) {
      bullet(`  Invoke with "/${BRAND.skillId} auto" or "${BRAND.cliName} auto".`);
    }
    await updateConfig((current) => ({
      ...current,
      agents: [
        ...(current.agents ?? []).filter((entry) => entry.location !== result.location),
        { id: target.id, installedAt: new Date().toISOString(), location: result.location }
      ]
    }));
  }
}

export async function installCommand(): Promise<void> {
  const repoRoot = await findRepoRoot(process.cwd());
  heading("install");
  await installSkillsInteractively(repoRoot);
}
