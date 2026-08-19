import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import type { SignedManifest, UpdateDecision } from "@myrqen/updater";
import { blocksCloudSync, describeDecision, evaluateUpdate, verifyArtifact, verifyManifest } from "@myrqen/updater";
import { resolveClient } from "../api/client.js";
import { readConfig, updateConfig } from "../config/store.js";
import { blank, bullet, field, heading, json, style, warn, write } from "../ui/output.js";
import { track } from "../api/telemetry.js";

/**
 * Pinned root verification keys. A compromised API response cannot introduce a
 * new signing key, so it cannot select an artifact or cause code execution.
 */
export function trustedKeys(): Record<string, string> {
  const fromEnv = process.env.MYRQEN_UPDATE_PUBLIC_KEYS;
  if (fromEnv) {
    try {
      return JSON.parse(fromEnv) as Record<string, string>;
    } catch {
      warn("MYRQEN_UPDATE_PUBLIC_KEYS is not valid JSON and was ignored.");
    }
  }
  return EMBEDDED_KEYS;
}

/**
 * Release keys are embedded at build time. This deployment ships none yet, so
 * update checks report "no signed release channel" rather than trusting anything.
 */
const EMBEDDED_KEYS: Record<string, string> = Object.freeze({});

export interface UpdateOptions {
  asJson?: boolean;
  apply?: boolean;
  pin?: string;
  unpin?: boolean;
  channel?: "stable" | "beta" | "canary";
}

export interface UpdateCheck {
  currentVersion: string;
  decision?: UpdateDecision;
  blocksSync: boolean;
  message: string;
  verified: boolean;
  failure?: string;
}

export async function checkForUpdate(options: { channel?: "stable" | "beta" | "canary" } = {}): Promise<UpdateCheck> {
  const config = await readConfig();
  const keys = trustedKeys();
  if (Object.keys(keys).length === 0) {
    return {
      currentVersion: CLI_VERSION,
      blocksSync: false,
      verified: false,
      message: "No signed release channel is configured for this build, so no update was applied."
    };
  }

  const { client } = await resolveClient();
  let signed: SignedManifest;
  try {
    signed = (await client.updateManifest()) as SignedManifest;
  } catch (error) {
    return {
      currentVersion: CLI_VERSION,
      blocksSync: false,
      verified: false,
      message: `The release manifest could not be fetched. ${BRAND.displayName} continues on the installed version.`,
      failure: error instanceof Error ? error.message : "network error"
    };
  }

  const verification = verifyManifest(signed, { trustedKeys: keys });
  if (!verification.valid) {
    return {
      currentVersion: CLI_VERSION,
      blocksSync: false,
      verified: false,
      message: `The release manifest was refused (${verification.reason}). Nothing was downloaded or installed.`,
      failure: verification.reason
    };
  }

  const decision = evaluateUpdate({
    manifest: verification.manifest,
    currentVersion: CLI_VERSION,
    os: process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux",
    arch: process.arch === "arm64" ? "arm64" : "x64",
    channel: options.channel ?? config.update?.channel ?? "stable",
    ...(config.update?.pinnedVersion ? { pinnedVersion: config.update.pinnedVersion } : {})
  });

  await updateConfig((current) => ({
    ...current,
    update: {
      ...current.update,
      lastCheckedAt: new Date().toISOString(),
      lastKnownVersion: verification.manifest.releaseVersion
    }
  }));

  return {
    currentVersion: CLI_VERSION,
    decision,
    blocksSync: blocksCloudSync(decision),
    verified: true,
    message: describeDecision(decision, BRAND.cliName)
  };
}

export async function updateCommand(options: UpdateOptions = {}): Promise<void> {
  if (options.pin) {
    await updateConfig((current) => ({ ...current, update: { ...current.update, pinnedVersion: options.pin! } }));
    write(`Pinned ${BRAND.cliName} to ${options.pin}. Revocations and minimum-version rules still apply.`);
    return;
  }
  if (options.unpin) {
    await updateConfig((current) => {
      const update = { ...current.update };
      delete update.pinnedVersion;
      return { ...current, update };
    });
    write(`Removed the ${BRAND.cliName} version pin.`);
    return;
  }

  const check = await checkForUpdate(options.channel ? { channel: options.channel } : {});
  if (options.asJson) {
    json(check);
    return;
  }

  heading("update");
  field("Installed", check.currentVersion);
  write(check.message);
  if (check.failure) bullet(`Reason: ${check.failure}`);
  if (check.blocksSync) {
    blank();
    write(
      style.warn(
        "Cloud sync is blocked on this version. Local scanning and local reports still work while you upgrade."
      )
    );
  }

  await track({
    name: "update_check_completed",
    client: "cli",
    metrics: { update_state: check.decision?.action ?? (check.verified ? "unknown" : "unverified") }
  });

  if (!options.apply || !check.decision || check.decision.action !== "update_available") return;

  const artifact = check.decision.artifact;
  write(`Downloading ${artifact.url}`);
  const response = await fetch(artifact.url);
  if (!response.ok) throw new Error(`The artifact could not be downloaded (status ${response.status}).`);
  const body = Buffer.from(await response.arrayBuffer());

  const artifactCheck = verifyArtifact(body, artifact);
  if (!artifactCheck.ok) {
    throw new Error(`Refusing to install: ${artifactCheck.reason}. Nothing was written to disk.`);
  }

  const staging = path.join(os.tmpdir(), `myrqen-update-${crypto.randomBytes(6).toString("hex")}`);
  await fs.mkdir(staging, { recursive: true });
  const staged = path.join(staging, "artifact.tgz");
  await fs.writeFile(staged, body, { mode: 0o600 });

  blank();
  write(`${style.ok("Verified")} ${artifact.sha256.slice(0, 16)}… staged at ${staged}`);
  write(
    `Install it with your package manager, for example "npm install -g ${staged}". ${BRAND.displayName} does not execute release payloads itself.`
  );
}
