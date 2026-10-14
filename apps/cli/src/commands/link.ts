import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import { hashToken } from "@myrqen/auth";
import { ApiClient, ApiRequestError, defaultDeviceName } from "../api/client.js";
import { storeCredential } from "../config/credentials.js";
import { readConfig, updateConfig } from "../config/store.js";
import { blank, bullet, capabilityNote, field, heading, style, write } from "../ui/output.js";
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

export interface AccountLinkOptions {
  apiBaseUrl?: string;
  deviceName?: string;
  open?: boolean;
  /**
   * Offered rather than demanded.
   *
   * `myrqen link` finishes by mentioning cloud reports. Scanning is entirely
   * local and works with no account at all, so this step asks once, accepts no
   * as an answer, and never blocks a non-interactive shell.
   */
  offer?: boolean;
}

/**
 * Links this device to an account through the browser. The durable credential is
 * minted only after an authenticated human approval and is never placed in a URL.
 */
export async function accountLinkCommand(options: AccountLinkOptions = {}): Promise<void> {
  const config = await readConfig();
  const baseUrl = options.apiBaseUrl ?? config.apiBaseUrl;

  if (options.offer) {
    if (config.account) {
      blank();
      write(`${style.dim("Account")} ${config.account.email} ${style.dim("· already connected")}`);
      return;
    }
    blank();
    write(style.bold("Cloud reports"));
    capabilityNote(
      "Scanning works entirely locally and needs no account. Connecting one adds shareable web reports and history."
    );
    if (!isInteractive()) {
      bullet(`Connect later with "${BRAND.cliName} login".`);
      return;
    }
    if (!(await confirm("Connect an account now?", { defaultYes: false }))) {
      bullet(`Connect later with "${BRAND.cliName} login".`);
      return;
    }
  }

  heading("login");

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

