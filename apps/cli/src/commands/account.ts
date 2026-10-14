import { BRAND } from "@myrqen/brand";
import { deleteCredential, readCredential } from "../config/credentials.js";
import { readConfig, updateConfig } from "../config/store.js";
import { resolveClient } from "../api/client.js";
import { blank, field, heading, json, style, write } from "../ui/output.js";
import { confirm } from "../ui/prompt.js";

/**
 * Account, device, and quota state.
 *
 * `collect` returns the payload instead of printing it, so `myrqen status` can
 * put the account half and the integration half in ONE json document. Two
 * `json()` calls put two documents on stdout, and `JSON.parse` fails on the
 * concatenation — which is the whole point of `--json`.
 */
export async function statusCommand(
  options: { asJson?: boolean; collect?: boolean } = {}
): Promise<Record<string, unknown> | void> {
  const config = await readConfig();
  const credential = config.account ? await readCredential(config.account.userId) : null;
  const { client } = await resolveClient();

  let quota = null;
  if (client.authenticated) {
    try {
      quota = await client.syncQuota();
    } catch {
      quota = null;
    }
  }

  const payload = {
    apiBaseUrl: config.apiBaseUrl,
    linked: Boolean(credential),
    account: config.account ? { email: config.account.email, deviceName: config.account.deviceName } : null,
    quota
  };
  if (options.collect) return payload;
  if (options.asJson) {
    json(payload);
    return;
  }

  heading("status");
  field("App", config.apiBaseUrl);
  if (config.account && credential) {
    field("Account", config.account.email);
    field("Device", `${config.account.deviceName} · credential in ${credential.backend}`);
  } else {
    // `link` writes files into the repository; somebody who only wants an
    // account wants `login`. Sending them to the installer is the wrong default
    // for a tool that edits configuration.
    field("Account", `not linked. Run "${BRAND.cliName} login".`);
  }
  if (quota) {
    field(
      "Cloud quota",
      `${quota.daily.used}/${quota.daily.limit} today · ${quota.weekly.used}/${quota.weekly.limit} this week · ${quota.retentionDays}-day retention`
    );
  }
}

export async function logoutCommand(): Promise<void> {
  const config = await readConfig();
  if (!config.account) {
    write("This device is not linked.");
    return;
  }
  const confirmed = await confirm(
    `Remove the local credential for ${config.account.email}? The device stays listed in the app until you revoke it there.`
  );
  if (!confirmed) {
    write("Left unchanged.");
    return;
  }
  await deleteCredential(config.account.userId);
  await updateConfig((current) => {
    const next = { ...current };
    delete next.account;
    return next;
  });
  blank();
  write(`${style.ok("Removed")} the local credential. Revoke the device in the app to invalidate it server-side.`);
}

export async function setUrlCommand(url: string): Promise<void> {
  const normalized = new URL(url).origin;
  await updateConfig((current) => ({ ...current, apiBaseUrl: normalized }));
  write(`App URL set to ${normalized}`);
}

/**
 * Turn product analytics on or off, persistently.
 *
 * The setting already existed and was already honoured, but the only ways to
 * change it were an environment variable on every single command or hand-editing
 * `config.json`. A privacy control a user cannot reach without a text editor is
 * not a control, and the privacy page had to describe one that did not exist.
 *
 * `MYRQEN_TELEMETRY=off` still wins for a single command, which is the right
 * precedence: an environment variable is the narrower, more deliberate act.
 */
export async function setTelemetryCommand(value: string): Promise<void> {
  const enabled = value === "on";
  if (!enabled && value !== "off") throw new Error("Usage: config telemetry <on|off>");

  await updateConfig((current) => ({ ...current, telemetry: { enabled } }));

  if (enabled) {
    write(`${style.ok("On")}. Product events are sent from this machine while it is linked to an account.`);
    write(style.dim("A fixed list of event names and numeric metrics. Never a file path, a finding, or a hostname."));
    return;
  }
  write(`${style.ok("Off")}. No product event will be sent from this machine.`);
  write(style.dim("Nothing else changes: scanning, reports, sync, and sharing are unaffected."));
}
