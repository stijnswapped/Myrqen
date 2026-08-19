import { BRAND } from "@myrqen/brand";
import { deleteCredential, readCredential } from "../config/credentials.js";
import { readConfig, updateConfig } from "../config/store.js";
import { resolveClient } from "../api/client.js";
import { blank, field, heading, json, style, write } from "../ui/output.js";
import { confirm } from "../ui/prompt.js";

export async function statusCommand(options: { asJson?: boolean } = {}): Promise<void> {
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

  if (options.asJson) {
    json({
      apiBaseUrl: config.apiBaseUrl,
      linked: Boolean(credential),
      account: config.account ? { email: config.account.email, deviceName: config.account.deviceName } : null,
      quota
    });
    return;
  }

  heading("status");
  field("App", config.apiBaseUrl);
  if (config.account && credential) {
    field("Account", config.account.email);
    field("Device", `${config.account.deviceName} · credential in ${credential.backend}`);
  } else {
    field("Account", `not linked. Run "${BRAND.cliName} link".`);
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
