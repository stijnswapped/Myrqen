import fs from "node:fs/promises";
import { configDirectory, configFile } from "./paths.js";
import { BRAND } from "@myrqen/brand";

export interface GlobalConfig {
  version: 1;
  apiBaseUrl: string;
  account?: {
    userId: string;
    email: string;
    deviceId: string;
    deviceName: string;
    linkedAt: string;
    credentialBackend: string;
  };
  update?: {
    pinnedVersion?: string;
    channel?: "stable" | "beta" | "canary";
    lastCheckedAt?: string;
    lastKnownVersion?: string;
    autoUpdate?: boolean;
  };
  agents?: Array<{ id: string; installedAt: string; location: string }>;
  telemetry?: { enabled: boolean };
}

/**
 * The hosted API, not localhost.
 *
 * A published CLI whose default endpoint is a development server fails for every
 * user on their first `link`, with a connection error that reads like their own
 * network being broken. Development points elsewhere through
 * MYRQEN_API_BASE_URL or `--url`, which is the direction that should require an
 * explicit act.
 */
const DEFAULTS: GlobalConfig = {
  version: 1,
  apiBaseUrl: BRAND.apiBaseUrl,
  telemetry: { enabled: true }
};

export async function readConfig(): Promise<GlobalConfig> {
  try {
    const parsed = JSON.parse(await fs.readFile(configFile(), "utf8")) as GlobalConfig;
    const apiBaseUrl = process.env.MYRQEN_API_BASE_URL ?? parsed.apiBaseUrl ?? DEFAULTS.apiBaseUrl;
    return { ...DEFAULTS, ...parsed, apiBaseUrl };
  } catch {
    return {
      ...DEFAULTS,
      ...(process.env.MYRQEN_API_BASE_URL ? { apiBaseUrl: process.env.MYRQEN_API_BASE_URL } : {})
    };
  }
}

export async function writeConfig(config: GlobalConfig): Promise<void> {
  await fs.mkdir(configDirectory(), { recursive: true, mode: 0o700 });
  await fs.writeFile(configFile(), `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

export async function updateConfig(patch: (config: GlobalConfig) => GlobalConfig): Promise<GlobalConfig> {
  const next = patch(await readConfig());
  await writeConfig(next);
  return next;
}
