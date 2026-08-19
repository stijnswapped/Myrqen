import fs from "node:fs/promises";
import { configDirectory, configFile } from "./paths.js";

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

const DEFAULTS: GlobalConfig = {
  version: 1,
  apiBaseUrl: "http://localhost:3000",
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
