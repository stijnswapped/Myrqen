import os from "node:os";
import path from "node:path";
import { BRAND } from "@myrqen/brand";

/** Platform-correct config directory. No product data is written outside it. */
export function configDirectory(): string {
  const override = process.env.MYRQEN_CONFIG_DIR;
  if (override) return path.resolve(override);

  if (process.platform === "win32") {
    const base = process.env.APPDATA ?? path.join(os.homedir(), "AppData", "Roaming");
    return path.join(base, BRAND.displayName);
  }
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support", BRAND.displayName);
  }
  const xdg = process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), ".config");
  return path.join(xdg, BRAND.configDirectoryName);
}

export function configFile(): string {
  return path.join(configDirectory(), "config.json");
}

export function credentialFallbackFile(): string {
  return path.join(configDirectory(), "credential.json");
}

export function stateDirectory(repoRoot: string): string {
  return path.join(repoRoot, BRAND.repoStateDirectoryName);
}

export function sessionDirectory(repoRoot: string, localReportId: string): string {
  return path.join(stateDirectory(repoRoot), "sessions", localReportId);
}

export function reportDirectory(repoRoot: string, localReportId: string): string {
  return path.join(stateDirectory(repoRoot), "reports", localReportId);
}

export function currentSessionPointer(repoRoot: string): string {
  return path.join(stateDirectory(repoRoot), "current-session");
}
