import { execFile, spawn } from "node:child_process";
import fs from "node:fs/promises";
import { promisify } from "node:util";
import { BRAND } from "@myrqen/brand";
import { configDirectory, credentialFallbackFile } from "./paths.js";

const run = promisify(execFile);
const SERVICE = `${BRAND.displayName} device credential`;

export type CredentialBackend = "keychain" | "wincred" | "secret-service" | "file";

export interface StoredCredential {
  deviceToken: string;
  backend: CredentialBackend;
}

function accountName(userId: string): string {
  return `${BRAND.cliName}:${userId}`;
}

interface FallbackFile {
  version: 1;
  userId: string;
  backend: CredentialBackend;
  deviceToken: string;
}

async function writeFallback(userId: string, token: string, backend: CredentialBackend): Promise<void> {
  await fs.mkdir(configDirectory(), { recursive: true, mode: 0o700 });
  const payload: FallbackFile = { version: 1, userId, backend, deviceToken: token };
  await fs.writeFile(credentialFallbackFile(), `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  await fs.chmod(credentialFallbackFile(), 0o600).catch(() => undefined);
}

async function readFallback(userId: string): Promise<StoredCredential | null> {
  try {
    const parsed = JSON.parse(await fs.readFile(credentialFallbackFile(), "utf8")) as FallbackFile;
    if (parsed.version !== 1 || parsed.userId !== userId) return null;
    return { deviceToken: parsed.deviceToken, backend: parsed.backend };
  } catch {
    return null;
  }
}

async function macSet(userId: string, token: string): Promise<boolean> {
  try {
    await run("security", ["add-generic-password", "-U", "-a", accountName(userId), "-s", SERVICE, "-w", token]);
    return true;
  } catch {
    return false;
  }
}

async function macGet(userId: string): Promise<string | null> {
  try {
    const { stdout } = await run("security", ["find-generic-password", "-a", accountName(userId), "-s", SERVICE, "-w"]);
    const value = stdout.trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

/** secret-tool reads the secret from stdin, so this uses a short spawn. */
async function linuxSet(userId: string, token: string): Promise<boolean> {
  return new Promise((resolve) => {
    const child = spawn(
      "secret-tool",
      ["store", "--label", SERVICE, "service", SERVICE, "account", accountName(userId)],
      { stdio: ["pipe", "ignore", "ignore"] }
    );
    child.on("error", () => resolve(false));
    child.on("close", (code) => resolve(code === 0));
    child.stdin.end(token);
  });
}

async function linuxGet(userId: string): Promise<string | null> {
  try {
    const { stdout } = await run("secret-tool", ["lookup", "service", SERVICE, "account", accountName(userId)]);
    const value = stdout.trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

/** Windows uses DPAPI through PowerShell, so the ciphertext is user-bound. */
async function windowsSet(userId: string, token: string): Promise<boolean> {
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    `$bytes=[System.Text.Encoding]::UTF8.GetBytes(${JSON.stringify(token)})`,
    "$protected=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$null,'CurrentUser')",
    "[Convert]::ToBase64String($protected)"
  ].join("; ");
  try {
    const { stdout } = await run("powershell", ["-NoProfile", "-NonInteractive", "-Command", script]);
    const protectedValue = stdout.trim();
    if (!protectedValue) return false;
    await writeFallback(userId, protectedValue, "wincred");
    return true;
  } catch {
    return false;
  }
}

async function windowsGet(userId: string): Promise<string | null> {
  const stored = await readFallback(userId);
  if (!stored || stored.backend !== "wincred") return null;
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    `$protected=[Convert]::FromBase64String(${JSON.stringify(stored.deviceToken)})`,
    "$bytes=[System.Security.Cryptography.ProtectedData]::Unprotect($protected,$null,'CurrentUser')",
    "[System.Text.Encoding]::UTF8.GetString($bytes)"
  ].join("; ");
  try {
    const { stdout } = await run("powershell", ["-NoProfile", "-NonInteractive", "-Command", script]);
    const value = stdout.trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

/**
 * Device credentials go to the OS keystore when one is available. The file
 * fallback is permission-restricted and reported as a fallback by `doctor`.
 */
export async function storeCredential(userId: string, token: string): Promise<CredentialBackend> {
  if (process.env.MYRQEN_CREDENTIAL_BACKEND === "file") {
    await writeFallback(userId, token, "file");
    return "file";
  }
  if (process.platform === "darwin" && (await macSet(userId, token))) return "keychain";
  if (process.platform === "win32" && (await windowsSet(userId, token))) return "wincred";
  if (process.platform === "linux" && (await linuxSet(userId, token))) return "secret-service";
  await writeFallback(userId, token, "file");
  return "file";
}

export async function readCredential(userId: string): Promise<StoredCredential | null> {
  if (process.env.MYRQEN_DEVICE_TOKEN) {
    return { deviceToken: process.env.MYRQEN_DEVICE_TOKEN, backend: "file" };
  }
  if (process.env.MYRQEN_CREDENTIAL_BACKEND !== "file") {
    if (process.platform === "darwin") {
      const value = await macGet(userId);
      if (value) return { deviceToken: value, backend: "keychain" };
    }
    if (process.platform === "win32") {
      const value = await windowsGet(userId);
      if (value) return { deviceToken: value, backend: "wincred" };
    }
    if (process.platform === "linux") {
      const value = await linuxGet(userId);
      if (value) return { deviceToken: value, backend: "secret-service" };
    }
  }
  const fallback = await readFallback(userId);
  if (fallback && fallback.backend === "file") return fallback;
  return null;
}

export async function deleteCredential(userId: string): Promise<void> {
  if (process.platform === "darwin") {
    try {
      await run("security", ["delete-generic-password", "-a", accountName(userId), "-s", SERVICE]);
    } catch {
      // Nothing stored; deletion is idempotent.
    }
  }
  if (process.platform === "linux") {
    try {
      await run("secret-tool", ["clear", "service", SERVICE, "account", accountName(userId)]);
    } catch {
      // Nothing stored.
    }
  }
  try {
    await fs.unlink(credentialFallbackFile());
  } catch {
    // Nothing stored.
  }
}
