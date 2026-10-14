import { execFile } from "node:child_process";

/**
 * Open a URL or a local file with the platform's default handler.
 *
 * A convenience only: every caller also prints what it opened, so a machine
 * without a browser, or a handler that fails silently, loses nothing. Arguments
 * are passed as an argv array, never through a shell string.
 *
 * Windows is the case that needs care. `cmd /c start "" <target>` hands the
 * target to cmd, which re-parses it: `&`, `|`, `^`, `%VAR%` in a report path or a
 * URL would run as commands. `explorer.exe` takes the target as a plain argument
 * and opens it with the registered handler, and a target carrying any character
 * cmd treats specially is refused anyway, in case some layer re-parses it.
 */

export interface OpenInvocation {
  command: string;
  args: string[];
}

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;
const CMD_SPECIAL = /[&|^%!"<>()]/;

/** How to open `target` on `platform`, or null when it must not be opened at all. */
export function openInvocation(target: string, platform: NodeJS.Platform = process.platform): OpenInvocation | null {
  if (!target || CONTROL_CHARACTERS.test(target)) return null;
  // A leading dash would be read as an option by open and xdg-open.
  if (target.startsWith("-")) return null;
  if (platform === "win32") {
    if (CMD_SPECIAL.test(target)) return null;
    return { command: "explorer.exe", args: [target] };
  }
  if (platform === "darwin") return { command: "open", args: [target] };
  return { command: "xdg-open", args: [target] };
}

/** Returns false when the target was refused or the opener could not be started. */
export function openExternal(target: string): boolean {
  const invocation = openInvocation(target);
  if (!invocation) return false;
  try {
    const child = execFile(invocation.command, invocation.args, () => {
      // The path or URL is always printed too.
    });
    child.unref?.();
    return true;
  } catch {
    // Same: printing the target is the fallback.
    return false;
  }
}
