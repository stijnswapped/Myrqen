/**
 * Settings patches.
 *
 * A workspace admin edits the extension's settings in the web app, and the app
 * pushes the changed subtree down as a JSON document rather than the whole
 * object — partly to keep chrome.storage.sync under its per-item quota, partly
 * so two devices editing different sections do not clobber each other.
 */
import { readSettings, writeSettings } from "./storage";
import { log } from "../log";

export interface OriginPolicy {
  trusted?: boolean;
  autoClip?: boolean;
}

export interface Settings {
  theme: string;
  autoSyncMinutes: number;
  origins: Record<string, OriginPolicy>;
}

/**
 * `JSON.parse` gives an own property for every key in the text, `__proto__`
 * included, and writing that key — or recursing into what it reads back —
 * reaches Object.prototype and changes every object in the worker.
 */
const RESERVED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Copies `patch` over `target`, one subtree at a time, so a patch that names
 * only `origins["docs.acme.test"].autoClip` leaves the rest of the tree alone.
 */
function merge(target: Record<string, unknown>, patch: Record<string, unknown>) {
  for (const key of Object.keys(patch)) {
    if (RESERVED_KEYS.has(key)) {
      log.warn("settings patch names a reserved key", { key });
      continue;
    }
    const value = patch[key];
    if (isPlainObject(value)) {
      if (!isPlainObject(target[key]) || !Object.hasOwn(target, key)) target[key] = {};
      merge(target[key] as Record<string, unknown>, value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

/**
 * The panel skips the "clip this?" prompt on origins the workspace has already
 * decided about, and clips from a trusted origin go straight to the team feed.
 */
export function isTrustedOrigin(settings: Settings, origin: string): boolean {
  return Object.hasOwn(settings.origins, origin) && settings.origins[origin]?.trusted === true;
}

/**
 * `payload.document` is the JSON the web app sent. It arrives as text because
 * the sync API signs the document and we keep the bytes it signed.
 */
export async function applySettingsProfile(payload: Record<string, unknown>) {
  const document = typeof payload.document === "string" ? payload.document : "";
  if (!document) return { ok: false, error: "missing_document" };

  let patch: unknown;
  try {
    patch = JSON.parse(document);
  } catch {
    return { ok: false, error: "malformed_document" };
  }
  if (!isPlainObject(patch)) return { ok: false, error: "malformed_document" };

  const settings = await readSettings();
  const updated = merge(settings as unknown as Record<string, unknown>, patch);
  await writeSettings(updated as unknown as Settings);

  log.info("settings patched", { keys: Object.keys(patch).join(",") });
  return { ok: true, settings: updated };
}
