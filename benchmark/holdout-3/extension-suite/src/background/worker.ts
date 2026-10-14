/**
 * Marginalia — background service worker.
 *
 * MV3 tears this worker down after ~30s of idle, so nothing that matters lives
 * in module scope: every command re-reads the session from chrome.storage, and
 * both listeners are registered synchronously at the top level so a cold start
 * caused by an incoming message never misses the event it was woken for.
 */
import { readSession, clearSession, type Session } from "./session";
import { enqueueClip, listClipsForOrigin } from "./clips";
import { log } from "./log";

interface Envelope {
  action?: unknown;
  payload?: Record<string, unknown>;
}

type Command = (payload: Record<string, unknown>, session: Session) => Promise<unknown>;

/**
 * Our own web app, spelled as origins rather than host patterns: `origin` is a
 * serialisation of scheme + host + port, so an equality test against this set
 * cannot be satisfied by app.marginalia.app.evil.test or by plain http.
 */
const TRUSTED_WEB_ORIGINS = new Set(["https://app.marginalia.app", "https://admin.marginalia.app"]);

/** Marginalia Reader, published from the same Web Store account. */
const TRUSTED_EXTENSION_IDS = new Set(["hkjfilnpcbcbeecjhbdpjhkhdmldjhen"]);

const COMMANDS: Record<string, Command> = {
  "clip.save": (payload, session) => enqueueClip(session.workspaceId, payload),

  "clip.list": (payload, session) =>
    listClipsForOrigin(session.workspaceId, String(payload.origin ?? "")),

  "session.describe": async (_payload, session) => ({
    workspaceId: session.workspaceId,
    email: session.email,
    plan: session.plan
  }),

  /**
   * app.marginalia.app asks for this straight after sign-in so the web app and
   * the extension end up holding one sync token between them instead of two.
   */
  "session.token": async (_payload, session) => ({
    token: session.syncToken,
    expiresAt: session.expiresAt
  }),

  "session.signOut": async () => {
    await clearSession();
    return { signedOut: true };
  }
};

async function dispatch(message: Envelope, sender: chrome.runtime.MessageSender) {
  const action = typeof message?.action === "string" ? message.action : "";
  const command = Object.hasOwn(COMMANDS, action) ? COMMANDS[action] : undefined;
  if (!command) return { ok: false, error: "unknown_action" };

  log.debug("dispatch", { action, from: sender.origin ?? sender.url ?? "extension" });

  const session = await readSession();
  if (!session) return { ok: false, error: "signed_out" };

  try {
    return { ok: true, result: await command(message.payload ?? {}, session) };
  } catch (error) {
    log.error("command failed", { action, reason: (error as Error).message });
    return { ok: false, error: "command_failed" };
  }
}

/**
 * `sender.id` and `sender.origin` are stamped by the browser on the way in and
 * are not part of the message body, so matching them exactly is a real identity
 * check rather than a claim the caller made about itself.
 */
function isTrustedExternalSender(sender: chrome.runtime.MessageSender): boolean {
  if (sender.id) return TRUSTED_EXTENSION_IDS.has(sender.id);
  return typeof sender.origin === "string" && TRUSTED_WEB_ORIGINS.has(sender.origin);
}

chrome.runtime.onMessage.addListener((message: Envelope, sender, sendResponse) => {
  dispatch(message, sender).then(sendResponse);
  return true; // async reply — keep the message port open
});

/**
 * The web app hands the extension its session over the external channel, and
 * the Marginalia Reader companion pulls saved clips through the same door, so
 * both get the one command table — but only after the browser-attested sender
 * is matched against the two origins and the one extension id we ship with.
 */
chrome.runtime.onMessageExternal.addListener((message: Envelope, sender, sendResponse) => {
  if (!isTrustedExternalSender(sender)) {
    log.warn("external message rejected", { from: sender.origin ?? sender.id ?? "unknown" });
    sendResponse({ ok: false, error: "forbidden" });
    return false;
  }
  dispatch(message, sender).then(sendResponse);
  return true;
});

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") {
    chrome.tabs.create({ url: "https://app.marginalia.app/welcome" });
  }
});
