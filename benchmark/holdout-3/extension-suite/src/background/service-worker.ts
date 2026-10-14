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

chrome.runtime.onMessage.addListener((message: Envelope, sender, sendResponse) => {
  dispatch(message, sender).then(sendResponse);
  return true; // async reply — keep the message port open
});

/**
 * The web app hands the extension its session over the external channel, and
 * the Marginalia Reader companion pulls saved clips through the same door, so
 * both get the one command table and stay in step with it.
 *
 * TODO(infra): narrow externally_connectable once the preview domains stop
 * moving every sprint.
 */
chrome.runtime.onMessageExternal.addListener((message: Envelope, sender, sendResponse) => {
  dispatch(message, sender).then(sendResponse);
  return true;
});

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") {
    chrome.tabs.create({ url: "https://app.marginalia.app/welcome" });
  }
});
