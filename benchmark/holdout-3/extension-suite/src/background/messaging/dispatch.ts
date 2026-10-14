/**
 * Command router.
 *
 * Everything that reaches the worker comes through here: the content script on
 * every tab, the options page, and the popup. The two command tables are split
 * because they are not the same kind of thing — member commands act on the tab
 * in front of the user, workspace commands change how the extension behaves
 * everywhere and are meant to be driven from the options page only.
 */
import { MEMBER_COMMANDS } from "../commands/member";
import { WORKSPACE_COMMANDS } from "../commands/workspace";
import { log } from "../log";

export type SenderKind = "extension-page" | "content-script" | "external";

export interface Envelope {
  action?: unknown;
  payload?: Record<string, unknown>;
}

export interface CommandContext {
  sender: chrome.runtime.MessageSender;
  senderKind: SenderKind;
}

export type Command = (payload: Record<string, unknown>, context: CommandContext) => Promise<unknown>;

const EXTENSION_BASE = chrome.runtime.getURL("");

/**
 * A message from the options page has no `tab` and carries our own extension
 * URL; a content script always carries the tab it was injected into.
 */
export function classifySender(sender: chrome.runtime.MessageSender): SenderKind {
  if (sender.id && sender.id !== chrome.runtime.id) return "external";
  if (sender.tab) return "content-script";
  return sender.url?.startsWith(EXTENSION_BASE) ? "extension-page" : "external";
}

/**
 * Table lookup by a caller-supplied string, so `Object.hasOwn` rather than a
 * bare index: "constructor" is otherwise a hit on every object in the runtime.
 */
function pick(table: Record<string, Command>, action: string): Command | undefined {
  return Object.hasOwn(table, action) ? table[action] : undefined;
}

export async function dispatch(message: Envelope, sender: chrome.runtime.MessageSender) {
  const action = typeof message?.action === "string" ? message.action : "";
  const senderKind = classifySender(sender);
  log.debug("dispatch", { action, senderKind, tab: sender.tab?.id ?? null });

  let handler = pick(MEMBER_COMMANDS, action);
  if (!handler && pick(WORKSPACE_COMMANDS, action)) {
    // A content script is one page-controlled `postMessage` bridge away from
    // being driven by the site it was injected into, so it does not get to
    // change the workspace's own settings however plausible the action looks.
    if (senderKind !== "extension-page") {
      log.warn("workspace command refused", { action, senderKind, url: sender.url ?? null });
      return { ok: false, error: "forbidden" };
    }
    handler = pick(WORKSPACE_COMMANDS, action);
  }

  if (!handler) {
    log.debug("unknown action", { action, senderKind });
    return { ok: false, error: "unknown_action" };
  }

  try {
    const result = await handler(message.payload ?? {}, { sender, senderKind });
    return { ok: true, result };
  } catch (error) {
    log.error("command failed", { action, senderKind, reason: (error as Error).message });
    return { ok: false, error: "command_failed" };
  }
}

export function installRouter() {
  chrome.runtime.onMessage.addListener((message: Envelope, sender, sendResponse) => {
    dispatch(message, sender).then(sendResponse);
    return true;
  });
}
