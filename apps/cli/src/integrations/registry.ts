import type { AdapterContext, AgentAdapter, DetectionResult, Scope } from "./types.js";
import { claudeCodeAdapter, agentsMdAdapter } from "./adapters/claude.js";
import { cursorAdapter, windsurfAdapter } from "./adapters/cursor-windsurf.js";
import { copilotAdapter, geminiAdapter } from "./adapters/copilot-gemini.js";
import { clineAdapter, rooAdapter, continueAdapter } from "./adapters/vscode-rules.js";
import { codexAdapter, kiroAdapter, aiderAdapter, opencodeAdapter } from "./adapters/misc.js";

/**
 * Every agent Myrqen knows how to integrate with, in the order the installer
 * presents them: the ones most people have first, then the rest alphabetically.
 *
 * This list is the single source of truth. The README's support matrix, the
 * `--agent` flag's accepted values, `status`, `doctor`, and `unlink` all read it,
 * so adding an agent is one new adapter file and one line here — never a change
 * spread across documentation and five commands that then disagree with each other.
 */
export const ADAPTERS: readonly AgentAdapter[] = Object.freeze([
  claudeCodeAdapter,
  codexAdapter,
  cursorAdapter,
  copilotAdapter,
  geminiAdapter,
  windsurfAdapter,
  clineAdapter,
  rooAdapter,
  continueAdapter,
  kiroAdapter,
  aiderAdapter,
  opencodeAdapter,
  agentsMdAdapter
]);

export function adapterById(id: string): AgentAdapter | undefined {
  return ADAPTERS.find((adapter) => adapter.id === id);
}

export function adapterIds(): string[] {
  return ADAPTERS.map((adapter) => adapter.id);
}

export interface DetectedAdapter {
  adapter: AgentAdapter;
  detection: DetectionResult;
  scopes: Scope[];
  /** Scopes that already carry a Myrqen integration. */
  linkedScopes: Scope[];
}

/**
 * Detect every supported agent, concurrently.
 *
 * Concurrent because a run that is permitted to probe may still launch an
 * editor or two, and every one of those is time-bounded: in sequence, thirteen
 * adapters with a worst case of a few seconds each would make `myrqen link` feel
 * broken on a machine with one slow editor. With probing off — the default
 * outside an attended terminal — this is filesystem reads and finishes in
 * milliseconds.
 */
export async function detectAll(context: AdapterContext): Promise<DetectedAdapter[]> {
  return Promise.all(
    ADAPTERS.map(async (adapter) => {
      const supported = adapter.platforms.includes(context.platform);
      const detection = supported
        ? await adapter.detect(context).catch(() => ({ detected: false, confidence: "absent" as const, signals: [] }))
        : { detected: false, confidence: "absent" as const, signals: [] };
      const installed = await adapter.installed(context).catch(() => []);
      return {
        adapter,
        detection,
        scopes: supported ? adapter.supportedScopes(context) : [],
        linkedScopes: [...new Set(installed.map((entry) => entry.scope))]
      };
    })
  );
}

/**
 * The default selection: everything Myrqen is sure about.
 *
 * `probable` is deliberately excluded from the default. A configuration
 * directory left behind by an uninstalled editor is a real thing that happens,
 * and writing files for an agent the user does not have is the kind of small
 * dishonesty that makes a setup tool feel untrustworthy. They are still offered.
 */
export function recommendedSelection(detected: DetectedAdapter[]): DetectedAdapter[] {
  return detected.filter((entry) => entry.detection.confidence === "confirmed" && entry.scopes.length > 0);
}
