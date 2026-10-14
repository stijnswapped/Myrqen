import os from "node:os";
import { skillSourceDirectory } from "../install/skill.js";
import { refusingLedger } from "./probe.js";
import type { AdapterContext } from "./types.js";

/**
 * The environment an adapter sees.
 *
 * Home directory, platform, and environment are injected rather than read from
 * `os` and `process` inside each adapter, so a fixture test can describe a
 * Windows machine with three editors installed without owning one.
 *
 * The probe ledger is injected the same way, and its default is the strict one:
 * a caller that does not hand one over gets a context that executes nothing.
 * `link`, `status`, and `doctor` build a real one from `--no-probe`,
 * `MYRQEN_NO_PROBE`, `CI`, and whether stdout is a terminal; everything else
 * stays incapable of launching somebody's agent CLI by accident.
 */
export async function adapterContext(repoRoot: string, overrides: Partial<AdapterContext> = {}): Promise<AdapterContext> {
  let skillSource = overrides.skillSource;
  if (!skillSource) {
    // A missing skill bundle is not fatal here: most adapters write a pointer,
    // and only the skill-based ones need the directory. They check for
    // themselves and report a blocked write with a readable reason.
    skillSource = await skillSourceDirectory().catch(() => "");
  }
  return {
    repoRoot,
    home: overrides.home ?? os.homedir(),
    skillSource,
    platform: overrides.platform ?? process.platform,
    env: overrides.env ?? process.env,
    probe: overrides.probe ?? refusingLedger()
  };
}
