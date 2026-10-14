import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BRAND } from "@myrqen/brand";

/**
 * Finding the portable skill bundle that ships with this CLI.
 *
 * This module used to install that bundle as well, with its own idea of which
 * agents exist and where their skills live. The adapter layer in
 * `../integrations/` replaced it: adapters compute a plan the user approves
 * before anything is written, and `../integrations/apply.ts` is the only code
 * that touches the disk, which is what makes a half-finished install roll back.
 * Two writers for one directory could disagree about the managed marker and a
 * reader could not tell which of them had run, so the imperative half is gone
 * and locating the bundle — the one job the adapters still need from here — is
 * all that is left.
 */

async function exists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve the portable skill bundle that ships with this CLI.
 *
 * The candidates cover the three shapes the bundle is found in: beside the
 * published binary, one level up from it in a development build, and inside the
 * monorepo when the CLI is run from source.
 */
export async function skillSourceDirectory(): Promise<string> {
  const override = process.env.MYRQEN_SKILL_SOURCE;
  if (override && (await exists(path.join(override, "SKILL.md")))) return override;

  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, "..", "skill"),
    path.resolve(here, "..", "..", "skill"),
    path.resolve(here, "..", "..", "..", "packages", "skill", BRAND.skillId),
    path.resolve(process.cwd(), "packages", "skill", BRAND.skillId)
  ];
  for (const candidate of candidates) {
    if (await exists(path.join(candidate, "SKILL.md"))) return candidate;
  }
  throw new Error("The portable skill bundle could not be located next to this installation.");
}
