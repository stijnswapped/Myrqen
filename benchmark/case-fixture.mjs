import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

/**
 * One corpus case, alone in a directory, exactly as a scanner or an agent should see it.
 *
 * Extracted from `score-corpus.mjs` so the static scorer and the agent harness build
 * **byte-identical** inputs. That equality is the whole basis of comparing the two: if the
 * agent saw one more file than the engine did, the difference between their scores would be
 * partly the difference between their inputs, and nobody could tell which part.
 *
 * The directory holds the case's own file, a package manifest, and whatever `extraFiles` the
 * case ships. It holds **nothing else** — in particular no `cases.json`, which is why
 * `assertNoGroundTruth` exists below.
 */

/**
 * Where a case's file goes inside the application when the case does not say.
 *
 * The temporary directory is named for nothing in particular and the file keeps only its
 * extension, so no rule can key on a corpus path.
 */
export function defaultScanPath(entry) {
  if (entry.family.startsWith("nextjs")) return entry.file.split("/").slice(1).join("/");
  return path.join("src", path.basename(entry.file));
}

/**
 * Build the directory for one case. The caller owns removing it.
 *
 * Returns the root, and `scanAs` — the case file's path relative to that root — because
 * attributing a finding to the case's own file rather than to a shared helper is what stops
 * one finding in one `extraFiles` module being counted once per case that ships it.
 *
 * `baseDir` exists because an agent is asked to read this directory by *name*. macOS puts
 * `os.tmpdir()` at a fifty-character random path, and a small model transcribes it wrong —
 * measured: `.../00000gn/T/probe-KMzxNx` came back as `.../00000gn_T/probe-KMzxNx`, and every
 * file read failed. That scores a model on copying a path rather than on finding a defect, and
 * it penalises exactly the weaker models whose ceiling is the thing being measured. The
 * contents are unchanged, which is what byte-identical inputs means; only the name is shorter.
 */
export async function materialiseCase(corpusDir, entry, prefix = "myrqen-case-", baseDir = os.tmpdir()) {
  const source = await fs.readFile(path.join(corpusDir, entry.file), "utf8");
  await fs.mkdir(baseDir, { recursive: true });
  const root = await fs.mkdtemp(path.join(baseDir, prefix));
  const relative = entry.scanAs ?? defaultScanPath(entry);
  const target = path.join(root, relative);

  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, source, "utf8");

  // A package manifest so dependency rules have something to read, and so the project looks
  // like a project rather than a loose file.
  const manifest = entry.packageJson ?? { name: "case", version: "1.0.0", type: "module" };
  await fs.writeFile(path.join(root, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  for (const [name, contents] of Object.entries(entry.extraFiles ?? {})) {
    const extra = path.join(root, name);
    await fs.mkdir(path.dirname(extra), { recursive: true });
    await fs.writeFile(extra, contents, "utf8");
  }

  return { root, scanAs: path.relative(root, target) };
}

/**
 * Refuse to hand anybody the answers.
 *
 * Called before every agent run. A ground-truth file inside the directory under measurement
 * is the one bug that would invalidate every figure silently and plausibly — the agent would
 * simply be reading the answer key, and the resulting recall would look like a triumph.
 *
 * Cheap enough to run every time, and it throws rather than warning, because there is no
 * version of this that is acceptable to continue past.
 */
const FORBIDDEN = ["cases.json", "ground-truth.json", "manifest.json"];

export async function assertNoGroundTruth(root) {
  const offenders = [];
  const walk = async (dir) => {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        // A fixture ships its own dependencies; their manifests are not ground truth.
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        await walk(full);
        continue;
      }
      if (FORBIDDEN.includes(entry.name)) offenders.push(path.relative(root, full));
    }
  };
  await walk(root);
  if (offenders.length > 0) {
    throw new Error(`ground truth is visible to the agent: ${offenders.join(", ")}`);
  }
}
