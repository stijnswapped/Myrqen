import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scanPython } from "../dist/index.js";

/** Scan a throwaway project made of the given files. */
export async function scanFiles(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-py-"));
  try {
    for (const [name, text] of Object.entries(files)) {
      const target = path.join(root, name);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, text.replace(/^\n/, ""), "utf8");
    }
    return await scanPython({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

export function categories(result) {
  return result.candidates.map((candidate) => candidate.category).sort();
}

export function only(result, category) {
  return result.candidates.filter((candidate) => candidate.category === category);
}
