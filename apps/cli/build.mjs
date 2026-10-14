#!/usr/bin/env node
/**
 * Bundles the CLI into a single ESM file and copies the portable skill bundle
 * next to it, so the published package works without the workspace.
 */
import { chmod, cp, mkdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import { build } from "esbuild";

const here = import.meta.dirname;
const outFile = path.join(here, "dist", "myrqen.mjs");

await rm(path.join(here, "dist"), { recursive: true, force: true });
await mkdir(path.join(here, "dist"), { recursive: true });

await build({
  entryPoints: [path.join(here, "src", "index.ts")],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outfile: outFile,
  // Minified because this is what `npx myrqen@latest` downloads before it does
  // anything at all, and the bundle inlines the TypeScript compiler for the
  // static engine's parser. The source map stays next to it for local debugging
  // and is deliberately not in the published `files` list: it is larger than the
  // bundle and nobody installing a CLI reads it.
  minify: true,
  sourcemap: true,
  // The TypeScript compiler is CommonJS and reaches for `require` at runtime.
  // An ESM bundle has none, so esbuild's shim throws on the first call. Giving
  // the bundle a real `require` is what makes the static analyser usable from a
  // single published file.
  banner: {
    js: [
      "#!/usr/bin/env node",
      "import { createRequire as __createRequire } from 'node:module';",
      "const require = __createRequire(import.meta.url);",
      "import { fileURLToPath as __fileURLToPath } from 'node:url';",
      "import { dirname as __dirname_of } from 'node:path';",
      "const __filename = __fileURLToPath(import.meta.url);",
      "const __dirname = __dirname_of(__filename);"
    ].join("\n")
  },
  // Node builtins stay external; everything else is inlined for portability.
  external: ["node:*"],
  logLevel: "warning"
});

await chmod(outFile, 0o755);

const skillSource = path.resolve(here, "..", "..", "packages", "skill", "myrqen");
const skillTarget = path.join(here, "skill");
await rm(skillTarget, { recursive: true, force: true });
await cp(skillSource, skillTarget, { recursive: true });

// npm includes a package's own LICENSE automatically, and a security tool that
// ships without its licence text is exactly the kind of detail a careful person
// checks before running it. The file lives once at the repository root; this
// copies it next to the manifest so the published tarball carries it.
await cp(path.resolve(here, "..", "..", "LICENSE"), path.join(here, "LICENSE"));

const { size } = await stat(outFile);
process.stdout.write(
  `built ${path.relative(process.cwd(), outFile)} (${Math.round(size / 1024)} KB) with bundled skill and licence\n`
);
