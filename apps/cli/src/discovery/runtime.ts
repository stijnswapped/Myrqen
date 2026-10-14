import fs from "node:fs/promises";
import path from "node:path";

/**
 * How to start the application under test.
 *
 * Runtime verification needs the app running, and "how do I start it" is the
 * question an agent otherwise answers by guessing — or a human answers again on
 * every run. This reads the obvious places once: package.json scripts, the
 * lockfile for the package manager, the framework's default port, a port named in
 * the script or the source, and the *names* of environment variables the
 * project's example env file declares.
 *
 * Never a value. `.env`, `.env.local`, and friends are not opened here; only
 * `.env.example`-style templates are, and only the left-hand side of each line is
 * kept. A template that carries a real secret on its right-hand side still does
 * not get that secret into Myrqen's config.
 */

export interface RunConfig {
  /** The shell command that starts the app, e.g. "npm run dev". */
  command: string;
  /** The loopback URL the app answers on once started. */
  url: string;
  port: number;
  /** Names of environment variables the app expects. Names only, never values. */
  env: string[];
  /** The package.json script the command runs, when there is one. */
  script?: string;
  framework?: string;
  packageManager?: string;
  /** Where each part came from, so `myrqen config` can say why. */
  reasons: string[];
}

const SCRIPT_PREFERENCE = ["dev", "start:dev", "develop", "serve", "start"];

const FRAMEWORK_DEFAULTS: ReadonlyArray<{ dependency: string; name: string; port: number }> = [
  { dependency: "next", name: "Next.js", port: 3000 },
  { dependency: "nuxt", name: "Nuxt", port: 3000 },
  { dependency: "@remix-run/dev", name: "Remix", port: 3000 },
  { dependency: "@nestjs/core", name: "NestJS", port: 3000 },
  { dependency: "astro", name: "Astro", port: 4321 },
  { dependency: "@sveltejs/kit", name: "SvelteKit", port: 5173 },
  { dependency: "vite", name: "Vite", port: 5173 },
  { dependency: "@angular/core", name: "Angular", port: 4200 },
  { dependency: "gatsby", name: "Gatsby", port: 8000 },
  { dependency: "express", name: "Express", port: 3000 },
  { dependency: "fastify", name: "Fastify", port: 3000 },
  { dependency: "hono", name: "Hono", port: 3000 },
  { dependency: "koa", name: "Koa", port: 3000 }
];

const ENV_TEMPLATES = [".env.example", ".env.sample", ".env.template", ".env.dist", "example.env"];

const SCRIPT_PORT_PATTERNS: RegExp[] = [
  /(?:^|\s)(?:--port|-p)[= ](\d{2,5})\b/,
  /\bPORT=(\d{2,5})\b/
];

const SOURCE_PORT_PATTERNS: RegExp[] = [
  /\blisten\s*\(\s*(\d{2,5})/,
  /\bPORT\s*\?\?\s*(\d{2,5})/,
  /\bPORT\s*\|\|\s*(\d{2,5})/,
  /\bport\s*:\s*(\d{2,5})/
];

const SOURCE_CANDIDATES = [
  "server.js",
  "server.ts",
  "index.js",
  "index.ts",
  "app.js",
  "app.ts",
  "main.ts",
  "src/server.js",
  "src/server.ts",
  "src/index.js",
  "src/index.ts",
  "src/app.js",
  "src/app.ts",
  "src/main.ts",
  "vite.config.ts",
  "vite.config.js"
];

interface Manifest {
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  main?: string;
}

async function readManifest(repoRoot: string): Promise<Manifest | null> {
  try {
    return JSON.parse(await fs.readFile(path.join(repoRoot, "package.json"), "utf8")) as Manifest;
  } catch {
    return null;
  }
}

async function exists(file: string): Promise<boolean> {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

export async function detectPackageManager(repoRoot: string): Promise<string> {
  if (await exists(path.join(repoRoot, "pnpm-lock.yaml"))) return "pnpm";
  if (await exists(path.join(repoRoot, "yarn.lock"))) return "yarn";
  if ((await exists(path.join(repoRoot, "bun.lockb"))) || (await exists(path.join(repoRoot, "bun.lock")))) return "bun";
  return "npm";
}

export function scriptCommand(packageManager: string, script: string): string {
  if (packageManager === "npm") return script === "start" ? "npm start" : `npm run ${script}`;
  if (packageManager === "bun") return `bun run ${script}`;
  return `${packageManager} ${script}`;
}

function validPort(value: number): boolean {
  return Number.isInteger(value) && value >= 80 && value <= 65535;
}

function firstMatch(patterns: RegExp[], text: string): number | null {
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match && validPort(Number(match[1]))) return Number(match[1]);
  }
  return null;
}

/** Names declared by an env template. Values are discarded line by line. */
export function parseEnvNames(contents: string): string[] {
  const names = new Set<string>();
  for (const raw of contents.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (match) names.add(match[1]!);
  }
  return [...names].slice(0, 60);
}

async function envNames(repoRoot: string): Promise<{ names: string[]; source?: string }> {
  for (const template of ENV_TEMPLATES) {
    try {
      const contents = await fs.readFile(path.join(repoRoot, template), "utf8");
      return { names: parseEnvNames(contents), source: template };
    } catch {
      // try the next template name
    }
  }
  return { names: [] };
}

async function sourcePort(repoRoot: string, manifest: Manifest | null): Promise<{ port: number; file: string } | null> {
  const candidates = [...(manifest?.main ? [manifest.main] : []), ...SOURCE_CANDIDATES];
  for (const relative of candidates) {
    try {
      const text = await fs.readFile(path.join(repoRoot, relative), "utf8");
      const port = firstMatch(SOURCE_PORT_PATTERNS, text);
      if (port) return { port, file: relative };
    } catch {
      // not there
    }
  }
  return null;
}

/**
 * Best-effort detection. Returns null when there is nothing to start — no
 * manifest script and no server entry — rather than inventing a command.
 */
export async function detectRunConfig(
  repoRoot: string,
  hints: { discoveredPorts?: number[] } = {}
): Promise<RunConfig | null> {
  const manifest = await readManifest(repoRoot);
  const reasons: string[] = [];
  const packageManager = await detectPackageManager(repoRoot);
  const scripts = manifest?.scripts ?? {};
  const script = SCRIPT_PREFERENCE.find((name) => typeof scripts[name] === "string" && scripts[name]!.trim().length > 0);

  const dependencies = { ...(manifest?.devDependencies ?? {}), ...(manifest?.dependencies ?? {}) };
  const framework = FRAMEWORK_DEFAULTS.find((entry) => entry.dependency in dependencies);

  let command: string | null = null;
  if (script) {
    command = scriptCommand(packageManager, script);
    reasons.push(`package.json script "${script}"`);
  }

  let port: number | null = null;
  if (script) {
    port = firstMatch(SCRIPT_PORT_PATTERNS, scripts[script]!);
    if (port) reasons.push(`port ${port} named in the "${script}" script`);
  }
  const fromSource = port ? null : await sourcePort(repoRoot, manifest);
  if (!command && fromSource) {
    command = `node ${fromSource.file}`;
    reasons.push(`server entry ${fromSource.file}`);
  }
  if (!port && fromSource) {
    port = fromSource.port;
    reasons.push(`port ${port} in ${fromSource.file}`);
  }
  if (!port && framework) {
    port = framework.port;
    reasons.push(`${framework.name} default port ${port}`);
  }
  if (!port && hints.discoveredPorts && hints.discoveredPorts.length > 0) {
    port = hints.discoveredPorts[0]!;
    reasons.push(`port ${port} referenced in the project`);
  }

  if (!command) return null;
  if (!port) {
    port = 3000;
    reasons.push("no port found; assuming 3000");
  }

  const env = await envNames(repoRoot);
  if (env.source && env.names.length > 0) reasons.push(`${env.names.length} variable name(s) from ${env.source}`);

  return {
    command,
    url: `http://127.0.0.1:${port}`,
    port,
    env: env.names,
    ...(script ? { script } : {}),
    ...(framework ? { framework: framework.name } : {}),
    packageManager,
    reasons
  };
}
