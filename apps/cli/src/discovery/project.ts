import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ProjectSignals } from "@myrqen/policy";
import { detectInjectionSignals, extractEnvSecretValues, normalizeHttpTarget } from "@myrqen/policy";
import type { StackSummary } from "@myrqen/contracts";
import { assertLoopbackUrl } from "../config/project-config.js";


const IGNORED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "out",
  "coverage",
  "vendor",
  "target",
  ".venv",
  "venv",
  "__pycache__",
  ".turbo",
  ".pnpm-store",
  ".myrqen",
  ".cache",
  ".idea",
  ".gradle"
]);

const SOURCE_EXTENSIONS = new Map<string, string>([
  [".ts", "TypeScript"],
  [".tsx", "TypeScript"],
  [".js", "JavaScript"],
  [".jsx", "JavaScript"],
  [".mjs", "JavaScript"],
  [".cjs", "JavaScript"],
  [".py", "Python"],
  [".go", "Go"],
  [".rb", "Ruby"],
  [".php", "PHP"],
  [".java", "Java"],
  [".kt", "Kotlin"],
  [".cs", "C#"],
  [".rs", "Rust"],
  [".swift", "Swift"]
]);

const DOCUMENT_EXTENSIONS = new Set([".md", ".mdx"]);

const CONFIG_FILES = [
  "package.json",
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
  "bun.lockb",
  "requirements.txt",
  "pyproject.toml",
  "poetry.lock",
  "go.mod",
  "Gemfile",
  "composer.json",
  "Cargo.toml",
  "docker-compose.yml",
  "compose.yml",
  "compose.yaml",
  "docker-compose.yaml",
  ".env",
  ".env.local",
  ".env.development",
  ".env.test",
  ".env.example"
];

const MAX_FILES = 4000;
const MAX_FILE_BYTES = 512 * 1024;

export interface DiscoveredProject {
  repoRoot: string;
  name: string;
  stack: StackSummary;
  signals: ProjectSignals;
  localTargets: string[];
  externalCandidates: string[];
  /**
   * Origins that appear only in content which also tries to instruct the scanner.
   * They are never offered for authorization: untrusted content must not be able
   * to widen scope, even with a human clicking through a prompt it authored.
   */
  injectionSuggestedOrigins: string[];
  testIdentityHints: string[];
  knownSecretValues: string[];
  injectionObservations: Array<{ file: string; id: string; excerpt: string }>;
  routeSamples: string[];
  sourceFiles: number;
  sourceBytes: number;
}

/*
 * A Python app often has no pyproject.toml, only requirements.txt (Flask and FastAPI
 * tutorials and most small services), so those count as a project root too.
 */
const ROOT_MARKERS = [
  ".git",
  "package.json",
  "pyproject.toml",
  "requirements.txt",
  "setup.py",
  "Pipfile",
  "go.mod",
  "Cargo.toml",
  "composer.json",
  "Gemfile"
];

/** Walk up for a repository or project marker. Falls back to the given directory. */
export async function findRepoRoot(from: string): Promise<string> {
  let current = path.resolve(from);
  for (let depth = 0; depth < 24; depth += 1) {
    for (const marker of ROOT_MARKERS) {
      try {
        await fs.access(path.join(current, marker));
        return current;
      } catch {
        // keep looking
      }
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return path.resolve(from);
}

interface WalkResult {
  files: string[];
  bytes: number;
}

async function walk(root: string): Promise<WalkResult> {
  const files: string[] = [];
  let bytes = 0;

  async function visit(directory: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name) || entry.name.startsWith(".") && entry.name !== ".github") continue;
        await visit(path.join(directory, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;
      const full = path.join(directory, entry.name);
      const extension = path.extname(entry.name);
      if (
        !SOURCE_EXTENSIONS.has(extension) &&
        !DOCUMENT_EXTENSIONS.has(extension) &&
        !CONFIG_FILES.includes(entry.name)
      ) {
        continue;
      }
      try {
        const stat = await fs.stat(full);
        if (stat.size > MAX_FILE_BYTES) continue;
        bytes += stat.size;
      } catch {
        continue;
      }
      files.push(full);
    }
  }

  await visit(root);
  return { files, bytes };
}

const FRAMEWORK_MARKERS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /"next"\s*:/, name: "Next.js" },
  { pattern: /"react"\s*:/, name: "React" },
  { pattern: /"express"\s*:/, name: "Express" },
  { pattern: /"fastify"\s*:/, name: "Fastify" },
  { pattern: /"@nestjs\/core"\s*:/, name: "NestJS" },
  { pattern: /"koa"\s*:/, name: "Koa" },
  { pattern: /"hono"\s*:/, name: "Hono" },
  { pattern: /"@sveltejs\/kit"\s*:/, name: "SvelteKit" },
  { pattern: /"nuxt"\s*:/, name: "Nuxt" },
  { pattern: /\bdjango\b/i, name: "Django" },
  { pattern: /\bflask\b/i, name: "Flask" },
  { pattern: /\bfastapi\b/i, name: "FastAPI" },
  { pattern: /\brails\b/i, name: "Rails" },
  { pattern: /\blaravel\b/i, name: "Laravel" },
  { pattern: /\bgin-gonic\b/i, name: "Gin" },
  { pattern: /\bactix\b/i, name: "Actix" }
];

const ROUTE_PATTERNS: RegExp[] = [
  // Framework registrations: app.get("/x"), router.post("/y"), @app.route("/z").
  /\b(?:app|router|server|api)\.(get|post|put|patch|delete|options|head)\s*\(\s*["'`]([^"'`]+)/gi,
  /@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["']([^"']+)/gi,
  /@(?:Get|Post|Put|Patch|Delete)\s*\(\s*["']([^"']*)/g,
  /\brouter\.(?:route)\s*\(\s*["']([^"']+)/gi,
  // Hand-rolled dispatch: route === "GET /api/orders" or pathname === "/api/orders".
  /["'`](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/[^"'`\s]*)["'`]/g,
  /\b(?:pathname|url\.pathname|req\.url)\s*===\s*["'`](\/[^"'`]*)["'`]/g
];

const SIGNAL_PATTERNS = {
  authentication: /\b(jsonwebtoken|jose|passport|next-auth|better-auth|session\s*\(|bcrypt|argon2|scrypt|login|signin|authenticate)\b/i,
  roles: /\b(isAdmin|is_admin|role\s*[:=]|roles\b|permission|authorize|acl|rbac)\b/i,
  database: /\b(prisma|knex|drizzle|sequelize|typeorm|mongoose|pg\b|mysql|sqlite|sqlalchemy|activerecord|gorm)\b/i,
  fileUpload: /\b(multer|formidable|busboy|multipart\/form-data|upload|createWriteStream)\b/i,
  serverFetch: /\b(fetch\s*\(|axios\.|got\(|http\.request|requests\.(get|post)|urllib|HttpClient)\b/i,
  payment: /\b(stripe|paypal|adyen|braintree|mollie|checkout\.session|payment_intent)\b/i,
  testIdentity: /\b(seed|fixture|test-user|testuser|E2E_|TEST_USER|admin@example|user@example)\b/i
};

const PORT_PATTERNS: RegExp[] = [
  /\blisten\s*\(\s*(\d{2,5})/g,
  /\bPORT\s*[=:]\s*["']?(\d{2,5})/gi,
  /\b--port[= ](\d{2,5})/g,
  /\bports:\s*\n\s*-\s*["']?(\d{2,5}):/gm,
  /localhost:(\d{2,5})/g,
  /127\.0\.0\.1:(\d{2,5})/g
];

// Label-by-label so a sentence-ending period is not absorbed into the hostname.
const URL_PATTERN = /https?:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*(?::\d{2,5})?(?=[/"'`\s).,;:]|$)/gi;

const IGNORED_EXTERNAL_HOSTS = new Set([
  "schemas.myrqen.invalid",
  "json-schema.org",
  "www.w3.org",
  "schema.org",
  "registry.npmjs.org",
  "github.com",
  "raw.githubusercontent.com",
  "nextjs.org",
  "reactjs.org",
  "docs.myrqen.invalid",
  "turbo.build",
  "example.com",
  "www.example.com",
  "localhost"
]);

/**
 * Threat-oriented discovery. This is a map, not a scanner: it feeds the effort
 * resolver and gives the host agent an accurate starting picture.
 */
export async function discoverProject(repoRoot: string): Promise<DiscoveredProject> {
  const { files, bytes } = await walk(repoRoot);

  const languages = new Set<string>();
  const frameworks = new Set<string>();
  const packageManagers = new Set<string>();
  const ports = new Set<number>();
  const externalOrigins = new Set<string>();
  const trustedOrigins = new Set<string>();
  const injectionSuggestedOrigins = new Set<string>();
  const routeSamples = new Set<string>();
  const knownSecretValues = new Set<string>();
  const injectionObservations: DiscoveredProject["injectionObservations"] = [];
  const testIdentityHints = new Set<string>();

  const signalHits = {
    authentication: false,
    roles: false,
    database: false,
    fileUpload: false,
    serverFetch: false,
    payment: false
  };

  let routeCount = 0;

  for (const file of files) {
    const base = path.basename(file);
    const extension = path.extname(file);
    const language = SOURCE_EXTENSIONS.get(extension);
    if (language) languages.add(language);

    if (base === "pnpm-lock.yaml") packageManagers.add("pnpm");
    if (base === "package-lock.json") packageManagers.add("npm");
    if (base === "yarn.lock") packageManagers.add("yarn");
    if (base === "bun.lockb") packageManagers.add("bun");
    if (base === "poetry.lock" || base === "pyproject.toml") packageManagers.add("poetry/pip");
    if (base === "requirements.txt") packageManagers.add("pip");
    if (base === "go.mod") packageManagers.add("go modules");
    if (base === "Gemfile") packageManagers.add("bundler");
    if (base === "composer.json") packageManagers.add("composer");
    if (base === "Cargo.toml") packageManagers.add("cargo");

    let content: string;
    try {
      content = await fs.readFile(file, "utf8");
    } catch {
      continue;
    }

    if (base.startsWith(".env")) {
      // Real .env values feed the redaction matcher. The example file does not.
      if (base !== ".env.example") for (const value of extractEnvSecretValues(content)) knownSecretValues.add(value);
    }

    for (const marker of FRAMEWORK_MARKERS) {
      if (marker.pattern.test(content)) frameworks.add(marker.name);
    }

    for (const pattern of ROUTE_PATTERNS) {
      const matcher = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = matcher.exec(content)) !== null) {
        routeCount += 1;
        const first = match[1] ?? "";
        const second = match[2];
        const method = second !== undefined && /^[a-z]+$/i.test(first) ? first.toUpperCase() : "ANY";
        const route = second !== undefined ? second : first;
        if (route.startsWith("/") && routeSamples.size < 60) routeSamples.add(`${method} ${route}`);
      }
    }

    // Next.js style file-based routes.
    const relative = path.relative(repoRoot, file).split(path.sep).join("/");
    if (/\/(?:app|pages)\/.*\/(?:route|page)\.(?:ts|tsx|js|jsx)$/.test(`/${relative}`)) {
      routeCount += 1;
      if (routeSamples.size < 60) routeSamples.add(`ANY /${relative}`);
    }

    for (const [key, pattern] of Object.entries(SIGNAL_PATTERNS)) {
      if (key === "testIdentity") {
        if (pattern.test(content) && testIdentityHints.size < 12) testIdentityHints.add(relative);
        continue;
      }
      if (pattern.test(content)) signalHits[key as keyof typeof signalHits] = true;
    }

    for (const pattern of PORT_PATTERNS) {
      const matcher = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = matcher.exec(content)) !== null) {
        const port = Number(match[1]);
        if (Number.isInteger(port) && port >= 80 && port <= 65535) ports.add(port);
      }
    }

    const fileSignals =
      DOCUMENT_EXTENSIONS.has(extension) || language ? detectInjectionSignals(content, 2) : [];
    for (const signal of fileSignals) {
      if (injectionObservations.length < 12) injectionObservations.push({ file: relative, ...signal });
    }

    const urlMatcher = new RegExp(URL_PATTERN.source, URL_PATTERN.flags);
    let urlMatch: RegExpExecArray | null;
    while ((urlMatch = urlMatcher.exec(content)) !== null) {
      try {
        const normalized = normalizeHttpTarget(urlMatch[0]);
        if (normalized.local) continue;
        if (IGNORED_EXTERNAL_HOSTS.has(normalized.hostname)) continue;
        if (normalized.hostname.endsWith(".invalid")) continue;
        externalOrigins.add(normalized.origin);
        if (fileSignals.length > 0) injectionSuggestedOrigins.add(normalized.origin);
        else trustedOrigins.add(normalized.origin);
      } catch {
        // Not a usable http target.
      }
    }
  }

  const localTargets = [...ports]
    .sort((a, b) => a - b)
    .slice(0, 12)
    .map((port) => `http://127.0.0.1:${port}`);

  const isolatedRuntimeAvailable = await dockerAvailable();
  const name = await projectName(repoRoot);

  // An origin that also appears in ordinary configuration is a real candidate; one
  // that appears only alongside injected instructions is not.
  for (const origin of trustedOrigins) injectionSuggestedOrigins.delete(origin);
  for (const origin of injectionSuggestedOrigins) externalOrigins.delete(origin);

  const signals: ProjectSignals = {
    sourceFileCount: files.length,
    sourceByteCount: bytes,
    routeCount,
    hasAuthentication: signalHits.authentication,
    hasRoles: signalHits.roles,
    hasDatabaseAccess: signalHits.database,
    hasFileUpload: signalHits.fileUpload,
    hasServerSideFetch: signalHits.serverFetch,
    hasPaymentIntegration: signalHits.payment,
    runtimeReachable: false,
    testIdentityCount: testIdentityHints.size > 0 ? 2 : 0,
    externalTargetCount: externalOrigins.size,
    isolatedRuntimeAvailable
  };

  const reachable = await firstReachable(localTargets);
  signals.runtimeReachable = reachable.length > 0;

  return {
    repoRoot,
    name,
    stack: {
      languages: [...languages].sort(),
      frameworks: [...frameworks].sort(),
      packageManagers: [...packageManagers].sort(),
      services: reachable
    },
    signals,
    localTargets,
    externalCandidates: [...externalOrigins].sort().slice(0, 24),
    injectionSuggestedOrigins: [...injectionSuggestedOrigins].sort().slice(0, 24),
    testIdentityHints: [...testIdentityHints],
    knownSecretValues: [...knownSecretValues],
    injectionObservations,
    routeSamples: [...routeSamples],
    sourceFiles: files.length,
    sourceBytes: bytes
  };
}

async function projectName(repoRoot: string): Promise<string> {
  try {
    const manifest = JSON.parse(await fs.readFile(path.join(repoRoot, "package.json"), "utf8")) as { name?: string };
    if (manifest.name) return manifest.name.replace(/^@[^/]+\//, "");
  } catch {
    // Fall through to the directory name.
  }
  return path.basename(repoRoot);
}

const ISOLATION_PROBE_TIMEOUT_MS = 2500;

/**
 * Probing for an isolated runtime must never stall a scan. An unresponsive Docker
 * daemon is a common local state, so the probe races a hard deadline, kills the
 * child outright, and reports "not available" rather than waiting or failing.
 */
async function dockerAvailable(): Promise<boolean> {
  if (process.env.MYRQEN_ASSUME_NO_ISOLATION === "1") return false;

  const { spawn } = await import("node:child_process");
  return new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (value: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };

    let child: ReturnType<typeof spawn>;
    try {
      // Not in the project directory. Windows will not remove or rename a directory
      // that is some process's working directory, and `docker info`, or a helper
      // it starts, can outlive the deadline that kills it. A probe that only asks
      // whether a daemon answers has no reason to pin the user's project.
      child = spawn("docker", ["info", "--format", "{{.ServerVersion}}"], {
        stdio: "ignore",
        cwd: os.tmpdir(),
        windowsHide: true
      });
    } catch {
      finish(false);
      return;
    }

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(false);
    }, ISOLATION_PROBE_TIMEOUT_MS);
    timer.unref?.();

    child.on("error", () => finish(false));
    child.on("close", (code) => finish(code === 0));
  });
}

/** A quick liveness probe against local candidates only. */
/**
 * Which of these loopback targets answer. Anything that is not a strict loopback
 * origin is skipped without a request, whoever supplied it: a target list can
 * carry an address read from repository content, and this probe runs on the
 * user's own machine, inside their network.
 */
export async function firstReachable(targets: string[]): Promise<string[]> {
  const reachable: string[] = [];
  await Promise.all(
    targets.map(async (target) => {
      try {
        assertLoopbackUrl(target);
      } catch {
        return;
      }
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 900);
        const response = await fetch(target, { method: "GET", signal: controller.signal, redirect: "manual" });
        clearTimeout(timer);
        if (response.status > 0) reachable.push(target);
      } catch {
        // Not listening; that is normal and not an error.
      }
    })
  );
  return reachable.sort();
}
