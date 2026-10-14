import { resolve, sep } from "node:path";

/**
 * Serves the downloadable press kit. Same job as the handbook service: map a
 * slug onto a file, set the right content type, let the edge cache do the rest.
 */
const CONTENT_ROOT = resolve(import.meta.dir, "..", "..", "content", "press-kit");
const PREFIX = "/press-kit/";
const DEFAULT_DOCUMENT = "index.md";

const CONTENT_TYPES: Record<string, string> = {
  md: "text/markdown; charset=utf-8",
  pdf: "application/pdf",
  png: "image/png",
  svg: "image/svg+xml",
};

function contentTypeFor(slug: string): string {
  const extension = slug.split(".").pop()?.toLowerCase() ?? "";
  return CONTENT_TYPES[extension] ?? "application/octet-stream";
}

/** True when `candidate` is CONTENT_ROOT itself or something underneath it. */
function insideContentRoot(candidate: string): boolean {
  return candidate === CONTENT_ROOT || candidate.startsWith(`${CONTENT_ROOT}${sep}`);
}

Bun.serve({
  port: Number(Bun.env.PORT ?? 4011),

  async fetch(request) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(PREFIX)) {
      return new Response("Not found", { status: 404 });
    }

    // Asset names have spaces in them, so decode first — a check against the
    // still-encoded path would miss %2e%2e%2f entirely.
    const slug = decodeURIComponent(url.pathname.slice(PREFIX.length)) || DEFAULT_DOCUMENT;
    const candidate = resolve(CONTENT_ROOT, slug);
    if (!insideContentRoot(candidate)) {
      return new Response("Bad request", { status: 400 });
    }

    const file = Bun.file(candidate);
    if (!(await file.exists())) {
      return new Response("Not found", { status: 404 });
    }

    return new Response(file, {
      headers: {
        "content-type": contentTypeFor(slug),
        "cache-control": "public, max-age=300",
      },
    });
  },

  error(error) {
    console.error("press-kit request failed", error);
    return new Response("Internal error", { status: 500 });
  },
});

console.log(`press-kit listening on ${Bun.env.PORT ?? 4011}`);
