import { join } from "node:path";

/**
 * Serves the compiled employee handbook. It sits behind the edge cache, so the
 * only thing this process does is map a slug onto a file and set the right
 * content type.
 */
const CONTENT_ROOT = join(import.meta.dir, "..", "..", "content", "handbook");
const PREFIX = "/handbook/";
const DEFAULT_DOCUMENT = "index.md";

const CONTENT_TYPES: Record<string, string> = {
  md: "text/markdown; charset=utf-8",
  html: "text/html; charset=utf-8",
  png: "image/png",
  svg: "image/svg+xml",
};

function contentTypeFor(slug: string): string {
  const extension = slug.split(".").pop()?.toLowerCase() ?? "";
  return CONTENT_TYPES[extension] ?? "application/octet-stream";
}

Bun.serve({
  port: Number(Bun.env.PORT ?? 4010),

  async fetch(request) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(PREFIX)) {
      return new Response("Not found", { status: 404 });
    }

    // Nothing may climb out of the content directory.
    if (url.pathname.includes("..") || url.pathname.includes("\0")) {
      return new Response("Bad request", { status: 400 });
    }

    // Handbook titles have spaces and the odd apostrophe in them, so the slug
    // reaches us percent-encoded and has to be decoded before it is a filename.
    const slug = decodeURIComponent(url.pathname.slice(PREFIX.length)) || DEFAULT_DOCUMENT;
    const file = Bun.file(join(CONTENT_ROOT, slug));

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
    console.error("handbook request failed", error);
    return new Response("Internal error", { status: 500 });
  },
});

console.log(`handbook listening on ${Bun.env.PORT ?? 4010}`);
