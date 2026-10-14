import { error, json, type RequestHandler } from "@sveltejs/kit";
import { logger } from "$lib/server/logger";
import { previewCache } from "$lib/server/cache";

const EMBED_HOSTS = new Set([
  "www.youtube.com",
  "vimeo.com",
  "open.spotify.com",
  "docs.acme-suite.com"
]);
const FETCH_TIMEOUT_MS = 4_000;
const MAX_PREVIEW_BYTES = 512 * 1024;

function titleOf(html: string) {
  return html.match(/<title[^>]*>([^<]{1,300})<\/title>/i)?.[1]?.trim() ?? null;
}

export const GET: RequestHandler = async ({ url, locals }) => {
  if (!locals.session) throw error(401, "sign in required");
  const slug = url.searchParams.get("slug");
  if (!slug || !/^[a-z0-9-]{1,64}$/.test(slug)) throw error(400, "bad slug");
  const upstream = new URL(`/oembed/${slug}.json`, "https://docs.acme-suite.com");
  const response = await fetch(upstream, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  return json(await response.json());
};

export const POST: RequestHandler = async ({ request, locals }) => {
  if (!locals.session) throw error(401, "sign in required");
  const body = (await request.json()) as { url?: string };
  if (!body.url) throw error(400, "a url is required");

  const cached = await previewCache.get(body.url);
  if (cached) return json(cached);

  let parsed: URL;
  try {
    parsed = new URL(body.url);
  } catch {
    throw error(400, "that is not a url");
  }
  if (parsed.protocol !== "https:") throw error(400, "https only");
  if (!EMBED_HOSTS.has(parsed.hostname)) {
    logger.warn({ host: parsed.hostname, tenant: locals.session.tenantId }, "embed host outside the allow list");
    throw error(422, "that host cannot be embedded");
  }

  const response = await fetch(parsed, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    redirect: "manual",
    headers: { accept: "text/html", "user-agent": "acme-suite-link-preview/1.4" }
  });
  const html = (await response.text()).slice(0, MAX_PREVIEW_BYTES);
  const preview = { url: parsed.toString(), status: response.status, title: titleOf(html) };
  await previewCache.set(body.url, preview);
  return json(preview);
};
