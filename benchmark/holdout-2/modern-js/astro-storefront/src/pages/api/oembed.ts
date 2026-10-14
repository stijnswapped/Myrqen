import type { APIRoute } from "astro";
import { z } from "zod";
import { getSession } from "../../lib/session";

export const prerender = false;

/** Merchants paste a video link into the product description editor and we embed it. */
const body = z.object({ url: z.string().url() });

const FETCH_TIMEOUT_MS = 4_000;
const MAX_PREVIEW_BYTES = 512 * 1024;

/**
 * Exact origins, not suffixes: the key is compared against `URL.origin`, which is
 * scheme + host + port and cannot be widened by a userinfo or a subdomain trick.
 */
const PROVIDERS = new Map<string, string>([
  ["https://vimeo.com", "https://vimeo.com/api/oembed.json"],
  ["https://www.youtube.com", "https://www.youtube.com/oembed"],
  ["https://soundcloud.com", "https://soundcloud.com/oembed"],
]);

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export const POST: APIRoute = async ({ request, locals }) => {
  const session = getSession(locals);
  if (!session) return json({ error: "unauthorized" }, 401);

  const parsed = body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return json({ error: "url must be an absolute URL" }, 400);

  const submitted = new URL(parsed.data.url);
  const provider = PROVIDERS.get(submitted.origin);
  if (!provider) {
    return json({ error: "that site cannot be embedded" }, 400);
  }

  // The destination is the provider endpoint; the merchant's link only ever
  // travels inside a query parameter of it.
  const endpoint = new URL(provider);
  endpoint.searchParams.set("url", submitted.toString());
  endpoint.searchParams.set("format", "json");

  try {
    const response = await fetch(endpoint, {
      headers: { accept: "application/json", "user-agent": "storefront-oembed/1.2" },
      redirect: "manual",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    if (!response.ok) return json({ error: "the embed could not be read" }, 502);

    const payload = (await response.text()).slice(0, MAX_PREVIEW_BYTES);
    return json({ embed: JSON.parse(payload) });
  } catch (error) {
    console.warn("oembed lookup failed", { merchantId: session.merchantId, reason: String(error) });
    return json({ error: "the embed could not be read" }, 502);
  }
};
