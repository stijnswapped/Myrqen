import type { APIRoute } from "astro";
import { z } from "zod";
import { getSession } from "../../lib/session";
import { parseOpenGraph } from "../../lib/open-graph";

export const prerender = false;

/** Merchants paste a link into the product description editor and we render a card. */
const body = z.object({ url: z.string().url() });

const FETCH_TIMEOUT_MS = 4_000;
const MAX_PREVIEW_BYTES = 512 * 1024;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "0:0:0:0:0:0:0:1", "[::1]"]);

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

  const target = new URL(parsed.data.url);
  if (target.protocol !== "https:" && target.protocol !== "http:") {
    return json({ error: "only http and https links can be previewed" }, 400);
  }
  // Keep the editor from pointing the preview at the box it is running on.
  if (LOOPBACK_HOSTS.has(target.hostname.toLowerCase())) {
    return json({ error: "that host cannot be previewed" }, 400);
  }

  try {
    const response = await fetch(target, {
      headers: { accept: "text/html", "user-agent": "storefront-link-preview/1.2" },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });

    if (!response.ok) return json({ error: "the page could not be read" }, 502);

    const html = (await response.text()).slice(0, MAX_PREVIEW_BYTES);
    return json({ preview: parseOpenGraph(html), fetchedFrom: response.url });
  } catch (error) {
    console.warn("link preview failed", { merchantId: session.merchantId, reason: String(error) });
    return json({ error: "the page could not be read" }, 502);
  }
};
