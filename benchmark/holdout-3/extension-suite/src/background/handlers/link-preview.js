/**
 * Link preview cards.
 *
 * A content script cannot read a cross-origin document, so when the reader
 * hovers a link inside a clip the panel asks the worker to fetch it and hands
 * back a card. The extension holds <all_urls>, which is the whole reason the
 * feature also works on customers' internal wikis.
 */
import { log } from "../log";

const PREVIEW_TIMEOUT_MS = 4_000;
const PREVIEW_BYTES = 8 * 1024;
const CACHE_TTL_MS = 5 * 60 * 1000;
const EXCERPT_CHARS = 480;

/** url -> { at, card }. Bounded because the worker is evicted regularly anyway. */
const cache = new Map();

function readCache(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return hit.card;
}

function titleOf(html) {
  const match = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(html);
  return match ? match[1].replace(/\s+/g, " ").trim() : null;
}

function descriptionOf(html) {
  const match = /<meta[^>]+name=["']description["'][^>]+content=["']([^"']{0,300})["']/i.exec(html);
  return match ? match[1].trim() : null;
}

/**
 * `payload.url` is the href the panel saw in the page it is rendering.
 */
export async function linkPreview(payload) {
  const url = typeof payload.url === "string" ? payload.url.trim() : "";
  if (!url) return { ok: false, error: "missing_url" };

  const cached = readCache(url);
  if (cached) return { ok: true, card: cached };

  let response;
  try {
    response = await fetch(url, {
      credentials: "omit",
      headers: { Accept: "text/html,application/xhtml+xml" },
      signal: AbortSignal.timeout(PREVIEW_TIMEOUT_MS)
    });
  } catch (error) {
    log.warn("preview fetch failed", { url, reason: error.message });
    return { ok: false, error: "unreachable" };
  }

  const html = (await response.text()).slice(0, PREVIEW_BYTES);
  const card = {
    url: response.url,
    status: response.status,
    title: titleOf(html) ?? url,
    description: descriptionOf(html),
    excerpt: html.slice(0, EXCERPT_CHARS)
  };

  cache.set(url, { at: Date.now(), card });
  return { ok: true, card };
}
