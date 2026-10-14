/**
 * Link preview cards.
 *
 * A content script cannot read a cross-origin document, so when the reader
 * hovers a link inside a clip the panel asks the worker to fetch it and hands
 * back a card. The extension holds <all_urls> for clipping, so this handler is
 * the one place that has to decide what the worker will and will not go and
 * read on a page's say-so.
 */
import { log } from "../log";

const PREVIEW_TIMEOUT_MS = 4_000;
const PREVIEW_BYTES = 8 * 1024;
const CACHE_TTL_MS = 5 * 60 * 1000;
const EXCERPT_CHARS = 480;

/**
 * The knowledge sources previews are offered for. Hostnames, compared with
 * Set membership: a suffix test would take arxiv.org.lookup.internal with it,
 * and the point of the list is that the set of reachable hosts is closed.
 */
const PREVIEW_HOSTS = new Set([
  "docs.marginalia.app",
  "wiki.marginalia.app",
  "arxiv.org",
  "www.arxiv.org",
  "pubmed.ncbi.nlm.nih.gov"
]);

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
 * Returns the URL we are willing to fetch, or null. Parsing first means the
 * decision is made about a real URL rather than about a string that merely
 * starts with something reassuring.
 */
function previewTarget(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (!PREVIEW_HOSTS.has(url.hostname)) return null;
  url.hash = "";
  return url;
}

/**
 * `payload.url` is the href the panel saw in the page it is rendering.
 */
export async function pagePreview(payload) {
  const raw = typeof payload.url === "string" ? payload.url.trim() : "";
  const target = raw ? previewTarget(raw) : null;
  if (!target) return { ok: false, error: "unsupported_source" };

  const key = target.toString();
  const cached = readCache(key);
  if (cached) return { ok: true, card: cached };

  let response;
  try {
    response = await fetch(key, {
      credentials: "omit",
      // An allow-listed host that answers 302 http://169.254.169.254/ would
      // otherwise walk the worker straight past the check above.
      redirect: "error",
      headers: { Accept: "text/html,application/xhtml+xml" },
      signal: AbortSignal.timeout(PREVIEW_TIMEOUT_MS)
    });
  } catch (error) {
    log.warn("preview fetch failed", { host: target.hostname, reason: error.message });
    return { ok: false, error: "unreachable" };
  }

  const html = (await response.text()).slice(0, PREVIEW_BYTES);
  const card = {
    url: key,
    status: response.status,
    title: titleOf(html) ?? key,
    description: descriptionOf(html),
    excerpt: html.slice(0, EXCERPT_CHARS)
  };

  cache.set(key, { at: Date.now(), card });
  return { ok: true, card };
}
