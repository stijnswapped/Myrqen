/**
 * Receipt delivery.
 *
 * Card receipts live on the same mounted volume as the rest of the documents,
 * one directory per tenant. Bun streams the file straight off disk, which is
 * why this is a separate process from the API: the API pod is memory-capped
 * and a batch of receipt PDFs should not be its problem.
 */
import { resolve, sep } from "node:path";
import { subjectFromSignedCookie } from "./sessions.js";
import { auditRead } from "./audit.js";

const DOCUMENT_ROOT = process.env.DOCUMENT_ROOT ?? "/srv/wallet/documents";
const PREFIX = "/receipts/";

function notFound() {
  return new Response("not found", { status: 404, headers: { "cache-control": "no-store" } });
}

/**
 * Resolve a caller-supplied key inside the tenant's own directory.
 *
 * `resolve` collapses "..", so the only way to tell an escape from a legitimate
 * nested key is to compare the resolved path against the base afterwards. The
 * separator on the end matters: without it "/srv/wallet/documents/t_10" would
 * accept "/srv/wallet/documents/t_1000".
 */
function resolveWithinTenant(tenantId, key) {
  const base = resolve(DOCUMENT_ROOT, tenantId);
  const target = resolve(base, key);
  return target === base || target.startsWith(base + sep) ? target : null;
}

Bun.serve({
  port: Number(process.env.PORT ?? 8091),
  idleTimeout: 60,

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") return new Response("ok");
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("method not allowed", { status: 405, headers: { allow: "GET, HEAD" } });
    }
    if (!url.pathname.startsWith(PREFIX)) return notFound();

    const subject = await subjectFromSignedCookie(request);
    if (!subject) {
      return new Response("unauthorized", { status: 401, headers: { "www-authenticate": "Cookie" } });
    }

    const key = decodeURIComponent(url.pathname.slice(PREFIX.length));
    if (key.length === 0) return notFound();

    const path = resolveWithinTenant(subject.tenantId, key);
    if (!path) {
      console.warn(JSON.stringify({ event: "receipt_key_rejected", subjectId: subject.id }));
      return notFound();
    }

    const file = Bun.file(path);
    if (!(await file.exists())) return notFound();

    auditRead({ subjectId: subject.id, tenantId: subject.tenantId, key });

    return new Response(file, {
      headers: {
        "content-type": file.type || "application/octet-stream",
        "content-disposition": `inline; filename="${key.split("/").pop()}"`,
        "cache-control": "private, max-age=60"
      }
    });
  },

  error(error) {
    console.error(JSON.stringify({ event: "receipt_server_error", message: error.message }));
    return new Response("internal error", { status: 500 });
  }
});
