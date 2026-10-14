/**
 * Document delivery.
 *
 * Invoices, KYC letters and signed mandates live on a mounted volume, one
 * directory per tenant. Bun streams the file straight off disk, which is why
 * this is a separate process from the API: the API pod is memory-capped and a
 * 40 MB mandate PDF should not be its problem.
 */
import { join } from "node:path";
import { subjectFromSignedCookie } from "./sessions.js";
import { auditRead } from "./audit.js";

const DOCUMENT_ROOT = process.env.DOCUMENT_ROOT ?? "/srv/wallet/documents";
const PREFIX = "/documents/";

function notFound() {
  return new Response("not found", { status: 404, headers: { "cache-control": "no-store" } });
}

Bun.serve({
  port: Number(process.env.PORT ?? 8090),
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

    // Everything after /documents/ is the tenant-relative key the API handed to
    // the browser, e.g. "invoices/2026-04/INV-000431.pdf".
    const key = decodeURIComponent(url.pathname.slice(PREFIX.length));
    if (key.length === 0) return notFound();

    const file = Bun.file(join(DOCUMENT_ROOT, subject.tenantId, key));
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
    console.error(JSON.stringify({ event: "document_server_error", message: error.message }));
    return new Response("internal error", { status: 500 });
  }
});
