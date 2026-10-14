/** Small helpers so every endpoint answers with the same envelope and headers. */

export function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "content-type": "application/json; charset=utf-8", ...(init.headers ?? {}) }
  });
}

export function problem(status: number, code: string, detail?: string): Response {
  return json({ error: { code, detail } }, { status });
}

/** Endpoints that answer with per-customer data must never land in a shared cache. */
export const PRIVATE_CACHE = { "cache-control": "private, no-store" } as const;
