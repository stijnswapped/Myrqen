/** Response helpers shared by every handler in the service. */

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

export function badRequest(message: string): Response {
  return json({ error: "invalid_request", message }, 400);
}

export function notFound(): Response {
  return json({ error: "not_found" }, 404);
}

export function serverError(): Response {
  // Deliberately opaque: the detail is in the log, not in the body.
  return json({ error: "internal_error" }, 500);
}
