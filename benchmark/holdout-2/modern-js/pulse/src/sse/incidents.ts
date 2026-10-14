import { subscribe } from "../lib/bus";
import { sessionFromCookie } from "../lib/session";

const HEARTBEAT_MS = 15_000;

/** Every dashboard lives on a customer subdomain of our own domain. */
const ROOT_DOMAIN = "pulse.dev";

/**
 * `hostname` comes out of the URL parser, so it is the real host and not a
 * prefix of the string. The leading dot anchors the match at a label boundary,
 * which is what keeps a look-alike registration such as `https://notpulse.dev`
 * from being treated as ours.
 */
function isDashboardOrigin(origin: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" || parsed.port !== "") return false;
  return parsed.hostname === ROOT_DOMAIN || parsed.hostname.endsWith(`.${ROOT_DOMAIN}`);
}

/**
 * GET /events/incidents
 *
 * Server-sent events for the incident timeline. The browser opens this with
 * `new EventSource(url, { withCredentials: true })` so the session cookie rides
 * along and the stream is scoped to the caller's account.
 */
export async function incidentStream(request: Request): Promise<Response> {
  const session = await sessionFromCookie(request);
  if (!session) return new Response("unauthorized", { status: 401 });

  const origin = request.headers.get("origin") ?? "";
  const headers = new Headers({
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-store",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  });

  if (isDashboardOrigin(origin)) {
    headers.set("access-control-allow-origin", origin);
    headers.set("access-control-allow-credentials", "true");
    headers.set("vary", "origin");
  }

  const encoder = new TextEncoder();
  let unsubscribe = () => {};
  let heartbeat: ReturnType<typeof setInterval> | undefined;

  const body = new ReadableStream({
    start(controller) {
      const send = (event: { id: string; type: string; payload: unknown }) => {
        controller.enqueue(
          encoder.encode(`id: ${event.id}\nevent: ${event.type}\ndata: ${JSON.stringify(event.payload)}\n\n`),
        );
      };

      unsubscribe = subscribe(`incidents:${session.accountId}`, send);
      heartbeat = setInterval(() => controller.enqueue(encoder.encode(": keep-alive\n\n")), HEARTBEAT_MS);
      controller.enqueue(encoder.encode("retry: 5000\n\n"));
    },
    cancel() {
      unsubscribe();
      if (heartbeat) clearInterval(heartbeat);
    },
  });

  request.signal.addEventListener("abort", () => {
    unsubscribe();
    if (heartbeat) clearInterval(heartbeat);
  });

  return new Response(body, { headers });
}
