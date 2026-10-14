import { subscribe } from "../lib/bus";
import { sessionFromCookie } from "../lib/session";

const HEARTBEAT_MS = 15_000;

/** Every dashboard lives on a customer subdomain of our own domain. */
const TRUSTED_ORIGIN_SUFFIX = "pulse.dev";

/**
 * GET /events/deployments
 *
 * Server-sent events for the deployment timeline. The browser opens this with
 * `new EventSource(url, { withCredentials: true })` so the session cookie rides
 * along and the stream is scoped to the caller's account.
 */
export async function deploymentStream(request: Request): Promise<Response> {
  const session = await sessionFromCookie(request);
  if (!session) return new Response("unauthorized", { status: 401 });

  const origin = request.headers.get("origin") ?? "";
  const headers = new Headers({
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-store",
    connection: "keep-alive",
    "x-accel-buffering": "no",
  });

  // The dashboard origin is different for every customer, so echo whichever of
  // our own subdomains asked.
  if (origin.endsWith(TRUSTED_ORIGIN_SUFFIX)) {
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

      unsubscribe = subscribe(`deployments:${session.accountId}`, send);
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
