import { deploymentStream } from "./sse/deployments";
import { incidentStream } from "./sse/incidents";

Bun.serve({
  port: Number(Bun.env.PORT ?? 3100),
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === "/events/deployments") return deploymentStream(request);
    if (pathname === "/events/incidents") return incidentStream(request);
    return new Response("Not found", { status: 404 });
  },
});
