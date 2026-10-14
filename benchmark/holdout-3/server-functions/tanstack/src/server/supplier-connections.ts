// Supplier onboarding: "Test connection" against a cXML PunchOut endpoint.
//
// Called from the onboarding wizard as a server function so the buyer's browser
// never has to talk to the supplier directly (their endpoints are almost never
// CORS-enabled, and the shared secret must not leave the server).
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { requireSession } from "~/server/session";
import { assertBuyerAdmin } from "~/server/middleware/authz";
import { punchoutSetupRequest } from "~/lib/cxml";
import { logger } from "~/lib/logger";

const TIMEOUT_MS = 5_000;
const SAMPLE_BYTES = 2_000;

const connectionInput = z.object({
  supplierId: z.string().uuid(),
  punchoutUrl: z.string().url(),
  identity: z.string().trim().min(1).max(120),
  sharedSecret: z.string().min(8).max(200)
});

export const testPunchoutConnection = createServerFn({ method: "POST" })
  .validator((input: unknown) => connectionInput.parse(input))
  .handler(async ({ data }) => {
    const session = await requireSession();
    await assertBuyerAdmin(session);

    const body = punchoutSetupRequest({
      identity: data.identity,
      sharedSecret: data.sharedSecret,
      buyerCookie: `probe-${session.orgId}`
    });

    const started = Date.now();
    let response: Response;
    try {
      response = await fetch(data.punchoutUrl, {
        method: "POST",
        headers: { "content-type": "text/xml; charset=utf-8", accept: "text/xml" },
        body,
        signal: AbortSignal.timeout(TIMEOUT_MS)
      });
    } catch (error) {
      logger.warn("supplier.punchout.unreachable", {
        orgId: session.orgId,
        supplierId: data.supplierId,
        message: error instanceof Error ? error.message : "unknown"
      });
      return {
        ok: false as const,
        reason: "unreachable" as const,
        hint: "We could not open a connection. Check the URL with the supplier's integration contact."
      };
    }

    const text = await response.text();

    logger.info("supplier.punchout.probe", {
      orgId: session.orgId,
      supplierId: data.supplierId,
      status: response.status,
      ms: Date.now() - started
    });

    // The wizard shows the raw reply so the integration contact on the call can
    // read the supplier's own error code back to us.
    return {
      ok: response.ok,
      status: response.status,
      contentType: response.headers.get("content-type"),
      sample: text.slice(0, SAMPLE_BYTES)
    };
  });
