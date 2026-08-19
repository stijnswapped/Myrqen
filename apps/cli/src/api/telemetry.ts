import { CLI_VERSION } from "@myrqen/brand";
import { createEvent } from "@myrqen/analytics";
import type { ProductEventEnvelope } from "@myrqen/analytics";
import { readConfig } from "../config/store.js";
import { resolveClient } from "./client.js";

type EventInput = Parameters<typeof createEvent>[0];

/**
 * Privacy-safe product analytics. The envelope is validated locally before it is
 * sent, delivery failures are silent, and the user can turn it off entirely.
 */
export async function track(input: EventInput): Promise<void> {
  try {
    const config = await readConfig();
    if (config.telemetry?.enabled === false || process.env.MYRQEN_TELEMETRY === "off") return;

    const event: ProductEventEnvelope = createEvent({
      ...input,
      clientVersion: input.clientVersion ?? CLI_VERSION,
      osFamily: input.osFamily ?? process.platform,
      arch: input.arch ?? process.arch
    });

    const { client } = await resolveClient();
    if (!client.authenticated) return;
    await client.sendAnalytics([event]);
  } catch {
    // Analytics must never affect a scan.
  }
}
