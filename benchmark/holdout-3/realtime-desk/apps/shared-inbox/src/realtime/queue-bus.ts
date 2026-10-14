import { EventEmitter } from "node:events";

/**
 * Process-local fan-out for queue counter changes. In production this emitter
 * is fed by a single Postgres LISTEN connection held by the process, so every
 * stream in the process shares one database connection rather than polling.
 */
export const queueBus = new EventEmitter();

// One listener per open stream, and a desk pod holds a few thousand of them.
queueBus.setMaxListeners(0);

export function queueChannel(orgId: string, queueId: string): string {
  return `queue:${orgId}:${queueId}`;
}
