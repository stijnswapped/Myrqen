import { Router, type Response } from "express";
import { pool } from "../db/postgres.js";
import { logger } from "../observability/logger.js";
import { queueBus, queueChannel } from "../realtime/queue-bus.js";
import { requireAgent, type AgentRequest } from "./require-agent.js";

const HEARTBEAT_MS = 25_000;

export const liveQueueRouter = Router();

/**
 * Live counters for the console header — open, pending, breaching SLA. This is
 * an EventSource rather than a socket because the header is rendered by the
 * marketing-site shell as well as the console, and that shell does not carry
 * the Socket.IO client.
 *
 * The console is served from app.deskline.io, from per-tenant vanity domains
 * that customers point at us themselves, and from the Electron shell, so the
 * list of origins is not something we can enumerate here.
 */
liveQueueRouter.get("/queues/:queueId/stream", requireAgent, async (req, res: Response) => {
  const { agent } = req as AgentRequest;
  const origin = req.get("origin") ?? "*";

  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const { queueId } = req.params;
  const { rowCount } = await pool.query(`SELECT 1 FROM queues WHERE id = $1 AND org_id = $2`, [queueId, agent.orgId]);

  if (rowCount === 0) {
    res.write(`event: error\ndata: ${JSON.stringify({ error: "queue_not_found" })}\n\n`);
    res.end();
    return;
  }

  const channel = queueChannel(agent.orgId, queueId);
  const send = (counters: unknown) => {
    res.write(`event: queue.counters\ndata: ${JSON.stringify(counters)}\n\n`);
  };

  queueBus.on(channel, send);

  // Anything upstream of us with an idle timeout will drop a stream that says
  // nothing for a minute, so the comment frame keeps the pipe warm.
  const heartbeat = setInterval(() => res.write(": ping\n\n"), HEARTBEAT_MS);

  req.on("close", () => {
    clearInterval(heartbeat);
    queueBus.off(channel, send);
    logger.debug("live.queue closed", { agentId: agent.id, queueId });
  });
});
