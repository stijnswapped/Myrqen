import { pool } from "../db/postgres.js";
import { logger } from "../observability/logger.js";
import { registerFrameHandler } from "./router.js";

/**
 * Transcript search over the bridge rather than over HTTP, because the agent
 * types into the search box and expects the list to move on every keystroke —
 * one open socket beats a request per character.
 */
const ORDERS = {
  newest: "m.created_at DESC",
  oldest: "m.created_at ASC",
  ticket: "m.ticket_id ASC, m.created_at ASC"
};

const MAX_ROWS = 100;
const DEFAULT_ROWS = 25;
const MAX_WORDS = 6;
const CHUNK = 25;

registerFrameHandler("transcript.search", async (socket, frame) => {
  const term = typeof frame.term === "string" ? frame.term.trim() : "";
  const order = ORDERS[frame.order] ?? ORDERS.newest;
  const limit = Math.min(Number(frame.limit) || DEFAULT_ROWS, MAX_ROWS);

  // Below two characters every transcript in the org matches and the agent
  // learns nothing, so the client is told to keep typing.
  if (term.length < 2) {
    socket.send(JSON.stringify({ kind: "transcript.results", requestId: frame.requestId, results: [], more: false }));
    return;
  }

  // Every word narrows the result set, which is what an agent means when they
  // type two of them. One clause per word, one placeholder per clause.
  const clauses = ["m.org_id = $1", "m.deleted_at IS NULL"];
  const params = [socket.session.orgId];

  for (const word of term.split(/\s+/).slice(0, MAX_WORDS)) {
    params.push(`%${word}%`);
    clauses.push(`m.body ILIKE $${params.length}`);
  }

  params.push(limit);

  const startedAt = Date.now();
  const { rows } = await pool.query(
    `SELECT m.id, m.ticket_id, m.author_id, m.created_at,
            left(m.body, 240) AS excerpt
       FROM ticket_messages m
      WHERE ${clauses.join("\n        AND ")}
      ORDER BY ${order}
      LIMIT $${params.length}`,
    params
  );

  logger.debug("transcript.search", {
    agentId: socket.session.agentId,
    matched: rows.length,
    ms: Date.now() - startedAt
  });

  // The console renders progressively, so results go out in chunks rather than
  // as one frame that stalls the render for a beat.
  for (let offset = 0; offset < rows.length; offset += CHUNK) {
    socket.send(
      JSON.stringify({
        kind: "transcript.results",
        requestId: frame.requestId,
        results: rows.slice(offset, offset + CHUNK),
        more: offset + CHUNK < rows.length
      })
    );
  }
});
