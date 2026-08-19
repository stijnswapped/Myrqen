import { Hono } from "hono";
import { cors } from "hono/cors";

import { db } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const embed = new Hono<SessionEnv>();

// Customers drop the support widget onto their own marketing pages and every
// customer ships it from a different hostname, so the widget origin comes off
// the request rather than from a list we would have to keep updating.
embed.use(
  "/embed/*",
  cors({
    origin: (origin) => origin ?? "*",
    credentials: true,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["content-type", "x-widget-version"],
    maxAge: 86_400,
  })
);

embed.use("/embed/*", requireSession);

// GET /embed/conversations
// The widget's unread list for whoever is signed in on the embedding page.
embed.get("/embed/conversations", async (c) => {
  const viewer = c.get("viewer");

  const rows = await db.conversation.findMany({
    where: { workspaceId: viewer.workspaceId, participantId: viewer.userId },
    orderBy: { updatedAt: "desc" },
    take: 20,
    select: { id: true, subject: true, unreadCount: true, updatedAt: true },
  });

  return c.json({ conversations: rows });
});

// POST /embed/conversations/:id/messages
// Posts a reply from the widget composer.
embed.post("/embed/conversations/:id/messages", async (c) => {
  const viewer = c.get("viewer");
  const conversationId = c.req.param("id");
  const { body } = await c.req.json<{ body: string }>();

  const conversation = await db.conversation.findFirst({
    where: { id: conversationId, workspaceId: viewer.workspaceId, participantId: viewer.userId },
    select: { id: true },
  });

  if (!conversation) {
    return c.json({ error: "Conversation not found" }, 404);
  }

  const message = await db.message.create({
    data: { conversationId: conversation.id, authorId: viewer.userId, body },
    select: { id: true, createdAt: true },
  });

  return c.json({ message }, 201);
});

export default embed;
