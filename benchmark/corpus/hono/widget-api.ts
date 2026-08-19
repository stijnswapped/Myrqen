import { Hono } from "hono";
import { cors } from "hono/cors";

import { db } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const widget = new Hono<SessionEnv>();

// The status widget is served from the marketing site and the docs site, both of
// which are ours; anything else gets no CORS headers at all.
const EMBEDDING_ORIGINS = new Set([
  "https://www.helpdesk.example",
  "https://docs.helpdesk.example",
  "https://app.helpdesk.example",
]);

widget.use(
  "/widget/*",
  cors({
    origin: (origin) => (EMBEDDING_ORIGINS.has(origin) ? origin : null),
    credentials: true,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["content-type", "x-widget-version"],
    maxAge: 86_400,
  })
);

widget.use("/widget/*", requireSession);

// GET /widget/subscriptions
// The follow list the widget renders in its bell menu.
widget.get("/widget/subscriptions", async (c) => {
  const viewer = c.get("viewer");

  const rows = await db.subscription.findMany({
    where: { workspaceId: viewer.workspaceId, userId: viewer.userId },
    orderBy: { createdAt: "desc" },
    take: 20,
    select: { id: true, componentId: true, channel: true, createdAt: true },
  });

  return c.json({ subscriptions: rows });
});

// POST /widget/subscriptions
// Follows one component from the widget.
widget.post("/widget/subscriptions", async (c) => {
  const viewer = c.get("viewer");
  const { componentId, channel } = await c.req.json<{ componentId: string; channel: string }>();

  const component = await db.component.findFirst({
    where: { id: componentId, workspaceId: viewer.workspaceId },
    select: { id: true },
  });

  if (!component) {
    return c.json({ error: "Component not found" }, 404);
  }

  const subscription = await db.subscription.create({
    data: {
      workspaceId: viewer.workspaceId,
      userId: viewer.userId,
      componentId: component.id,
      channel: channel === "sms" ? "sms" : "email",
    },
    select: { id: true, createdAt: true },
  });

  return c.json({ subscription }, 201);
});

export default widget;
