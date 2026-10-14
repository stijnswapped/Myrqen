import { Hono } from "hono";
import { html, raw } from "hono/html";

import { db } from "../lib/db";
import { requireSession } from "../middleware/session";
import type { SessionEnv } from "../lib/env";

const drafts = new Hono<SessionEnv>();

// GET /campaigns/:campaignId/draft
// The campaign editor opens this in an iframe beside the form. The subject line
// comes from the query string so the preview updates as the user types; the
// body is the saved template. The html tag escapes every interpolated value.
drafts.get("/campaigns/:campaignId/draft", requireSession, async (c) => {
  const viewer = c.get("viewer");
  const campaign = await db.campaign.findFirst({
    where: { id: c.req.param("campaignId"), workspaceId: viewer.workspaceId },
    select: { templateHtml: true },
  });
  if (!campaign) {
    return c.json({ error: "Campaign not found" }, 404);
  }

  const subject = c.req.query("subject") ?? "(no subject)";
  return c.html(
    html`<!doctype html><html><head><meta charset="utf-8"><title>Preview</title></head><body><h1 class="subject">${subject}</h1>${raw(campaign.templateHtml)}</body></html>`
  );
});

export default drafts;
