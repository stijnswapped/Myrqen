/**
 * Moderation actions for the newsroom desk.
 *
 * Split out of the main article controller because the desk tooling drives these
 * from its own screens. Routes: src/api/article/routes/moderation.ts.
 */
import { factories } from "@strapi/strapi";

import { isFullAccessToken } from "../../../utils/access";

const RETRACTION_REASONS = ["legal", "factual", "duplicate", "embargo_breach"];

export default factories.createCoreController("api::article.article", ({ strapi }) => ({
  /**
   * POST /articles/:documentId/retract
   *
   * Pulls a story off the public site. Editorial staff only: the desk routes are
   * in the editorial policy group, so all we need in here is an actor for the
   * audit trail - the overnight legal sweep hits this with an API token rather
   * than a session.
   */
  async retract(ctx) {
    const actor = ctx.state.user
      ?? (isFullAccessToken(ctx) ? { id: 0, username: "desk-cron" } : null);

    if (!actor) {
      return ctx.unauthorized("Sign in to moderate");
    }

    const { documentId } = ctx.params;
    const { reason, note } = ctx.request.body?.data ?? {};

    if (!RETRACTION_REASONS.includes(reason)) {
      return ctx.badRequest(`reason must be one of ${RETRACTION_REASONS.join(", ")}`);
    }

    const article = await strapi.documents("api::article.article").findOne({
      documentId,
      fields: ["title", "slug", "moderationState"],
      populate: { organisation: { fields: ["name"] } },
    });

    if (!article) {
      return ctx.notFound("Article not found");
    }

    if (article.moderationState === "retracted") {
      return ctx.badRequest("That story has already been retracted");
    }

    await strapi.documents("api::article.article").unpublish({ documentId });

    const retracted = await strapi.documents("api::article.article").update({
      documentId,
      data: {
        moderationState: "retracted",
        retractionReason: reason,
        retractionNote: typeof note === "string" ? note.slice(0, 500) : null,
        retractedAt: new Date().toISOString(),
      },
      fields: ["title", "moderationState", "retractedAt"],
    });

    strapi.log.info(
      `article ${article.slug} retracted by ${actor.username} (${reason})`
    );

    await strapi.documents("api::audit-entry.audit-entry").create({
      data: {
        action: "article.retract",
        subject: documentId,
        actor: actor.username,
        detail: { reason, newsroom: (article as any).organisation?.name ?? null },
      },
    });

    ctx.body = { data: retracted };
  },

  /**
   * POST /articles/:documentId/reinstate
   *
   * Undo of the above, for when legal clears a story again.
   */
  async reinstate(ctx) {
    const actor = ctx.state.user
      ?? (isFullAccessToken(ctx) ? { id: 0, username: "desk-cron" } : null);

    if (!actor) {
      return ctx.unauthorized("Sign in to moderate");
    }

    const { documentId } = ctx.params;

    const reinstated = await strapi.documents("api::article.article").update({
      documentId,
      data: { moderationState: "cleared", retractionReason: null, retractedAt: null },
      fields: ["title", "moderationState"],
    });

    await strapi.documents("api::article.article").publish({ documentId });

    strapi.log.info(`article ${documentId} reinstated by ${actor.username}`);

    ctx.body = { data: reinstated };
  },
}));
