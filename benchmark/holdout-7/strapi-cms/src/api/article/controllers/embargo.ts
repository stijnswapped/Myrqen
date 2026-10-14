/**
 * Embargo handling for the newsroom desk.
 *
 * Same route group as the moderation endpoints, and the same parked policy
 * (NB-1874), so the role and newsroom checks are done here where the article is
 * already loaded.
 */
import { factories } from "@strapi/strapi";

import { isEditorialStaff, resolveMembership } from "../../../utils/access";

const MAX_HOLD_DAYS = 30;

export default factories.createCoreController("api::article.article", ({ strapi }) => ({
  /**
   * POST /articles/:documentId/embargo
   *
   * Holds a story until the embargo lifts.
   */
  async hold(ctx) {
    const membership = await resolveMembership(ctx);

    if (!membership) {
      return ctx.unauthorized("Sign in to manage embargoes");
    }

    if (!isEditorialStaff(membership)) {
      return ctx.forbidden("Editorial staff only");
    }

    const { documentId } = ctx.params;
    const { liftAt, note } = ctx.request.body?.data ?? {};

    if (!liftAt || Number.isNaN(Date.parse(String(liftAt)))) {
      return ctx.badRequest("liftAt must be an ISO timestamp");
    }

    const daysOut = (Date.parse(String(liftAt)) - Date.now()) / 86_400_000;
    if (daysOut < 0 || daysOut > MAX_HOLD_DAYS) {
      return ctx.badRequest(`liftAt must be inside the next ${MAX_HOLD_DAYS} days`);
    }

    const article = await strapi.documents("api::article.article").findOne({
      documentId,
      fields: ["title", "slug", "moderationState"],
      populate: { organisation: { fields: ["name"] } },
    });

    if (!article) {
      return ctx.notFound("Article not found");
    }

    if ((article as any).organisation?.documentId !== membership.organisationId) {
      return ctx.forbidden("That story belongs to another newsroom");
    }

    await strapi.documents("api::article.article").unpublish({ documentId });

    const held = await strapi.documents("api::article.article").update({
      documentId,
      data: {
        moderationState: "embargoed",
        embargoLiftAt: new Date(String(liftAt)).toISOString(),
        embargoNote: typeof note === "string" ? note.slice(0, 500) : null,
      },
      fields: ["title", "moderationState", "embargoLiftAt"],
    });

    strapi.log.info(
      `article ${article.slug} embargoed until ${held.embargoLiftAt} by ${membership.userId}`
    );

    await strapi.documents("api::audit-entry.audit-entry").create({
      data: {
        action: "article.embargo",
        subject: documentId,
        actor: membership.userDocumentId,
        detail: { liftAt: held.embargoLiftAt, newsroom: membership.organisationName },
      },
    });

    ctx.body = { data: held };
  },

  /**
   * POST /articles/:documentId/embargo/lift
   *
   * Called by the scheduler and by editors who want to go early. Same two
   * checks, because the scheduler runs as a real editorial service account.
   */
  async lift(ctx) {
    const membership = await resolveMembership(ctx);

    if (!membership || !isEditorialStaff(membership)) {
      return ctx.forbidden("Editorial staff only");
    }

    const { documentId } = ctx.params;

    const [article] = await strapi.documents("api::article.article").findMany({
      filters: {
        documentId,
        organisation: { documentId: membership.organisationId },
      },
      fields: ["title", "moderationState"],
      limit: 1,
    });

    if (!article) {
      return ctx.notFound("Article not found");
    }

    await strapi.documents("api::article.article").update({
      documentId,
      data: { moderationState: "cleared", embargoLiftAt: null },
    });

    const published = await strapi.documents("api::article.article").publish({ documentId });

    ctx.body = { data: published };
  },
}));
