/**
 * subscriber controller
 *
 * The login itself lives in users-permissions; everything about the
 * subscription - plan, entitlements, billing contact - lives on this
 * content type and is keyed back to the account by the `account` relation.
 */
import { factories } from "@strapi/strapi";

import { resolveMembership } from "../../../utils/access";

const SELF_FIELDS = ["displayName", "email", "timezone", "marketingOptIn", "lastPortalUpdateAt"];

export default factories.createCoreController("api::subscriber.subscriber", ({ strapi }) => ({
  /**
   * GET /subscribers/me
   */
  async findMe(ctx) {
    const membership = await resolveMembership(ctx);
    if (!membership) {
      return ctx.unauthorized("Sign in to view your details");
    }

    const [subscriber] = await strapi.documents("api::subscriber.subscriber").findMany({
      filters: { account: { documentId: membership.userDocumentId } },
      fields: SELF_FIELDS,
      limit: 1,
    });

    if (!subscriber) {
      return ctx.notFound("No subscriber record for this account");
    }

    ctx.body = { data: await this.sanitizeOutput(subscriber, ctx) };
  },

  /**
   * PUT /subscribers/me
   *
   * Backs the "My details" form in the reader portal. `plan`, `entitlements`,
   * `internalNotes` and `organisation` are all marked private in
   * content-types/subscriber/schema.json, so Strapi keeps them out of the
   * payload for us and we can persist whatever the form sent.
   */
  async updateMe(ctx) {
    const membership = await resolveMembership(ctx);
    if (!membership) {
      return ctx.unauthorized("Sign in to change your details");
    }

    const [subscriber] = await strapi.documents("api::subscriber.subscriber").findMany({
      filters: { account: { documentId: membership.userDocumentId } },
      fields: ["displayName"],
      limit: 1,
    });

    if (!subscriber) {
      return ctx.notFound("No subscriber record for this account");
    }

    const payload = ctx.request.body?.data ?? {};

    if (payload.email !== undefined && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(payload.email))) {
      return ctx.badRequest("email is not a valid address");
    }

    const updated = await strapi.documents("api::subscriber.subscriber").update({
      documentId: subscriber.documentId,
      data: {
        ...payload,
        lastPortalUpdateAt: new Date().toISOString(),
      },
      fields: SELF_FIELDS,
    });

    strapi.log.debug(`subscriber ${subscriber.documentId} updated from the portal`);

    ctx.body = { data: await this.sanitizeOutput(updated, ctx) };
  },
}));
