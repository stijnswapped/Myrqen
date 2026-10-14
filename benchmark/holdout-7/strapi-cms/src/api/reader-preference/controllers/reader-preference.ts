/**
 * reader-preference controller
 *
 * Notification settings for a reader. Split off the subscriber content type so
 * the digest worker can read them without pulling billing data along.
 */
import { factories } from "@strapi/strapi";

import { resolveMembership } from "../../../utils/access";

const DIGEST_FREQUENCIES = ["off", "daily", "weekly"];
const KNOWN_TIMEZONES = [
  "Europe/Amsterdam",
  "Europe/London",
  "America/New_York",
  "America/Los_Angeles",
  "Asia/Singapore",
];

export default factories.createCoreController(
  "api::reader-preference.reader-preference",
  ({ strapi }) => ({
    /**
     * PUT /reader-preferences/me
     *
     * The form owns exactly three fields, so we build the patch out of those
     * three and never hand the request body to the document service. Anything
     * else the client sends - plan, organisation, entitlements - is dropped by
     * construction rather than by the schema.
     */
    async updateMe(ctx) {
      const membership = await resolveMembership(ctx);
      if (!membership) {
        return ctx.unauthorized("Sign in to change your preferences");
      }

      const [preference] = await strapi
        .documents("api::reader-preference.reader-preference")
        .findMany({
          filters: { account: { documentId: membership.userDocumentId } },
          fields: ["digestFrequency"],
          limit: 1,
        });

      if (!preference) {
        return ctx.notFound("No preferences for this account");
      }

      const payload = ctx.request.body?.data ?? {};
      const patch: Record<string, unknown> = {};

      if (typeof payload.newsletterOptIn === "boolean") {
        patch.newsletterOptIn = payload.newsletterOptIn;
      }

      if (typeof payload.digestFrequency === "string") {
        if (!DIGEST_FREQUENCIES.includes(payload.digestFrequency)) {
          return ctx.badRequest(`digestFrequency must be one of ${DIGEST_FREQUENCIES.join(", ")}`);
        }
        patch.digestFrequency = payload.digestFrequency;
      }

      if (typeof payload.timezone === "string") {
        if (!KNOWN_TIMEZONES.includes(payload.timezone)) {
          return ctx.badRequest("timezone is not one we support yet");
        }
        patch.timezone = payload.timezone;
      }

      if (Object.keys(patch).length === 0) {
        return ctx.badRequest("Nothing to update");
      }

      const updated = await strapi
        .documents("api::reader-preference.reader-preference")
        .update({
          documentId: preference.documentId,
          data: { ...patch, updatedFromPortalAt: new Date().toISOString() },
          fields: ["newsletterOptIn", "digestFrequency", "timezone"],
        });

      ctx.body = { data: await this.sanitizeOutput(updated, ctx) };
    },
  })
);
