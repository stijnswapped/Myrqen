/**
 * syndication-feed controller
 *
 * Newsrooms pull wire copy from partner feeds. Before an editor saves a feed we
 * let them preview it, which means fetching it server side - the browser cannot,
 * because none of the partners send CORS headers.
 */
import { factories } from "@strapi/strapi";

import { isEditorialStaff, resolveMembership } from "../../../utils/access";

const FETCH_TIMEOUT_MS = 8_000;
const PREVIEW_BYTES = 4_096;

export default factories.createCoreController(
  "api::syndication-feed.syndication-feed",
  ({ strapi }) => ({
    /**
     * POST /syndication-feeds/preview
     *
     * Body: { data: { url, headers? } }
     *
     * Only editorial staff get this far, and they paste the url straight out of
     * the partner's onboarding pack, so there is nothing to check beyond it
     * parsing as a url. Some partners want a bearer token, hence `headers`.
     */
    async preview(ctx) {
      const membership = await resolveMembership(ctx);

      if (!membership || !isEditorialStaff(membership)) {
        return ctx.forbidden("Editorial staff only");
      }

      const { url, headers } = ctx.request.body?.data ?? {};

      if (typeof url !== "string" || !url.length) {
        return ctx.badRequest("A feed url is required");
      }

      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        return ctx.badRequest("That is not a url");
      }

      const response = await fetch(parsed.toString(), {
        method: "GET",
        headers: {
          accept: "application/rss+xml, application/atom+xml, application/xml",
          "user-agent": "Northbeam-Syndication/1.4",
          ...(typeof headers === "object" && headers ? headers : {}),
        },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });

      const body = await response.text();

      strapi.log.info(
        `feed preview for ${parsed.host} by ${membership.userDocumentId} -> ${response.status}`
      );

      ctx.body = {
        data: {
          status: response.status,
          contentType: response.headers.get("content-type"),
          bytes: body.length,
          sample: body.slice(0, PREVIEW_BYTES),
        },
      };
    },

    /**
     * POST /syndication-feeds
     *
     * Saving a feed only records the url; the importer picks it up on its next
     * pass.
     */
    async create(ctx) {
      const membership = await resolveMembership(ctx);

      if (!membership || !isEditorialStaff(membership)) {
        return ctx.forbidden("Editorial staff only");
      }

      const { url, label } = ctx.request.body?.data ?? {};

      if (typeof url !== "string" || typeof label !== "string") {
        return ctx.badRequest("url and label are required");
      }

      const feed = await strapi.documents("api::syndication-feed.syndication-feed").create({
        data: {
          label: label.slice(0, 120),
          url,
          organisation: membership.organisationId,
          addedBy: membership.userDocumentId,
        },
        fields: ["label", "url"],
      });

      ctx.body = { data: feed };
    },
  })
);
