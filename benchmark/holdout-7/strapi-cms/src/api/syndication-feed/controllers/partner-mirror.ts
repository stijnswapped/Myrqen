/**
 * Partner mirror preview.
 *
 * Same job as the feed preview - fetch something on the server and show the
 * editor what came back - but the mirror endpoints are a fixed set of partner
 * hosts, so the url is checked against that set before anything is opened.
 */
import { factories } from "@strapi/strapi";

import { isEditorialStaff, resolveMembership } from "../../../utils/access";

const FETCH_TIMEOUT_MS = 8_000;
const PREVIEW_BYTES = 4_096;

/**
 * Exact hostnames. The list changes maybe twice a year when a wire contract is
 * signed, so it lives here rather than in the database.
 */
const PARTNER_HOSTS = new Set([
  "feeds.anp-nieuws.example",
  "wire.reuters-partner.example",
  "syndication.afp-partner.example",
]);

export default factories.createCoreController(
  "api::syndication-feed.syndication-feed",
  ({ strapi }) => ({
    /**
     * POST /syndication-feeds/mirror
     *
     * Body: { data: { url } }
     */
    async preview(ctx) {
      const membership = await resolveMembership(ctx);

      if (!membership || !isEditorialStaff(membership)) {
        return ctx.forbidden("Editorial staff only");
      }

      const { url } = ctx.request.body?.data ?? {};

      if (typeof url !== "string" || !url.length) {
        return ctx.badRequest("A mirror url is required");
      }

      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        return ctx.badRequest("That is not a url");
      }

      if (parsed.protocol !== "https:") {
        return ctx.badRequest("Mirrors are https only");
      }

      if (!PARTNER_HOSTS.has(parsed.hostname)) {
        strapi.log.warn(
          `mirror preview refused for ${parsed.hostname} (${membership.userDocumentId})`
        );
        return ctx.forbidden("That host is not one of our syndication partners");
      }

      const response = await fetch(parsed.toString(), {
        method: "GET",
        headers: {
          accept: "application/rss+xml, application/atom+xml, application/xml",
          "user-agent": "Northbeam-Syndication/1.4",
        },
        // A partner redirecting us somewhere else is a partner problem, not a
        // reason to follow it.
        redirect: "manual",
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });

      if (response.status >= 300 && response.status < 400) {
        return ctx.badRequest("The partner redirected the request; check the url");
      }

      const body = await response.text();

      ctx.body = {
        data: {
          status: response.status,
          contentType: response.headers.get("content-type"),
          bytes: body.length,
          sample: body.slice(0, PREVIEW_BYTES),
        },
      };
    },
  })
);
