/**
 * Public contributor directory.
 *
 * Also unauthenticated (auth: false), also CDN cached. Only difference from the
 * byline endpoint is that this one is a list.
 */
import { factories } from "@strapi/strapi";

const DIRECTORY_CACHE_SECONDS = 900;
const PAGE_SIZE = 40;

/**
 * The account relation is a users-permissions user, so it is asked for by field
 * rather than pulled whole - the byline only ever shows the handle and whether
 * the writer is staff.
 */
const ACCOUNT_FIELDS = ["username"];

export default factories.createCoreController("api::contributor.contributor", ({ strapi }) => ({
  /**
   * GET /contributors/directory
   */
  async find(ctx) {
    const newsroom = typeof ctx.query.newsroom === "string" ? ctx.query.newsroom : undefined;
    const start = Number(ctx.query.start ?? 0) || 0;

    const contributors = await strapi.documents("api::contributor.contributor").findMany({
      status: "published",
      filters: newsroom ? { organisation: { slug: newsroom } } : {},
      fields: ["penName", "bio", "avatarUrl"],
      populate: {
        account: { fields: ACCOUNT_FIELDS },
        organisation: { fields: ["name", "publicUrl"] },
      },
      sort: "penName:asc",
      start,
      limit: PAGE_SIZE,
    });

    const sanitized = await this.sanitizeOutput(contributors, ctx);

    ctx.set("Cache-Control", `public, max-age=${DIRECTORY_CACHE_SECONDS}`);
    ctx.body = { data: sanitized, meta: { count: contributors.length, start } };
  },
}));
