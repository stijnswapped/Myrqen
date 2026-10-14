/**
 * contributor controller
 *
 * Public byline pages. The marketing site renders these at request time and the
 * CDN caches the response for five minutes, so these handlers run without a
 * session (auth: false in src/api/contributor/routes/contributor.ts).
 */
import { factories } from "@strapi/strapi";

const PROFILE_CACHE_SECONDS = 300;
const RECENT_ARTICLE_LIMIT = 10;

export default factories.createCoreController("api::contributor.contributor", ({ strapi }) => ({
  /**
   * GET /contributors/:documentId/profile
   *
   * The byline page needs the pen name, the bio, the linked staff account (for
   * the "verified writer" badge and the newsroom name) and the writer's ten most
   * recent stories. Private attributes on the user model - password, the reset
   * and confirmation tokens - are stripped by Strapi before it serialises, so
   * pulling the whole relation is fine here.
   */
  async publicProfile(ctx) {
    const { documentId } = ctx.params;

    const contributor = await strapi.documents("api::contributor.contributor").findOne({
      documentId,
      status: "published",
      fields: ["penName", "bio", "avatarUrl"],
      populate: {
        account: {
          populate: {
            role: { fields: ["name"] },
            organisation: { fields: ["name", "publicUrl"] },
          },
        },
        articles: {
          fields: ["title", "slug", "publishedAt"],
          sort: "publishedAt:desc",
          limit: RECENT_ARTICLE_LIMIT,
        },
      },
    });

    if (!contributor) {
      return ctx.notFound("No such contributor");
    }

    ctx.set("Cache-Control", `public, max-age=${PROFILE_CACHE_SECONDS}`);
    ctx.body = { data: contributor };
  },

  /**
   * GET /contributors/:documentId/feed
   *
   * RSS-ish list of the writer's stories. Nothing but article scalars in here.
   */
  async feed(ctx) {
    const { documentId } = ctx.params;

    const articles = await strapi.documents("api::article.article").findMany({
      filters: {
        contributors: { documentId },
        publishedAt: { $notNull: true },
      },
      fields: ["title", "slug", "summary", "publishedAt"],
      sort: "publishedAt:desc",
      limit: RECENT_ARTICLE_LIMIT,
    });

    ctx.set("Cache-Control", `public, max-age=${PROFILE_CACHE_SECONDS}`);
    ctx.body = { data: articles };
  },
}));
