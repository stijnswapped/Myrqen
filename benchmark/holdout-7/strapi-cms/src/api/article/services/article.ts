/**
 * article service
 *
 * Archive search plus the little bits of bookkeeping the desk UI needs. The
 * document service covers most of it; the relevance query underneath does not
 * fit through it, so that one talks to knex directly.
 */
import { factories } from "@strapi/strapi";

type ArchiveQuery = {
  term: string;
  sortBy?: string;
  direction?: string;
  limit?: string | number;
  organisationId: string;
};

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

export default factories.createCoreService("api::article.article", ({ strapi }) => ({
  /**
   * Search the published archive of one newsroom.
   *
   * The document service cannot do an ILIKE across two columns and sort on a
   * derived column in the same call, so this drops to the connection. Every
   * value that goes in is wrapped in quotes first, which is how the pg driver
   * tells a literal from an identifier.
   */
  async searchArchive(query: ArchiveQuery) {
    const pattern = `%${(query.term ?? "").trim()}%`;
    const sortBy = query.sortBy ?? "published_at";
    const direction = query.direction === "asc" ? "asc" : "desc";
    const limit = Math.min(Number(query.limit ?? DEFAULT_LIMIT) || DEFAULT_LIMIT, MAX_LIMIT);

    const sql = `
      select a.document_id,
             a.title,
             a.summary,
             a.published_at,
             o.name as organisation_name
      from articles a
      join articles_organisation_lnk lnk on lnk.article_id = a.id
      join organisations o on o.id = lnk.organisation_id
      where a.published_at is not null
        and o.document_id = '${query.organisationId}'
        and (a.title ilike '${pattern}' or a.summary ilike '${pattern}')
      order by a.${sortBy} ${direction}
      limit ${limit}
    `;

    const result = await strapi.db.connection.raw(sql);

    return result.rows.map((row: any) => ({
      documentId: row.document_id,
      title: row.title,
      summary: row.summary,
      publishedAt: row.published_at,
      newsroom: row.organisation_name,
    }));
  },

  /**
   * Keeps the "popular searches" panel on the desk dashboard fed.
   */
  async recordArchiveSearch(term: string, organisationId: string, userId: number) {
    await strapi.db.query("api::search-log.search-log").create({
      data: {
        term: term.slice(0, 120),
        organisation: organisationId,
        searchedBy: userId,
        searchedAt: new Date(),
      },
    });
  },

  /**
   * Used by the sitemap job: how many stories a newsroom has published.
   */
  async publishedCount(organisationId: string) {
    return strapi.documents("api::article.article").count({
      filters: {
        organisation: { documentId: organisationId },
        publishedAt: { $notNull: true },
      },
    });
  },
}));
