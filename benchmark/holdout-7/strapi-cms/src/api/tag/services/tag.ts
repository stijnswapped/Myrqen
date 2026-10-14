/**
 * tag service
 *
 * Autocomplete for the tag picker in the desk editor. Same shape as the archive
 * search: a grouped count that the document service cannot express, so it goes
 * through the connection.
 */
import { factories } from "@strapi/strapi";

type SuggestQuery = {
  term: string;
  sortBy?: string;
  direction?: string;
  limit?: string | number;
  organisationId: string;
};

/**
 * The sort comes off a dropdown, but the dropdown value still has to be mapped
 * to a column here - the column name is part of the statement, not a value, so
 * a binding cannot carry it.
 */
const SORTABLE_COLUMNS: Record<string, string> = {
  name: "t.name",
  usage: "usage_count",
  recent: "last_used_at",
};

const DEFAULT_LIMIT = 15;
const MAX_LIMIT = 50;

export default factories.createCoreService("api::tag.tag", ({ strapi }) => ({
  async suggest(query: SuggestQuery) {
    const pattern = `%${(query.term ?? "").trim()}%`;
    const column = SORTABLE_COLUMNS[query.sortBy ?? "usage"] ?? SORTABLE_COLUMNS.usage;
    const direction = query.direction === "asc" ? "asc" : "desc";
    const limit = Math.min(Number(query.limit ?? DEFAULT_LIMIT) || DEFAULT_LIMIT, MAX_LIMIT);

    const sql = `
      select t.document_id,
             t.name,
             count(lnk.article_id)::int as usage_count,
             max(a.published_at) as last_used_at
      from tags t
      join tags_organisation_lnk org_lnk on org_lnk.tag_id = t.id
      join organisations o on o.id = org_lnk.organisation_id
      left join articles_tags_lnk lnk on lnk.tag_id = t.id
      left join articles a on a.id = lnk.article_id
      where o.document_id = ?
        and t.name ilike ?
      group by t.document_id, t.name
      order by ${column} ${direction}
      limit ?
    `;

    const result = await strapi.db.connection.raw(sql, [
      query.organisationId,
      pattern,
      limit,
    ]);

    return result.rows.map((row: any) => ({
      documentId: row.document_id,
      name: row.name,
      usageCount: row.usage_count,
      lastUsedAt: row.last_used_at,
    }));
  },

  /**
   * Merges one tag into another and repoints the articles. Both ids are checked
   * against the newsroom before we get here.
   */
  async merge(fromDocumentId: string, intoDocumentId: string, organisationId: string) {
    const [from, into] = await Promise.all(
      [fromDocumentId, intoDocumentId].map((documentId) =>
        strapi.documents("api::tag.tag").findMany({
          filters: { documentId, organisation: { documentId: organisationId } },
          fields: ["name"],
          limit: 1,
        })
      )
    );

    if (!from.length || !into.length) {
      throw new Error("Both tags must belong to the same newsroom");
    }

    await strapi.db.connection.raw(
      `update articles_tags_lnk set tag_id = (select id from tags where document_id = ?)
       where tag_id = (select id from tags where document_id = ?)`,
      [intoDocumentId, fromDocumentId]
    );

    await strapi.documents("api::tag.tag").delete({ documentId: fromDocumentId });

    return { merged: from[0].name, into: into[0].name };
  },
}));
