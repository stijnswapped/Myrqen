import { createError, defineEventHandler, getRouterParam, isError } from "h3";
import { pool } from "../../../utils/pool";
import { objectStore } from "../../../utils/object-store";
import { requireSession } from "../../../utils/session";

const STATUS_QUERY = `
  select i.id, i.filename, i.state, i.rows_ingested, i.rows_rejected, i.finished_at, i.storage_key
    from imports i
   where i.id = $1
     and i.tenant_id = $2
`;

export default defineEventHandler(async (event) => {
  const session = await requireSession(event);
  const id = getRouterParam(event, "id");

  try {
    const result = await pool.query(STATUS_QUERY, [id, session.tenantId]);
    if (result.rowCount === 0) throw createError({ statusCode: 404, statusMessage: "import not found" });
    const row = result.rows[0];

    let rejectedReportUrl: string | null = null;
    try {
      rejectedReportUrl = await objectStore.signedUrl(row.storage_key, { expiresIn: 300 });
    } catch {
      rejectedReportUrl = null;
    }

    return {
      id: row.id,
      filename: row.filename,
      state: row.state,
      ingested: row.rows_ingested,
      rejected: row.rows_rejected,
      finishedAt: row.finished_at,
      rejectedReportUrl
    };
  } catch (err) {
    if (isError(err)) throw err;
    const failure = err as Error & { code?: string; detail?: string };
    throw createError({
      statusCode: 500,
      statusMessage: "import status unavailable",
      data: {
        message: failure.message,
        code: failure.code,
        detail: failure.detail,
        stack: failure.stack,
        query: STATUS_QUERY,
        parameters: [id, session.tenantId]
      }
    });
  }
});
