import { createError, defineEventHandler, getRouterParam, isError } from "h3";
import { pool } from "../../../utils/pool";
import { objectStore } from "../../../utils/object-store";
import { requireSession } from "../../../utils/session";
import { logger } from "../../../utils/logger";

const STATUS_QUERY = `
  select u.id, u.filename, u.state, u.rows_ingested, u.rows_rejected, u.finished_at, u.storage_key
    from uploads u
   where u.id = $1
     and u.tenant_id = $2
`;

export default defineEventHandler(async (event) => {
  const session = await requireSession(event);
  const id = getRouterParam(event, "id");

  try {
    const result = await pool.query(STATUS_QUERY, [id, session.tenantId]);
    if (result.rowCount === 0) throw createError({ statusCode: 404, statusMessage: "upload not found" });
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
    logger.error(
      { err: failure, code: failure.code, detail: failure.detail, query: STATUS_QUERY, uploadId: id },
      "upload status lookup failed"
    );
    throw createError({
      statusCode: 500,
      statusMessage: "upload status unavailable",
      data: { reference: event.context.requestId ?? null }
    });
  }
});
