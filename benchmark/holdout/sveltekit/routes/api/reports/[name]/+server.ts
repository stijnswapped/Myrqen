import { createReadStream } from "node:fs";
import { stat, unlink } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { error, json, type RequestHandler } from "@sveltejs/kit";
import { db } from "$lib/server/db";
import { REPORT_ROOT } from "$lib/server/storage";

const MAX_STREAM_BYTES = 200 * 1024 * 1024;
const REPORT_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.csv$/;

export const GET: RequestHandler = async ({ params, url, locals }) => {
  const session = locals.session;
  if (!session) throw error(401, "sign in required");

  const tenantRoot = join(REPORT_ROOT, session.tenantId);
  const requested = url.searchParams.get("file") ?? params.name;
  if (!requested) throw error(400, "no report requested");
  if (!REPORT_NAME.test(requested)) throw error(400, "not a report name");

  const target = join(tenantRoot, requested);
  const info = await stat(target).catch(() => null);
  if (!info?.isFile()) throw error(404, "report not found");
  if (info.size > MAX_STREAM_BYTES) throw error(413, "report too large to stream");

  return new Response(Readable.toWeb(createReadStream(target)) as ReadableStream, {
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-length": String(info.size),
      "content-disposition": `attachment; filename="${requested.replace(/[^\w.-]/g, "_")}"`,
      "cache-control": "private, no-store"
    }
  });
};

export const DELETE: RequestHandler = async ({ params, locals }) => {
  const session = locals.session;
  if (!session) throw error(401, "sign in required");

  const record = await db.report.findFirst({
    where: { id: params.name, tenantId: session.tenantId }
  });
  if (!record) throw error(404, "report not found");

  await unlink(join(REPORT_ROOT, session.tenantId, record.storageKey));
  await db.report.update({ where: { id: record.id }, data: { deletedAt: new Date() } });
  return json({ deleted: record.id });
};
