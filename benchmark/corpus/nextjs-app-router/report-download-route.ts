import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { and, eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { reportExports } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { recordDownload } from "@/lib/audit";

const EXPORT_ROOT = process.env.EXPORT_ROOT ?? "/var/lib/myrqen/exports";

const CONTENT_TYPES: Record<string, string> = {
  ".csv": "text/csv",
  ".pdf": "application/pdf",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};

export async function GET(request: Request) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const exportId = new URL(request.url).searchParams.get("id");
  if (!exportId) {
    return NextResponse.json({ error: "An export id is required" }, { status: 400 });
  }

  const record = await db.query.reportExports.findFirst({
    where: and(
      eq(reportExports.id, exportId),
      eq(reportExports.organizationId, session.organizationId),
    ),
    columns: { id: true, fileName: true, downloadName: true },
  });

  if (!record) {
    return NextResponse.json({ error: "Export not found" }, { status: 404 });
  }

  const organizationDir = path.join(EXPORT_ROOT, session.organizationId);
  const filePath = path.join(organizationDir, path.basename(record.fileName));

  if (!filePath.startsWith(organizationDir + path.sep)) {
    return NextResponse.json({ error: "Export not found" }, { status: 404 });
  }

  try {
    const info = await stat(filePath);
    if (!info.isFile()) {
      return NextResponse.json({ error: "Export not found" }, { status: 404 });
    }
  } catch {
    return NextResponse.json({ error: "Export not found" }, { status: 404 });
  }

  const body = await readFile(filePath);
  await recordDownload(session.userId, record.id);

  return new NextResponse(body, {
    status: 200,
    headers: {
      "content-type": CONTENT_TYPES[path.extname(record.fileName)] ?? "application/octet-stream",
      "content-disposition": `attachment; filename="${record.downloadName}"`,
      "cache-control": "private, no-store",
    },
  });
}
