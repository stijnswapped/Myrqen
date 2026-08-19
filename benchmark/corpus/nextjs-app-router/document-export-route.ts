import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

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

  const name = new URL(request.url).searchParams.get("name");
  if (!name) {
    return NextResponse.json({ error: "A file name is required" }, { status: 400 });
  }

  const filePath = path.join(EXPORT_ROOT, session.organizationId, name);

  try {
    const info = await stat(filePath);
    if (!info.isFile()) {
      return NextResponse.json({ error: "Export not found" }, { status: 404 });
    }
  } catch {
    return NextResponse.json({ error: "Export not found" }, { status: 404 });
  }

  const body = await readFile(filePath);
  await recordDownload(session.userId, name);

  return new NextResponse(body, {
    status: 200,
    headers: {
      "content-type": CONTENT_TYPES[path.extname(name)] ?? "application/octet-stream",
      "content-disposition": `attachment; filename="${path.basename(name)}"`,
      "cache-control": "private, no-store",
    },
  });
}
