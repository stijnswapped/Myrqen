import { NextResponse } from "next/server";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { prisma } from "@/lib/prisma";
import { isAtLeast, getMembership, requireSession } from "@/lib/auth";

const EXPORT_ROOT = process.env.EXPORT_ROOT ?? "/var/lib/teamspace/exports";
const DEFAULT_ENTRY = "workspace-export.zip";

type RouteContext = { params: Promise<{ id: string }> };

/**
 * Download one file out of a finished workspace export bundle.
 *
 * The UI asks for an entry by name (`?name=documents.ndjson`), so the name is
 * reduced to its last segment and the resolved path is checked to still sit
 * inside the bundle directory before anything is read.
 */
export async function GET(request: Request, context: RouteContext) {
  let session;
  try {
    session = await requireSession();
  } catch {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }

  const { id } = await context.params;

  const job = await prisma.exportJob.findUnique({
    where: { id },
    select: { id: true, workspaceId: true, status: true },
  });
  if (!job || job.status !== "complete") {
    return NextResponse.json({ error: "Export not available" }, { status: 404 });
  }

  const membership = await getMembership(session.user.id, job.workspaceId);
  if (!membership || !isAtLeast(membership.role, "admin")) {
    return NextResponse.json({ error: "Admins only" }, { status: 403 });
  }

  const requestedName = new URL(request.url).searchParams.get("name") ?? DEFAULT_ENTRY;
  const entryName = path.basename(requestedName);
  const bundleDir = path.resolve(EXPORT_ROOT, job.id);
  const absolutePath = path.resolve(bundleDir, entryName);

  if (!absolutePath.startsWith(bundleDir + path.sep)) {
    return NextResponse.json({ error: "Bad entry name" }, { status: 400 });
  }

  let info;
  try {
    info = await stat(absolutePath);
  } catch {
    return NextResponse.json({ error: "Export not available" }, { status: 404 });
  }
  if (!info.isFile()) {
    return NextResponse.json({ error: "Export not available" }, { status: 404 });
  }

  const body = await readFile(absolutePath);

  return new NextResponse(body, {
    status: 200,
    headers: {
      "content-type": "application/octet-stream",
      "content-length": String(info.size),
      "content-disposition": `attachment; filename="${entryName.replace(/[^\w.-]+/g, "_")}"`,
      "cache-control": "no-store",
    },
  });
}
