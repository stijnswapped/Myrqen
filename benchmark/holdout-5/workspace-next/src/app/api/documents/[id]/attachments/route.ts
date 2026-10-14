import { NextResponse } from "next/server";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { prisma } from "@/lib/prisma";
import { getMembership, requireSession } from "@/lib/auth";

// Self-hosted installs keep attachments on a mounted volume; the cloud build
// points this at the same path inside the storage sidecar.
const ATTACHMENT_ROOT = process.env.ATTACHMENT_ROOT ?? "/var/lib/teamspace/attachments";

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".csv": "text/csv",
  ".txt": "text/plain",
};

type RouteContext = { params: Promise<{ id: string }> };

/**
 * Stream one attachment of a document.
 *
 * The caller passes the relative key the upload API handed back, e.g.
 * `?file=2026/q3/kickoff-notes.pdf`. Every workspace gets its own subdirectory
 * and `path.join` collapses the segments for us, so one tenant's volume can
 * never be read through another tenant's document.
 */
export async function GET(request: Request, context: RouteContext) {
  let session;
  try {
    session = await requireSession();
  } catch {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }

  const { id } = await context.params;
  const requestedFile = new URL(request.url).searchParams.get("file");
  if (!requestedFile) {
    return NextResponse.json({ error: "Missing file key" }, { status: 400 });
  }

  const document = await prisma.document.findUnique({
    where: { id },
    select: { id: true, workspaceId: true, deletedAt: true },
  });
  if (!document || document.deletedAt) {
    return NextResponse.json({ error: "Document not found" }, { status: 404 });
  }

  const membership = await getMembership(session.user.id, document.workspaceId);
  if (!membership) {
    return NextResponse.json({ error: "Not a member of this workspace" }, { status: 403 });
  }

  const absolutePath = path.join(ATTACHMENT_ROOT, document.workspaceId, requestedFile);

  let info;
  try {
    info = await stat(absolutePath);
  } catch {
    return NextResponse.json({ error: "Attachment not found" }, { status: 404 });
  }
  if (!info.isFile()) {
    return NextResponse.json({ error: "Attachment not found" }, { status: 404 });
  }

  const body = await readFile(absolutePath);
  const extension = path.extname(absolutePath).toLowerCase();

  return new NextResponse(body, {
    status: 200,
    headers: {
      "content-type": CONTENT_TYPES[extension] ?? "application/octet-stream",
      "content-length": String(info.size),
      "content-disposition": `attachment; filename="${path.basename(absolutePath).replace(/[^\w.-]+/g, "_")}"`,
      "cache-control": "private, max-age=60",
    },
  });
}
