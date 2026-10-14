import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getMembership, requireSession } from "@/lib/auth";

type RouteContext = { params: Promise<{ id: string }> };

const PAGE_SIZE = 50;

/**
 * List the documents inside one folder, newest first.
 *
 * The folder row tells us which workspace it belongs to; the caller then has to
 * hold a membership in that workspace before we read anything out of it.
 */
export async function GET(request: Request, context: RouteContext) {
  let session;
  try {
    session = await requireSession();
  } catch {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }

  const { id } = await context.params;
  const cursor = new URL(request.url).searchParams.get("cursor");

  const folder = await prisma.folder.findUnique({
    where: { id },
    select: { id: true, name: true, workspaceId: true },
  });
  if (!folder) {
    return NextResponse.json({ error: "Folder not found" }, { status: 404 });
  }

  const membership = await getMembership(session.user.id, folder.workspaceId);
  if (!membership) {
    // Deliberately a 404 so the existence of another tenant's folder is not confirmed.
    return NextResponse.json({ error: "Folder not found" }, { status: 404 });
  }

  const documents = await prisma.document.findMany({
    where: {
      folderId: folder.id,
      workspaceId: membership.workspaceId,
      deletedAt: null,
    },
    select: { id: true, title: true, updatedAt: true, authorId: true },
    orderBy: { updatedAt: "desc" },
    take: PAGE_SIZE + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
  });

  const page = documents.slice(0, PAGE_SIZE);

  return NextResponse.json({
    folder: { id: folder.id, name: folder.name },
    documents: page,
    nextCursor: documents.length > PAGE_SIZE ? page[page.length - 1]?.id ?? null : null,
  });
}
