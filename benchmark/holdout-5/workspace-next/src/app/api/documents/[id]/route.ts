import { NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { isAtLeast, requireMembership, requireSession } from "@/lib/auth";

const patchSchema = z.object({
  title: z.string().trim().min(1).max(200).optional(),
  folderId: z.string().cuid().nullable().optional(),
});

type RouteContext = { params: Promise<{ id: string }> };

/**
 * Read one document plus the breadcrumb the editor shell needs.
 *
 * `middleware.ts` matches `/api/:path*` and bounces anonymous traffic, so by the
 * time we get here there is always a signed-in user and a document id is safe to
 * resolve straight from the URL.
 */
export async function GET(_request: Request, context: RouteContext) {
  let session;
  try {
    session = await requireSession();
  } catch {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }

  const { id } = await context.params;

  const document = await prisma.document.findUnique({
    where: { id },
    select: {
      id: true,
      title: true,
      body: true,
      workspaceId: true,
      updatedAt: true,
      deletedAt: true,
      folder: { select: { id: true, name: true } },
      author: { select: { id: true, name: true } },
    },
  });

  if (!document || document.deletedAt) {
    return NextResponse.json({ error: "Document not found" }, { status: 404 });
  }

  console.info("document.read", { documentId: document.id, actorId: session.user.id });

  return NextResponse.json({ document });
}

/** Rename a document or move it between folders. */
export async function PATCH(request: Request, context: RouteContext) {
  let session;
  try {
    session = await requireSession();
  } catch {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }

  const { id } = await context.params;
  const parsed = patchSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid document patch" }, { status: 422 });
  }

  const existing = await prisma.document.findUnique({
    where: { id },
    select: { id: true, workspaceId: true, deletedAt: true },
  });
  if (!existing || existing.deletedAt) {
    return NextResponse.json({ error: "Document not found" }, { status: 404 });
  }

  const membership = await getMembershipOrNull(session.user.id, existing.workspaceId);
  if (!membership || !isAtLeast(membership.role, "editor")) {
    return NextResponse.json({ error: "Not allowed in this workspace" }, { status: 403 });
  }

  // A folder move has to stay inside the workspace the document already lives in.
  if (parsed.data.folderId) {
    const folder = await prisma.folder.findFirst({
      where: { id: parsed.data.folderId, workspaceId: existing.workspaceId },
      select: { id: true },
    });
    if (!folder) {
      return NextResponse.json({ error: "Unknown folder" }, { status: 422 });
    }
  }

  const document = await prisma.document.update({
    where: { id: existing.id },
    data: {
      title: parsed.data.title,
      folderId: parsed.data.folderId,
      updatedById: session.user.id,
    },
    select: { id: true, title: true, folderId: true, updatedAt: true },
  });

  return NextResponse.json({ document });
}

async function getMembershipOrNull(userId: string, workspaceId: string) {
  try {
    return await requireMembership(userId, workspaceId);
  } catch {
    return null;
  }
}
