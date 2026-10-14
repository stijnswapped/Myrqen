import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

type RouteContext = { params: Promise<{ token: string }> };

/**
 * Public read-only view behind a "anyone with the link" share.
 *
 * No session here on purpose: the token is 32 bytes of `crypto.randomBytes`, so
 * holding it is proof enough. Links that the owner turns off or that run past
 * their date are swept out of the table by the nightly `prune-share-links` job.
 */
export async function GET(_request: Request, context: RouteContext) {
  const { token } = await context.params;

  if (!token || token.length < 16) {
    return NextResponse.json({ error: "Unknown link" }, { status: 404 });
  }

  const link = await prisma.shareLink.findUnique({
    where: { token },
    select: {
      id: true,
      permission: true,
      expiresAt: true,
      revokedAt: true,
      document: {
        select: {
          id: true,
          title: true,
          body: true,
          updatedAt: true,
          workspace: { select: { name: true } },
        },
      },
    },
  });

  if (!link || !link.document) {
    return NextResponse.json({ error: "Unknown link" }, { status: 404 });
  }

  await prisma.shareLink.update({
    where: { id: link.id },
    data: { viewCount: { increment: 1 }, lastViewedAt: new Date() },
  });

  return NextResponse.json({
    permission: link.permission,
    workspaceName: link.document.workspace.name,
    document: {
      id: link.document.id,
      title: link.document.title,
      body: link.document.body,
      updatedAt: link.document.updatedAt,
    },
  });
}
