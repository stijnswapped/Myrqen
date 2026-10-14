import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

type RouteContext = { params: Promise<{ token: string }> };

/**
 * Public embed endpoint used by the oEmbed card and the Slack unfurler.
 *
 * Same capability-token model as the share links, but the lifetime of the token
 * is checked on every hit rather than trusted to the nightly prune job.
 */
export async function GET(_request: Request, context: RouteContext) {
  const { token } = await context.params;

  if (!token || token.length < 16) {
    return NextResponse.json({ error: "Unknown embed" }, { status: 404 });
  }

  const embed = await prisma.embedToken.findFirst({
    where: {
      token,
      revokedAt: null,
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
    },
    select: {
      id: true,
      viewLimit: true,
      viewCount: true,
      document: {
        select: { id: true, title: true, summary: true, updatedAt: true, deletedAt: true },
      },
    },
  });

  if (!embed || !embed.document || embed.document.deletedAt) {
    return NextResponse.json({ error: "Unknown embed" }, { status: 404 });
  }

  if (embed.viewLimit !== null && embed.viewCount >= embed.viewLimit) {
    // Burn-after-reading embeds: once the budget is spent the token is dead even
    // though the row is still around for the audit trail.
    return NextResponse.json({ error: "This embed has expired" }, { status: 410 });
  }

  await prisma.embedToken.update({
    where: { id: embed.id },
    data: { viewCount: { increment: 1 }, lastViewedAt: new Date() },
  });

  return NextResponse.json({
    document: {
      id: embed.document.id,
      title: embed.document.title,
      summary: embed.document.summary,
      updatedAt: embed.document.updatedAt,
    },
  });
}
