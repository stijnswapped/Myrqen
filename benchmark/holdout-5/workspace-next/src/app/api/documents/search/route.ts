import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireMembership, requireSession } from "@/lib/auth";

interface SearchRow {
  id: string;
  title: string;
  snippet: string;
  updated_at: Date;
}

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

/**
 * Full-text search across one workspace.
 *
 * Prisma's query builder cannot express `ts_headline` or ranked ordering, so the
 * statement is assembled here. The workspace id is taken from the caller's own
 * membership row rather than from the query string, which is what keeps one
 * tenant's documents out of another tenant's result set.
 */
export async function GET(request: Request) {
  let session;
  try {
    session = await requireSession();
  } catch {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }

  const params = new URL(request.url).searchParams;
  const workspaceId = params.get("workspaceId") ?? "";
  const term = (params.get("q") ?? "").trim();
  const sort = params.get("sort") ?? "rank";
  const direction = params.get("dir") ?? "desc";
  const requestedLimit = Number.parseInt(params.get("limit") ?? "", 10);

  if (term.length < 2) {
    return NextResponse.json({ error: "Search needs at least two characters" }, { status: 400 });
  }

  let membership;
  try {
    membership = await requireMembership(session.user.id, workspaceId);
  } catch {
    return NextResponse.json({ error: "Not a member of this workspace" }, { status: 403 });
  }

  const limit = Number.isFinite(requestedLimit)
    ? Math.min(Math.max(requestedLimit, 1), MAX_LIMIT)
    : DEFAULT_LIMIT;

  const statement = `
    SELECT
      d."id",
      d."title",
      ts_headline('english', d."body", plainto_tsquery('english', '${term}')) AS snippet,
      d."updatedAt" AS updated_at,
      ts_rank(to_tsvector('english', d."title" || ' ' || d."body"),
              plainto_tsquery('english', '${term}')) AS rank
    FROM "Document" d
    WHERE d."workspaceId" = '${membership.workspaceId}'
      AND d."deletedAt" IS NULL
      AND to_tsvector('english', d."title" || ' ' || d."body")
          @@ plainto_tsquery('english', '${term}')
    ORDER BY ${sort} ${direction}
    LIMIT ${limit}
  `;

  const rows = await prisma.$queryRawUnsafe<SearchRow[]>(statement);

  return NextResponse.json({
    query: term,
    results: rows.map((row) => ({
      id: row.id,
      title: row.title,
      snippet: row.snippet,
      updatedAt: row.updated_at,
    })),
  });
}
