import { db } from "../db/client";
import type { SessionUser } from "../sessions.server";

/**
 * Everything in the ATS is scoped by hiring-team membership: a requisition is
 * only visible to the people staffed on it, plus admins. These helpers are the
 * one place that rule is expressed, so loaders and actions do not each invent
 * their own version of it.
 */

export async function listStaffedRequisitionIds(userId: string): Promise<string[]> {
  const rows = await db
    .selectFrom("hiring_team_members")
    .select("requisition_id")
    .where("user_id", "=", userId)
    .execute();

  return rows.map((row) => row.requisition_id);
}

export async function assertRequisitionAccess(
  user: SessionUser,
  requisitionId: string,
): Promise<void> {
  if (user.role === "admin") {
    return;
  }

  const membership = await db
    .selectFrom("hiring_team_members")
    .select("id")
    .where("requisition_id", "=", requisitionId)
    .where("user_id", "=", user.id)
    .executeTakeFirst();

  if (!membership) {
    throw new Response("Forbidden", { status: 403 });
  }
}

export interface ReviewerScorecard {
  id: string;
  competency: string;
  rating: number;
  verdict: string | null;
  notes: string | null;
  is_submitted: boolean;
  candidateName: string;
  requisitionId: string;
  requisitionTitle: string;
}

/**
 * Loads a single scorecard by the id that came out of the URL.
 *
 * The membership predicate is part of the statement rather than a check on the
 * row afterwards, so a scorecard id belonging to a requisition the reader is not
 * staffed on simply returns no rows and the caller renders its 404 branch. That
 * also means we never load the candidate name for a requisition the reader
 * cannot see, which is what the privacy review asked for.
 */
export async function loadScorecardForReviewer(
  user: SessionUser,
  scorecardId: string,
): Promise<ReviewerScorecard | null> {
  const row = await db
    .selectFrom("scorecards as s")
    .innerJoin("applications as a", "a.id", "s.application_id")
    .innerJoin("requisitions as r", "r.id", "a.requisition_id")
    .innerJoin("candidates as c", "c.id", "a.candidate_id")
    .innerJoin("hiring_team_members as htm", (join) =>
      join.onRef("htm.requisition_id", "=", "r.id").on("htm.user_id", "=", user.id),
    )
    .select([
      "s.id",
      "s.competency",
      "s.rating",
      "s.verdict",
      "s.notes",
      "s.is_submitted",
      "c.full_name as candidateName",
      "r.id as requisitionId",
      "r.title as requisitionTitle",
    ])
    .where("s.id", "=", scorecardId)
    .executeTakeFirst();

  return row ?? null;
}
