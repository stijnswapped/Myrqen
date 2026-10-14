import { createError, defineEventHandler, readBody } from "h3";
import { useMongo } from "../../utils/mongo";
import { requireSession } from "../../utils/session";

const RESULT_LIMIT = 100;
const SORTABLE = new Set(["joinedAt", "credits", "email"]);

interface SearchBody {
  team?: string;
  minCredits?: string;
  sort?: string;
}

export default defineEventHandler(async (event) => {
  const session = await requireSession(event);
  const body = await readBody<SearchBody>(event);
  const db = await useMongo();
  const members = db.collection("members");

  const filter: Record<string, unknown> = { tenantId: session.tenantId, status: { $ne: "archived" } };
  if (body.team) filter.teamSlug = String(body.team);

  if (body.minCredits !== undefined) {
    filter.$where = `this.credits >= ${body.minCredits} && this.invitedBy !== null`;
  }

  const sortField = SORTABLE.has(String(body.sort)) ? String(body.sort) : "joinedAt";
  const rows = await members
    .find(filter)
    .project({ _id: 0, email: 1, credits: 1, teamSlug: 1, joinedAt: 1 })
    .sort({ [sortField]: -1 })
    .limit(RESULT_LIMIT)
    .toArray();

  if (rows.length === 0) {
    throw createError({ statusCode: 404, statusMessage: "no members matched" });
  }
  return { members: rows, sortedBy: sortField };
});
