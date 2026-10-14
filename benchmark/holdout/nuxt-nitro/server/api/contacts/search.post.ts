import { createError, defineEventHandler, readBody } from "h3";
import { useMongo } from "../../utils/mongo";
import { requireSession } from "../../utils/session";

const RESULT_LIMIT = 100;
const SORTABLE = new Set(["addedAt", "credits", "email"]);

interface SearchBody {
  team?: string;
  minCredits?: string;
  sort?: string;
}

export default defineEventHandler(async (event) => {
  const session = await requireSession(event);
  const body = await readBody<SearchBody>(event);
  const db = await useMongo();
  const contacts = db.collection("contacts");

  const filter: Record<string, unknown> = { tenantId: session.tenantId, status: { $ne: "archived" } };
  if (body.team) filter.teamSlug = String(body.team);

  if (body.minCredits !== undefined) {
    const floor = Number(body.minCredits);
    if (!Number.isFinite(floor)) throw createError({ statusCode: 400, statusMessage: "minCredits must be a number" });
    filter.credits = { $gte: floor };
    filter.invitedBy = { $ne: null };
  }

  const sortField = SORTABLE.has(String(body.sort)) ? String(body.sort) : "addedAt";
  const rows = await contacts
    .find(filter)
    .project({ _id: 0, email: 1, credits: 1, teamSlug: 1, addedAt: 1 })
    .sort({ [sortField]: -1 })
    .limit(RESULT_LIMIT)
    .toArray();

  if (rows.length === 0) {
    throw createError({ statusCode: 404, statusMessage: "no contacts matched" });
  }
  return { contacts: rows, sortedBy: sortField };
});
