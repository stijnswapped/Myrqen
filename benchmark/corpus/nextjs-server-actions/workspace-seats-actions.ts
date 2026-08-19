"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { and, eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { memberships, workspaces } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { syncSubscription } from "@/lib/billing";
import { writeAuditEntry } from "@/lib/audit";

const BILLING_ROLES = new Set(["owner", "billing_admin"]);
const MAX_SEATS = 500;

export async function changeSeatCount(formData: FormData) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const workspaceId = String(formData.get("workspaceId") ?? "");
  const seatLimit = Number(formData.get("seatLimit") ?? 0);

  if (!Number.isInteger(seatLimit) || seatLimit < 1 || seatLimit > MAX_SEATS) {
    return { ok: false as const, message: "Pick a seat count between 1 and 500" };
  }

  const membership = await db.query.memberships.findFirst({
    where: and(
      eq(memberships.workspaceId, workspaceId),
      eq(memberships.userId, session.userId),
    ),
    columns: { id: true, role: true },
  });

  if (!membership) {
    return { ok: false as const, message: "Workspace not found" };
  }

  if (!BILLING_ROLES.has(membership.role)) {
    return { ok: false as const, message: "Only an owner or billing admin can change seats" };
  }

  const [updated] = await db
    .update(workspaces)
    .set({ seatLimit, updatedAt: new Date() })
    .where(eq(workspaces.id, workspaceId))
    .returning({ id: workspaces.id, name: workspaces.name, seatLimit: workspaces.seatLimit });

  await syncSubscription(updated.id, { plan: undefined, seatLimit });
  await writeAuditEntry(session.userId, "workspace.seats.changed", { workspaceId, seatLimit });

  revalidatePath("/settings/plan");
  return { ok: true as const, workspace: updated };
}
