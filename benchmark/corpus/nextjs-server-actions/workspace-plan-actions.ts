"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { and, eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { memberships, workspaces } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { syncSubscription } from "@/lib/billing";
import { writeAuditEntry } from "@/lib/audit";

const PLANS = ["starter", "team", "enterprise"] as const;
type Plan = (typeof PLANS)[number];

export async function changeWorkspacePlan(formData: FormData) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const workspaceId = String(formData.get("workspaceId") ?? "");
  const plan = String(formData.get("plan") ?? "") as Plan;
  const seatLimit = Number(formData.get("seatLimit") ?? 0);

  if (!PLANS.includes(plan) || !Number.isInteger(seatLimit) || seatLimit < 1) {
    return { ok: false as const, message: "Choose a plan and a seat count" };
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

  const [updated] = await db
    .update(workspaces)
    .set({ plan, seatLimit, updatedAt: new Date() })
    .where(eq(workspaces.id, workspaceId))
    .returning({ id: workspaces.id, name: workspaces.name, plan: workspaces.plan });

  await syncSubscription(updated.id, { plan, seatLimit });
  await writeAuditEntry(session.userId, "workspace.plan.changed", { workspaceId, plan, seatLimit });

  revalidatePath("/settings/plan");
  return { ok: true as const, workspace: updated };
}
