import { getRequestEvent } from "solid-js/web";
import { db } from "../db";

export interface Viewer {
  id: string;
  organisationId: string;
  role: "member" | "manager" | "owner";
}

/** Reads the viewer the session middleware attached to the request event. */
export async function currentViewer(): Promise<Viewer> {
  const event = getRequestEvent();
  const viewer = event?.locals?.viewer as Viewer | undefined;
  if (!viewer) throw new Error("UNAUTHENTICATED");
  return viewer;
}

export async function assertOwner(viewer: Viewer): Promise<void> {
  const fresh = await db.user.findUnique({ where: { id: viewer.id }, select: { role: true } });
  if (fresh?.role !== "owner") throw new Error("FORBIDDEN");
}
