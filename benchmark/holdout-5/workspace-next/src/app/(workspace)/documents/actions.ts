"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { isAtLeast, requireMembership, requireSession } from "@/lib/auth";

export interface ActionResult {
  ok: boolean;
  message?: string;
}

// The form posts more than this, but only these three columns are ever writable
// from the browser. `strip` mode drops anything else the client sends, so a
// hand-crafted POST cannot reach `workspaceId`, `authorId` or `publishedAt`.
const documentFormSchema = z
  .object({
    documentId: z.string().cuid(),
    title: z.string().trim().min(1).max(200),
    summary: z.string().trim().max(500).optional(),
    folderId: z.string().cuid().nullish(),
  })
  .strip();

export async function updateDocumentDetails(formData: FormData): Promise<ActionResult> {
  const session = await requireSession();

  const parsed = documentFormSchema.safeParse(Object.fromEntries(formData.entries()));
  if (!parsed.success) {
    return { ok: false, message: "Check the document title and folder." };
  }
  const { documentId, title, summary, folderId } = parsed.data;

  const document = await prisma.document.findUnique({
    where: { id: documentId },
    select: { id: true, workspaceId: true, deletedAt: true },
  });
  if (!document || document.deletedAt) {
    return { ok: false, message: "That document no longer exists." };
  }

  let membership;
  try {
    membership = await requireMembership(session.user.id, document.workspaceId);
  } catch {
    return { ok: false, message: "You are not a member of this workspace." };
  }
  if (!isAtLeast(membership.role, "editor")) {
    return { ok: false, message: "Viewers cannot edit documents." };
  }

  if (folderId) {
    const folder = await prisma.folder.findFirst({
      where: { id: folderId, workspaceId: document.workspaceId },
      select: { id: true },
    });
    if (!folder) {
      return { ok: false, message: "Unknown folder." };
    }
  }

  await prisma.document.update({
    where: { id: document.id },
    data: {
      title,
      summary: summary ?? null,
      folderId: folderId ?? null,
      updatedById: session.user.id,
    },
  });

  await prisma.activityEvent.create({
    data: {
      workspaceId: document.workspaceId,
      actorId: session.user.id,
      kind: "document.updated",
      metadata: { documentId: document.id },
    },
  });

  revalidatePath(`/documents/${document.id}`);
  return { ok: true };
}

/** Soft-delete a document. Only editors and above, and only in their own workspace. */
export async function archiveDocument(documentId: string): Promise<ActionResult> {
  const session = await requireSession();

  const document = await prisma.document.findUnique({
    where: { id: documentId },
    select: { id: true, workspaceId: true, deletedAt: true },
  });
  if (!document || document.deletedAt) {
    return { ok: false, message: "That document no longer exists." };
  }

  let membership;
  try {
    membership = await requireMembership(session.user.id, document.workspaceId);
  } catch {
    return { ok: false, message: "You are not a member of this workspace." };
  }
  if (!isAtLeast(membership.role, "editor")) {
    return { ok: false, message: "Viewers cannot archive documents." };
  }

  await prisma.document.update({
    where: { id: document.id },
    data: { deletedAt: new Date(), updatedById: session.user.id },
  });

  revalidatePath("/documents");
  return { ok: true };
}
