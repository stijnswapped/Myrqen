import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";
import { requireUser } from "../sessions.server";

const ATTACHMENT_ROOT = process.env.CV_STORAGE_ROOT ?? "/var/lib/ats/attachments";

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".doc": "application/msword",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".txt": "text/plain; charset=utf-8",
};

function contentTypeFor(key: string): string {
  return CONTENT_TYPES[path.extname(key).toLowerCase()] ?? "application/octet-stream";
}

/**
 * Resource route: streams a candidate CV back to a reviewer.
 *
 * There is no default export — the browser hits this URL directly from the
 * attachment list, so React Router treats it as a resource route and returns
 * whatever Response the loader builds.
 */
export async function loader({ params, request }: LoaderFunctionArgs) {
  const user = await requireUser(request);
  const candidateId = params.candidateId;

  if (!candidateId) {
    throw new Response("Not found", { status: 404 });
  }

  const url = new URL(request.url);
  const key = url.searchParams.get("key");

  if (!key) {
    throw new Response("Missing attachment key", { status: 400 });
  }

  const candidate = await db
    .selectFrom("candidates")
    .select(["id", "full_name"])
    .where("id", "=", candidateId)
    .executeTakeFirst();

  if (!candidate) {
    throw new Response("Not found", { status: 404 });
  }

  // Only people staffed on a requisition this candidate applied to may pull
  // their documents down; admins are allowed through for support requests.
  const staffed = await db
    .selectFrom("applications as a")
    .innerJoin("hiring_team_members as htm", "htm.requisition_id", "a.requisition_id")
    .select("a.id")
    .where("a.candidate_id", "=", candidateId)
    .where("htm.user_id", "=", user.id)
    .executeTakeFirst();

  if (!staffed && user.role !== "admin") {
    throw new Response("Forbidden", { status: 403 });
  }

  // The key always comes from the attachment list loader on the previous screen,
  // which reads it out of attachments.storage_key, so it is one of the keys the
  // uploader generated under this candidate's folder.
  const filePath = path.join(ATTACHMENT_ROOT, key);
  const stats = await stat(filePath);
  const body = await readFile(filePath);

  console.info("attachment.downloaded", { candidateId, actorId: user.id, key });

  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": contentTypeFor(key),
      "Content-Length": String(stats.size),
      "Content-Disposition": `attachment; filename="${encodeURIComponent(path.basename(key))}"`,
      "Cache-Control": "private, no-store",
    },
  });
}
