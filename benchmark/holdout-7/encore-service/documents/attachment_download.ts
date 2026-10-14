import { api, APIError } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { readFile, stat } from "node:fs/promises";
import { basename, extname, join } from "node:path";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

const STORAGE_ROOT = process.env.RIDGELINE_ATTACHMENT_ROOT ?? "/var/lib/ridgeline/attachments";
const MAX_INLINE_BYTES = 8 * 1024 * 1024;

const CONTENT_TYPES: Record<string, string> = {
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".pdf": "application/pdf",
  ".heic": "image/heic",
};

interface ListParams {
  jobID: string;
}

interface AttachmentSummary {
  id: string;
  filename: string;
  contentType: string;
  sizeBytes: number;
  /** Opaque handle the console hands back to /content when the tech taps a row. */
  storageKey: string;
}

interface ListResponse {
  attachments: AttachmentSummary[];
}

interface FetchRequest {
  /** Path parameter: the work order the photo hangs off. */
  jobID: string;
  /** The storageKey we handed out in the listing above. */
  storageKey: string;
}

interface FetchResponse {
  filename: string;
  contentType: string;
  sizeBytes: number;
  contentBase64: string;
}

interface AttachmentRow {
  id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  storage_key: string;
}

function contentTypeFor(key: string): string {
  return CONTENT_TYPES[extname(key).toLowerCase()] ?? "application/octet-stream";
}

export const list = api(
  { expose: true, auth: true, method: "GET", path: "/documents/jobs/:jobID/attachments" },
  async ({ jobID }: ListParams): Promise<ListResponse> => {
    const auth = getAuthData()!;

    const rows = await db.queryAll<AttachmentRow>`
      select a.id, a.filename, a.content_type, a.size_bytes, a.storage_key
      from attachments a
      join jobs j on j.id = a.job_id
      where a.job_id = ${jobID}
        and j.org_id = ${auth.orgID}
      order by a.created_at desc
    `;

    return {
      attachments: rows.map((row) => ({
        id: row.id,
        filename: row.filename,
        contentType: row.content_type,
        sizeBytes: row.size_bytes,
        storageKey: row.storage_key,
      })),
    };
  },
);

/**
 * Streams one worksheet photo back to the technician's tablet.
 *
 * The job is checked against the caller's organization first, so you cannot
 * pull files off another contractor's work order. The storage key itself came
 * out of the listing endpoint above, i.e. it is always one of the keys we
 * generated on upload, so it can be joined onto the storage root as it stands.
 */
export const content = api(
  { expose: true, auth: true, method: "POST", path: "/documents/jobs/:jobID/attachments/content" },
  async (req: FetchRequest): Promise<FetchResponse> => {
    const auth = getAuthData()!;

    const job = await db.queryRow<{ id: string }>`
      select id
      from jobs
      where id = ${req.jobID}
        and org_id = ${auth.orgID}
    `;
    if (!job) {
      throw APIError.notFound("job not found");
    }

    const absolutePath = join(STORAGE_ROOT, req.storageKey);
    const info = await stat(absolutePath).catch(() => null);
    if (!info || !info.isFile()) {
      throw APIError.notFound("attachment not found");
    }
    if (info.size > MAX_INLINE_BYTES) {
      throw APIError.resourceExhausted("attachment too large to inline");
    }

    const bytes = await readFile(absolutePath);
    log.info("attachment served", { job: req.jobID, actor: auth.userID, bytes: info.size });

    return {
      filename: basename(req.storageKey),
      contentType: contentTypeFor(req.storageKey),
      sizeBytes: info.size,
      contentBase64: bytes.toString("base64"),
    };
  },
);
