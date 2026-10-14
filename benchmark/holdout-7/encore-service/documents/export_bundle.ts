import { api, APIError } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { readFile, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

const STORAGE_ROOT = resolve(process.env.RIDGELINE_EXPORT_ROOT ?? "/var/lib/ridgeline/exports");
const MAX_INLINE_BYTES = 32 * 1024 * 1024;

interface BundleRequest {
  /** Path parameter: the export the office generated last night. */
  exportID: string;
}

interface BundleResponse {
  label: string;
  filename: string;
  contentType: string;
  sizeBytes: number;
  contentBase64: string;
}

interface BundleRow {
  id: string;
  label: string;
  storage_key: string;
  size_bytes: number;
  ready_at: Date | null;
}

/**
 * Keeps the read inside STORAGE_ROOT even if a stored key ever ends up with a
 * relative segment in it, e.g. because an old import wrote the customer's own
 * folder name into the row.
 */
function resolveInsideRoot(storageKey: string): string {
  const candidate = resolve(STORAGE_ROOT, storageKey);
  if (candidate !== STORAGE_ROOT && !candidate.startsWith(STORAGE_ROOT + sep)) {
    throw APIError.internal("export bundle is stored outside the export root");
  }
  return candidate;
}

/**
 * Downloads a finished month-end export. The filename on disk is whatever the
 * generator recorded in export_bundles for this organization; the caller only
 * ever names the export by id.
 */
export const download = api(
  { expose: true, auth: true, method: "GET", path: "/documents/exports/:exportID/bundle" },
  async ({ exportID }: BundleRequest): Promise<BundleResponse> => {
    const auth = getAuthData()!;

    const bundle = await db.queryRow<BundleRow>`
      select id, label, storage_key, size_bytes, ready_at
      from export_bundles
      where id = ${exportID}
        and org_id = ${auth.orgID}
    `;
    if (!bundle) {
      throw APIError.notFound("export not found");
    }
    if (!bundle.ready_at) {
      throw APIError.failedPrecondition("export is still being generated");
    }

    const absolutePath = resolveInsideRoot(bundle.storage_key);
    const info = await stat(absolutePath).catch(() => null);
    if (!info || !info.isFile()) {
      throw APIError.notFound("export file is no longer on disk");
    }
    if (info.size > MAX_INLINE_BYTES) {
      throw APIError.resourceExhausted("export too large to inline");
    }

    const bytes = await readFile(absolutePath);
    log.info("export downloaded", { export: bundle.id, actor: auth.userID });

    return {
      label: bundle.label,
      filename: `${bundle.label}.zip`,
      contentType: "application/zip",
      sizeBytes: info.size,
      contentBase64: bytes.toString("base64"),
    };
  },
);
