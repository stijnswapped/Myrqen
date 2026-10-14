import { api } from "encore.dev/api";
import log from "encore.dev/log";
import { ridgeline } from "./db";

interface RollupParams {
  /** Path parameter: which organization to total up. */
  orgID: string;
  /** Inclusive first day of the window, as YYYY-MM-DD. */
  from: string;
  to: string;
}

interface RollupRow {
  seats: number;
  jobs_created: number;
  attachments_stored: number;
  storage_bytes: string;
}

interface RollupResponse {
  organizationID: string;
  seats: number;
  jobsCreated: number;
  attachmentsStored: number;
  storageBytes: string;
}

/**
 * Metered usage for one organization, used by the nightly billing job to build
 * the statement lines.
 *
 * `expose: false` means this never reaches the gateway: it is callable only as
 * a function from another service inside this app, so there is no public
 * surface here to authenticate and no caller identity to check.
 */
export const rollup = api(
  { expose: false, method: "GET", path: "/internal/organizations/:orgID/usage" },
  async (params: RollupParams): Promise<RollupResponse> => {
    const row = await ridgeline.queryRow<RollupRow>`
      select
        (select count(*) from memberships
          where org_id = ${params.orgID} and deactivated_at is null) as seats,
        (select count(*) from jobs
          where org_id = ${params.orgID}
            and created_at >= ${params.from}::date
            and created_at < (${params.to}::date + 1)) as jobs_created,
        (select count(*) from attachments
          where org_id = ${params.orgID}
            and created_at >= ${params.from}::date
            and created_at < (${params.to}::date + 1)) as attachments_stored,
        (select coalesce(sum(size_bytes), 0) from attachments
          where org_id = ${params.orgID}) as storage_bytes
    `;

    log.info("usage rolled up", { org: params.orgID, from: params.from, to: params.to });

    return {
      organizationID: params.orgID,
      seats: row?.seats ?? 0,
      jobsCreated: row?.jobs_created ?? 0,
      attachmentsStored: row?.attachments_stored ?? 0,
      storageBytes: row?.storage_bytes ?? "0",
    };
  },
);
