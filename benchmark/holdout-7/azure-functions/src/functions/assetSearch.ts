import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import { CallerClaims, listSiteMemberships, toHttpError, verifyAccessToken } from "../shared/auth.js";
import { SqlParameter } from "@azure/cosmos";
import { container } from "../shared/cosmos.js";

/**
 * Plant and equipment register. Same board layout as the permit list, one row per asset
 * across the caller's sites, with a service-due sort by default.
 *
 * GET /api/assets?status=in_service&sortBy=nextServiceDue&pageSize=50
 */

const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 200;

// Cosmos will not take a parameter in an ORDER BY clause, so the sortable columns live in
// this map and anything that is not a key of it is a 400 rather than a substitution.
const SORTABLE_COLUMNS: Record<string, string> = {
  assetTag: "c.assetTag",
  installedAt: "c.installedAt",
  nextServiceDue: "c.nextServiceDue",
  status: "c.status",
};

const ASSET_STATUSES = ["in_service", "quarantined", "retired"];

interface AssetRow {
  id: string;
  siteId: string;
  assetTag: string;
  description: string;
  status: string;
  nextServiceDue: string;
}

function pageSizeFrom(raw: string | null): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_PAGE_SIZE;
  }
  return Math.min(parsed, MAX_PAGE_SIZE);
}

export async function assetSearch(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
  } catch (error) {
    return toHttpError(error, context);
  }

  const status = request.query.get("status");
  if (status && !ASSET_STATUSES.includes(status)) {
    return { status: 400, jsonBody: { error: `status must be one of ${ASSET_STATUSES.join(", ")}` } };
  }

  const sortColumn = SORTABLE_COLUMNS[request.query.get("sortBy") ?? "nextServiceDue"];
  if (!sortColumn) {
    return {
      status: 400,
      jsonBody: { error: `sortBy must be one of ${Object.keys(SORTABLE_COLUMNS).join(", ")}` },
    };
  }

  try {
    const memberships = await listSiteMemberships(caller);
    if (memberships.length === 0) {
      return { status: 200, jsonBody: { assets: [], sites: 0 } };
    }
    const siteIds = memberships.map((membership) => membership.siteId);

    const parameters: SqlParameter[] = [
      { name: "@tenantId", value: caller.tid },
      { name: "@siteIds", value: siteIds },
    ];

    let statusClause = "";
    if (status) {
      statusClause = " AND c.status = @status";
      parameters.push({ name: "@status", value: status });
    }

    // Everything that came off the request is either a bound parameter, a key of
    // SORTABLE_COLUMNS, or a clamped integer, so the only text being concatenated here is
    // text this file owns.
    const pageSize = pageSizeFrom(request.query.get("pageSize"));
    const query =
      "SELECT c.id, c.siteId, c.assetTag, c.description, c.status, c.nextServiceDue " +
      "FROM c WHERE c.tenantId = @tenantId AND ARRAY_CONTAINS(@siteIds, c.siteId)" +
      `${statusClause} ORDER BY ${sortColumn} ASC OFFSET 0 LIMIT ${pageSize}`;

    const { resources } = await container("assets")
      .items.query<AssetRow>({ query, parameters })
      .fetchAll();

    context.log(`asset register returned ${resources.length} rows for ${caller.oid}`);

    return {
      status: 200,
      headers: { "cache-control": "no-store" },
      jsonBody: { assets: resources, sites: siteIds.length },
    };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.http("assetSearch", {
  methods: ["GET"],
  authLevel: "function",
  route: "api/assets",
  handler: assetSearch,
});
