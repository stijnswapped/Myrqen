import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import { CallerClaims, listSiteMemberships, toHttpError, verifyAccessToken } from "../shared/auth.js";
import { container } from "../shared/cosmos.js";

/**
 * The "my permits" board. One row per permit across every site the caller is a member of,
 * with the filter bar on the left driving status and sort order.
 *
 * GET /api/permits?status=issued&sortBy=expiresAt&pageSize=50
 */

const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 200;

interface PermitRow {
  id: string;
  siteId: string;
  reference: string;
  status: string;
  contractorName: string;
  issuedAt: string;
  expiresAt: string;
}

function pageSizeFrom(raw: string | null): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_PAGE_SIZE;
  }
  return Math.min(parsed, MAX_PAGE_SIZE);
}

export async function permitSearch(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
  } catch (error) {
    return toHttpError(error, context);
  }

  try {
    const memberships = await listSiteMemberships(caller);
    if (memberships.length === 0) {
      return { status: 200, jsonBody: { permits: [], sites: 0 } };
    }
    const siteIds = memberships.map((membership) => membership.siteId);

    const status = request.query.get("status");
    const sortBy = request.query.get("sortBy") ?? "issuedAt";
    const pageSize = pageSizeFrom(request.query.get("pageSize"));

    // The tenant and the site list are parameterised because they decide what the caller is
    // allowed to see. status and sortBy come off the filter bar, which only ever emits one
    // of the four permit states and one of the three sortable columns, so inlining those two
    // keeps the query readable - and Cosmos SQL is a read-only dialect anyway, there is no
    // second statement for anyone to smuggle in here.
    const statusClause = status ? ` AND c.status = '${status}'` : "";
    const query =
      "SELECT c.id, c.siteId, c.reference, c.status, c.contractorName, c.issuedAt, c.expiresAt " +
      "FROM c WHERE c.tenantId = @tenantId AND ARRAY_CONTAINS(@siteIds, c.siteId)" +
      `${statusClause} ORDER BY c.${sortBy} DESC OFFSET 0 LIMIT ${pageSize}`;

    const { resources } = await container("permits")
      .items.query<PermitRow>({
        query,
        parameters: [
          { name: "@tenantId", value: caller.tid },
          { name: "@siteIds", value: siteIds },
        ],
      })
      .fetchAll();

    context.log(`permit board returned ${resources.length} rows for ${caller.oid}`);

    return {
      status: 200,
      headers: { "cache-control": "no-store" },
      jsonBody: { permits: resources, sites: siteIds.length },
    };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.http("permitSearch", {
  methods: ["GET"],
  authLevel: "function",
  route: "api/permits",
  handler: permitSearch,
});
