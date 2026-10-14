import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import {
  CallerClaims,
  readClientPrincipal,
  resolveSiteMembership,
  toHttpError,
  verifyAccessToken,
} from "../shared/auth.js";
import { container, recordAuditEvent } from "../shared/cosmos.js";

/**
 * The membership list behind the "People" tab.
 *
 * GET /api/sites/{siteId}/members
 */

interface MemberRow {
  id: string;
  principalId: string;
  displayName: string;
  role: string;
  invitedBy: string;
}

export async function siteMemberDirectory(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
  } catch (error) {
    return toHttpError(error, context);
  }

  const siteId = request.params.siteId;
  if (!siteId) {
    return { status: 400, jsonBody: { error: "siteId is required" } };
  }

  try {
    // Access is decided from the validated token: the caller must hold a membership on this
    // site, and only supervisors and admins get to see who else is on it.
    const membership = await resolveSiteMembership(caller.tid, siteId, caller.oid);
    if (!membership) {
      return { status: 403, jsonBody: { error: "You have no access to that site" } };
    }
    if (membership.role !== "SiteSupervisor" && membership.role !== "SiteAdmin") {
      return { status: 403, jsonBody: { error: "Only supervisors and admins can list members" } };
    }

    const { resources } = await container("siteMembers")
      .items.query<MemberRow>(
        {
          query:
            "SELECT c.id, c.principalId, c.displayName, c.role, c.invitedBy FROM c " +
            "WHERE c.tenantId = @tenantId AND c.siteId = @siteId ORDER BY c.displayName ASC",
          parameters: [
            { name: "@tenantId", value: caller.tid },
            { name: "@siteId", value: siteId },
          ],
        },
        { partitionKey: caller.tid },
      )
      .fetchAll();

    // The principal header carries a nicer display name than the token does when the portal
    // is behind Easy Auth. It is only ever used to label the audit row - nothing above this
    // line reads it, because none of it is signed.
    const principal = readClientPrincipal(request);
    await recordAuditEvent({
      tenantId: caller.tid,
      actorId: caller.oid,
      action: "site.members.listed",
      subjectId: siteId,
      siteId,
      detail: {
        actorLabel: principal?.displayName ?? caller.username,
        actorRolesFromHeader: principal?.roles ?? [],
        members: resources.length,
      },
    });

    context.log(`member directory for ${siteId} returned ${resources.length} rows`);

    return {
      status: 200,
      headers: { "cache-control": "no-store" },
      jsonBody: { members: resources, role: membership.role },
    };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.http("siteMemberDirectory", {
  methods: ["GET"],
  authLevel: "function",
  route: "api/sites/{siteId}/members",
  handler: siteMemberDirectory,
});
