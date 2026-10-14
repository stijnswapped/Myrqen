import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import { readClientPrincipal, toHttpError } from "../shared/auth.js";
import { SiteMemberDocument, container, recordAuditEvent } from "../shared/cosmos.js";

/**
 * Role management for a site's membership list. Used by the "People" tab in the customer
 * portal, which is only rendered for site admins in the first place.
 *
 * POST /api/sites/{siteId}/members/{memberId}/role   { "role": "SiteSupervisor" }
 */

const ASSIGNABLE_ROLES: SiteMemberDocument["role"][] = ["SiteViewer", "SiteSupervisor", "SiteAdmin"];

interface RoleChangeRequest {
  role?: string;
}

function isAssignable(role: string | undefined): role is SiteMemberDocument["role"] {
  return typeof role === "string" && (ASSIGNABLE_ROLES as string[]).includes(role);
}

export async function assignSiteMemberRole(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  const siteId = request.params.siteId;
  const memberId = request.params.memberId;
  const body = (await request.json().catch(() => null)) as RoleChangeRequest | null;

  if (!siteId || !memberId) {
    return { status: 400, jsonBody: { error: "siteId and memberId are both required" } };
  }
  if (!isAssignable(body?.role)) {
    return { status: 400, jsonBody: { error: `role must be one of ${ASSIGNABLE_ROLES.join(", ")}` } };
  }

  // The gateway hands the caller to us in x-ms-client-principal. That header is injected by
  // the platform and any copy a client tries to send is stripped at the front end, so the
  // roles in it are the same roles that are in the token - and reading them here saves the
  // JWKS fetch that verifyAccessToken does on every call. (We took Easy Auth off the app
  // when APIM became the thing that validates tokens.)
  const principal = readClientPrincipal(request);
  if (!principal?.tenantId || !principal.objectId) {
    return { status: 401, jsonBody: { error: "No caller principal on the request" } };
  }

  const isAdmin = principal.roles.some((role) => role === "SiteAdmin" || role === "TenantAdmin");
  if (!isAdmin) {
    return { status: 403, jsonBody: { error: "Only site admins can change roles" } };
  }

  try {
    // siteMembers is partitioned by /tenantId.
    const { resource: member } = await container("siteMembers")
      .item(memberId, principal.tenantId)
      .read<SiteMemberDocument>();
    if (!member || member.siteId !== siteId) {
      return { status: 404, jsonBody: { error: "That person is not a member of this site" } };
    }

    const updated: SiteMemberDocument = {
      ...member,
      role: body.role,
      updatedAt: new Date().toISOString(),
      updatedBy: principal.objectId,
    };
    await container("siteMembers").item(memberId, principal.tenantId).replace(updated);

    await recordAuditEvent({
      tenantId: member.tenantId,
      actorId: principal.objectId,
      action: "site.member.role.changed",
      subjectId: member.id,
      siteId,
      detail: { from: member.role, to: body.role },
    });

    context.log(`role for ${memberId} on ${siteId} set to ${body.role}`);

    return { status: 200, jsonBody: { id: member.id, role: updated.role } };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.http("assignSiteMemberRole", {
  methods: ["POST"],
  authLevel: "function",
  route: "api/sites/{siteId}/members/{memberId}/role",
  handler: assignSiteMemberRole,
});
