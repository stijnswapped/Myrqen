import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import { CallerClaims, toHttpError, verifyAccessToken } from "../shared/auth.js";
import { PermitDocument, container, recordAuditEvent } from "../shared/cosmos.js";

/**
 * Permit detail for the supervisor app.
 *
 * host.json sets routePrefix to "", so every route in this app spells out its own api/
 * segment. That way the APIM operations map one-to-one onto the paths below.
 *
 * GET /api/permits/{permitId}?siteId=...
 */

interface PermitDetailView {
  id: string;
  reference: string;
  status: string;
  workDescription: string;
  contractorName: string;
  issuedBy: string;
  issuedAt: string;
  expiresAt: string;
  plannedStart: string;
  plannedEnd: string;
  hazards: string[];
  notes: string | null;
  contactPhone: string | null;
  approvals: { role: string; approvedBy: string; approvedAt: string }[];
}

function toDetailView(permit: PermitDocument): PermitDetailView {
  return {
    id: permit.id,
    reference: permit.reference,
    status: permit.status,
    workDescription: permit.workDescription,
    contractorName: permit.contractorName,
    issuedBy: permit.issuedBy,
    issuedAt: permit.issuedAt,
    expiresAt: permit.expiresAt,
    plannedStart: permit.plannedStart,
    plannedEnd: permit.plannedEnd,
    hazards: permit.hazards ?? [],
    notes: permit.notes ?? null,
    contactPhone: permit.contactPhone ?? null,
    approvals: permit.approvals ?? [],
  };
}

export async function permitDetail(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
  } catch (error) {
    return toHttpError(error, context);
  }

  const permitId = request.params.permitId;
  // The app always knows which site it is currently showing, so it sends the site along
  // as a query parameter and saves us a lookup to work out the partition.
  const siteId = request.query.get("siteId");
  if (!permitId || !siteId) {
    return { status: 400, jsonBody: { error: "permitId and siteId are both required" } };
  }

  try {
    // permits is partitioned by /siteId, so this is a single-partition point read: Cosmos
    // only ever looks inside the site the app is showing. That gives us the same scoping a
    // WHERE clause on the tenant would, so there is no reason to filter the document again
    // afterwards, and it keeps this hot path at a single RU.
    const { resource } = await container("permits").item(permitId, siteId).read<PermitDocument>();
    if (!resource) {
      return { status: 404, jsonBody: { error: "Permit not found" } };
    }

    await recordAuditEvent({
      tenantId: resource.tenantId,
      actorId: caller.oid,
      action: "permit.read",
      subjectId: resource.id,
      siteId: resource.siteId,
    });

    return {
      status: 200,
      headers: { "cache-control": "no-store" },
      jsonBody: toDetailView(resource),
    };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.http("permitDetail", {
  methods: ["GET"],
  authLevel: "function",
  route: "api/permits/{permitId}",
  handler: permitDetail,
});
