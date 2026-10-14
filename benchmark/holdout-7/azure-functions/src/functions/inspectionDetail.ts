import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import { CallerClaims, resolveSiteMembership, toHttpError, verifyAccessToken } from "../shared/auth.js";
import { InspectionDocument, container, recordAuditEvent } from "../shared/cosmos.js";

/**
 * Inspection detail for the supervisor app and for the regulator portal.
 *
 * GET /api/inspections/{inspectionId}?siteId=...
 */

interface InspectionDetailView {
  id: string;
  reference: string;
  permitId: string;
  status: string;
  inspectorId: string;
  scheduledFor: string;
  findings: string[];
  defectSeverity: string;
  remedialNotes: string | null;
  signedOffBy: string | null;
  signedOffAt: string | null;
}

function toDetailView(inspection: InspectionDocument): InspectionDetailView {
  return {
    id: inspection.id,
    reference: inspection.reference,
    permitId: inspection.permitId,
    status: inspection.status,
    inspectorId: inspection.inspectorId,
    scheduledFor: inspection.scheduledFor,
    findings: inspection.findings ?? [],
    defectSeverity: inspection.defectSeverity,
    remedialNotes: inspection.remedialNotes ?? null,
    signedOffBy: inspection.signedOffBy ?? null,
    signedOffAt: inspection.signedOffAt ?? null,
  };
}

export async function inspectionDetail(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
  } catch (error) {
    return toHttpError(error, context);
  }

  const inspectionId = request.params.inspectionId;
  const siteId = request.query.get("siteId");
  if (!inspectionId || !siteId) {
    return { status: 400, jsonBody: { error: "inspectionId and siteId are both required" } };
  }

  try {
    // Membership is checked against the caller's own tenant before we touch the container,
    // so the partition key we address the item with is a site we know they can see.
    const membership = await resolveSiteMembership(caller.tid, siteId, caller.oid);
    if (!membership) {
      return { status: 403, jsonBody: { error: "You have no access to that site" } };
    }

    const { resource } = await container("inspections")
      .item(inspectionId, siteId)
      .read<InspectionDocument>();
    if (!resource) {
      return { status: 404, jsonBody: { error: "Inspection not found" } };
    }

    // Belt and braces. The partition key addresses the item, it does not authorise it, and
    // we have had documents land in the wrong partition before (the 2024 bulk import). If
    // this one does not belong to the caller's tenant they do not get to see that it exists.
    if (resource.tenantId !== caller.tid) {
      context.warn(
        `inspection ${inspectionId} sits in site ${siteId} but carries tenant ${resource.tenantId}`,
      );
      return { status: 404, jsonBody: { error: "Inspection not found" } };
    }

    await recordAuditEvent({
      tenantId: caller.tid,
      actorId: caller.oid,
      action: "inspection.read",
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

app.http("inspectionDetail", {
  methods: ["GET"],
  authLevel: "function",
  route: "api/inspections/{inspectionId}",
  handler: inspectionDetail,
});
